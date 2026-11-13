"""Shared helpers for non-CSV adapters: turn a list of partial flow records into
the internal event schema (all FLOW_FEATURES present, documented defaults)."""
import io
import ipaddress
import re
import unicodedata
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from .schema import FLOW_FEATURES, IngestReport

DEFAULTS = {f: 0.0 for f in FLOW_FEATURES}
DEFAULTS.update({"init_win_fwd": -1.0, "init_win_bwd": -1.0})
PROTO_NUM = {"TCP": 6, "UDP": 17, "ICMP": 1, "ICMPV6": 58, "IPV6-ICMP": 58}
PROTO_NAME = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6", 0: "HOPOPT"}
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def read_bytes(source) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if isinstance(source, (str, Path)):
        return Path(source).read_bytes()
    data = source.read()
    return data.encode() if isinstance(data, str) else data


def read_text(source) -> str:
    return read_bytes(source).decode("utf-8", errors="replace")


def clean_message(msg: str, cap=300) -> str:
    """Untrusted log text: normalise, strip control chars, cap length. Stored for
    analysts only - never passed to the models or the LLM."""
    msg = unicodedata.normalize("NFKC", msg or "")
    return _CTRL.sub(" ", msg)[:cap]


def _ip_ok(v):
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def build_frame(records, report: IngestReport, extra_cols=("message",)) -> pd.DataFrame:
    """records: dicts with observed_at (datetime), src_ip, dst_ip, src_port, dst_port,
    protocol (name or number) and any subset of FLOW_FEATURES."""
    rows = []
    for r in records:
        if not (_ip_ok(str(r.get("src_ip", ""))) and _ip_ok(str(r.get("dst_ip", "")))):
            report.add_rejects("invalid_ip", 1)
            continue
        try:
            sp, dp = int(r.get("src_port") or 0), int(r.get("dst_port") or 0)
        except (TypeError, ValueError):
            report.add_rejects("invalid_port", 1)
            continue
        if not (0 <= sp <= 65535 and 0 <= dp <= 65535):
            report.add_rejects("invalid_port", 1)
            continue
        if not isinstance(r.get("observed_at"), datetime):
            report.add_rejects("bad_timestamp", 1)
            continue
        feats = {**DEFAULTS, **{k: r[k] for k in FLOW_FEATURES if k in r and r[k] is not None}}
        vals = np.array(list(feats.values()), dtype=float)
        if not np.isfinite(vals).all():
            report.add_rejects("non_numeric_or_infinite_feature", 1)
            continue
        if any(feats[k] < (-1 if k.startswith("init_win") else 0) for k in feats):
            report.add_rejects("negative_value", 1)
            continue
        proto = r.get("protocol")
        if isinstance(proto, (int, np.integer)) or (isinstance(proto, str) and proto.isdigit()):
            proto = PROTO_NAME.get(int(proto), f"OTHER({int(proto)})")
        row = {"observed_at": pd.Timestamp(r["observed_at"]), "src_ip": str(r["src_ip"]), "dst_ip": str(r["dst_ip"]),
               "src_port": sp, "dst_port": dp, "protocol": str(proto or "OTHER").upper().replace("ICMPV6", "ICMPv6"),
               **feats}
        for c in extra_cols:
            if r.get(c) is not None:
                row[c] = r[c]
        rows.append(row)
    report.accepted += len(rows)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    for c in FLOW_FEATURES:
        df[c] = df[c].astype("float32")
    df["src_port"] = df["src_port"].astype("int32")
    df["dst_port"] = df["dst_port"].astype("int32")
    return df


def as_stream(data: bytes):
    return io.BytesIO(data)
