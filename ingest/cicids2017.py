"""CIC-IDS2017 'GeneratedLabelledFlows' (TrafficLabelling) CSV import profile.

Source: Canadian Institute for Cybersecurity, University of New Brunswick.
https://www.unb.ca/cic/datasets/ids-2017.html  (Sharafaldin et al., ICISSP 2018)
"""
import io

import numpy as np
import pandas as pd

from .base import BaseAdapter, register_adapter
from .schema import FLOW_FEATURES, LABEL_FIELD, SENTINEL_MINUS_ONE, IngestReport
from .validate import parse_timestamps, protocol_name, valid_ip, valid_port

# dataset column -> internal name
COLUMN_MAP = {
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "observed_at",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Flow Bytes/s": "flow_bytes_per_s",
    "Flow Packets/s": "flow_packets_per_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Fwd IAT Total": "fwd_iat_total",
    "Bwd IAT Total": "bwd_iat_total",
    "Fwd Packets/s": "fwd_packets_per_s",
    "Bwd Packets/s": "bwd_packets_per_s",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "FIN Flag Count": "fin_flags",
    "SYN Flag Count": "syn_flags",
    "RST Flag Count": "rst_flags",
    "PSH Flag Count": "psh_flags",
    "ACK Flag Count": "ack_flags",
    "URG Flag Count": "urg_flags",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "avg_packet_size",
    "Init_Win_bytes_forward": "init_win_fwd",
    "Init_Win_bytes_backward": "init_win_bwd",
    "act_data_pkt_fwd": "act_data_pkt_fwd",
    "Active Mean": "active_mean",
    "Idle Mean": "idle_mean",
    "Label": LABEL_FIELD,
}
REQUIRED = [c for c, n in COLUMN_MAP.items() if n != LABEL_FIELD]
assert set(FLOW_FEATURES) <= set(COLUMN_MAP.values())


def normalise_label(s: pd.Series) -> pd.Series:
    return (
        s.astype(str)
        .str.replace("\x96", "-", regex=False)
        .str.replace("\u2013", "-", regex=False)
        .str.replace("\ufffd", "-", regex=False)
        .str.strip()
    )


@register_adapter
class CICIDS2017Adapter(BaseAdapter):
    name = "cicids2017"
    extensions = (".csv",)
    description = "CIC-IDS2017 GeneratedLabelledFlows / CICFlowMeter CSV (one row per flow)"

    def _open(self, source):
        if isinstance(source, (bytes, bytearray)):
            return io.BytesIO(source)
        return source

    def iter_normalised(self, source, chunksize: int = 200_000):
        src = self._open(source)
        header = pd.read_csv(src, nrows=0, encoding="latin-1")
        cols = [c.strip() for c in header.columns]
        missing = [c for c in REQUIRED if c not in cols]
        if missing:
            rep = IngestReport(missing_columns=missing)
            yield pd.DataFrame(), rep
            return
        if hasattr(src, "seek"):
            src.seek(0)
        # map stripped name -> original position (first occurrence wins)
        pos = {}
        for i, c in enumerate(cols):
            pos.setdefault(c, i)
        wanted = [c for c in COLUMN_MAP if c in pos]
        usecols = [pos[c] for c in wanted]
        reader = pd.read_csv(
            src, usecols=usecols, encoding="latin-1", chunksize=chunksize,
            low_memory=False, dtype=str, skip_blank_lines=True,
        )
        idx_to_name = {pos[c]: COLUMN_MAP[c] for c in wanted}
        for chunk in reader:
            chunk.columns = [idx_to_name[pos[c.strip()]] if c.strip() in pos else c for c in chunk.columns]
            yield self._normalise_chunk(chunk)

    def _normalise_chunk(self, df: pd.DataFrame):
        rep = IngestReport(total_rows=len(df))
        # CIC CSVs contain fully blank padding rows (Thursday WebAttacks file)
        blank = df.isna().all(axis=1)
        rep.add_rejects("blank_row", blank.sum())
        df = df[~blank]

        ok = pd.Series(True, index=df.index)
        checks = [
            ("invalid_ip", valid_ip(df["src_ip"]) & valid_ip(df["dst_ip"])),
            ("invalid_port", valid_port(df["src_port"]) & valid_port(df["dst_port"])),
        ]
        ts = parse_timestamps(df["observed_at"], twelve_hour_fix=True)
        checks.append(("bad_timestamp", ts.notna()))
        proto_num = pd.to_numeric(df["protocol"], errors="coerce")
        checks.append(("invalid_protocol", proto_num.notna() & (proto_num >= 0) & (proto_num <= 255)))

        feats = df[FLOW_FEATURES].apply(pd.to_numeric, errors="coerce")
        finite = np.isfinite(feats.to_numpy(dtype="float64"))
        checks.append(("non_numeric_or_infinite_feature", finite.all(axis=1)))
        neg = feats < 0
        for c in SENTINEL_MINUS_ONE:
            neg[c] = feats[c] < -1
        checks.append(("negative_value", ~neg.any(axis=1)))

        for reason, mask in checks:
            mask = pd.Series(mask, index=df.index).fillna(False).astype(bool)
            bad = ok & ~mask  # attribute each row to its first failing reason
            rep.add_rejects(reason, bad.sum())
            ok &= mask

        out = pd.DataFrame(index=df.index[ok])
        out["observed_at"] = ts[ok]
        out["src_ip"] = df.loc[ok, "src_ip"].str.strip()
        out["dst_ip"] = df.loc[ok, "dst_ip"].str.strip()
        out["src_port"] = pd.to_numeric(df.loc[ok, "src_port"]).astype("int32")
        out["dst_port"] = pd.to_numeric(df.loc[ok, "dst_port"]).astype("int32")
        out["protocol"] = protocol_name(df.loc[ok, "protocol"])
        for c in FLOW_FEATURES:
            out[c] = feats.loc[ok, c].astype("float32")
        if LABEL_FIELD in df.columns:
            out[LABEL_FIELD] = normalise_label(df.loc[ok, LABEL_FIELD])
        rep.accepted = int(ok.sum())
        return out.reset_index(drop=True), rep
