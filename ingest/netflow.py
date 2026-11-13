"""NetFlow v5 (binary export datagrams) and nfdump CSV (``nfdump -o csv``).

NetFlow records are unidirectional and carry only packets, bytes, first/last
timestamps and the OR of TCP flags, so: bwd_* = 0; flag "counts" are 0/1
(cumulative flags); bytes include IP/TCP headers (CICFlowMeter counts payload);
IAT / window / active-idle statistics are not available (0 or -1 defaults).
Durations, rates, mean packet size and all 60 s window counts are exact.
"""
import csv
import io
import socket
import struct
from datetime import datetime

from .base import BaseAdapter, register_adapter
from .flowbuild import build_frame, read_bytes, read_text
from .schema import IngestReport

HEADER = struct.Struct("!HHIIIIBBH")  # 24 bytes
RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")  # 48 bytes
TCP_FLAG_BITS = {"fin_flags": 0x01, "syn_flags": 0x02, "rst_flags": 0x04, "psh_flags": 0x08, "ack_flags": 0x10,
                 "urg_flags": 0x20}


def _features(pkts, octets, duration_ms, flags):
    dur_s = duration_ms / 1000.0
    f = {"flow_duration": duration_ms * 1000.0, "fwd_packets": float(pkts), "fwd_bytes": float(octets),
         "flow_packets_per_s": pkts / dur_s if dur_s > 0 else 0.0,
         "flow_bytes_per_s": octets / dur_s if dur_s > 0 else 0.0,
         "fwd_packets_per_s": pkts / dur_s if dur_s > 0 else 0.0}
    mean = octets / pkts if pkts else 0.0
    f.update({"pkt_len_mean": mean, "fwd_pkt_len_mean": mean, "avg_packet_size": mean, "fwd_pkt_len_max": mean})
    for name, bit in TCP_FLAG_BITS.items():
        f[name] = 1.0 if flags & bit else 0.0
    return f


def parse_v5_datagram(data: bytes):
    """Parse one NetFlow v5 export datagram -> list of flow records (dicts)."""
    if len(data) < HEADER.size:
        raise ValueError("short datagram")
    version, count, uptime, secs, nsecs, _seq, _et, _eid, _samp = HEADER.unpack_from(data, 0)
    if version != 5:
        raise ValueError(f"not NetFlow v5 (version {version})")
    if len(data) < HEADER.size + count * RECORD.size:
        raise ValueError("truncated datagram")
    boot = secs + nsecs / 1e9 - uptime / 1000.0
    out = []
    for i in range(count):
        (src, dst, _nh, _in, _out, pkts, octets, first, last, sport, dport, _p1, flags, prot, _tos,
         _sas, _das, _sm, _dm, _p2) = RECORD.unpack_from(data, HEADER.size + i * RECORD.size)
        rec = {"observed_at": datetime.fromtimestamp(boot + first / 1000.0),
               "src_ip": socket.inet_ntoa(src), "dst_ip": socket.inet_ntoa(dst),
               "src_port": sport, "dst_port": dport, "protocol": prot}
        rec.update(_features(pkts, octets, max(0, last - first), flags))
        out.append(rec)
    return out, HEADER.size + count * RECORD.size


def encode_v5(records, uptime_ms=None, unix_secs=None, seq=0):
    """Build NetFlow v5 datagrams (max 30 records each) - used by tests and the sender.
    By default the export time is just after the last flow and the exporter 'booted'
    60 s before the first one, so record timestamps round-trip exactly (to 1 ms)."""
    if not records:
        return []
    unix_secs = int(unix_secs or (max(r.get("end", r["start"]) for r in records) + 1))
    if uptime_ms is None:
        uptime_ms = int((unix_secs - min(r["start"] for r in records)) * 1000) + 60_000
    boot = unix_secs - uptime_ms / 1000.0
    out = []
    for start in range(0, len(records), 30):
        chunk = records[start:start + 30]
        body = b""
        for r in chunk:
            first = int((r["start"] - boot) * 1000)
            last = int((r.get("end", r["start"]) - boot) * 1000)
            body += RECORD.pack(socket.inet_aton(r["src_ip"]), socket.inet_aton(r["dst_ip"]), b"\0" * 4, 0, 0,
                                int(r["packets"]), int(r["bytes"]), max(first, 0), max(last, 0),
                                int(r["src_port"]), int(r["dst_port"]), 0, int(r.get("tcp_flags", 0)),
                                int(r.get("protocol", 6)), 0, 0, 0, 0, 0, 0)
        out.append(HEADER.pack(5, len(chunk), uptime_ms, unix_secs, 0, seq + start, 0, 0, 0) + body)
    return out


@register_adapter
class NetFlowV5Adapter(BaseAdapter):
    name = "netflow_v5"
    description = "NetFlow v5 binary export (concatenated datagrams, as received by the UDP collector)"
    extensions = (".nf5", ".bin", ".netflow")

    def iter_normalised(self, source, chunksize: int = 200_000):
        data, rep, recs, off = read_bytes(source), IngestReport(), [], 0
        while off < len(data):
            try:
                r, used = parse_v5_datagram(data[off:])
            except ValueError:
                rep.add_rejects("malformed_datagram", 1)
                break
            recs.extend(r)
            off += used
        rep.total_rows += len(recs) + rep.rejected
        yield build_frame(recs, rep), rep


NFDUMP_FLAGS = {"U": "urg_flags", "A": "ack_flags", "P": "psh_flags", "R": "rst_flags", "S": "syn_flags",
                "F": "fin_flags"}


def _nf_ts(v):
    v = v.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            pass
    return None


@register_adapter
class NfdumpCsvAdapter(BaseAdapter):
    name = "nfdump_csv"
    description = "nfdump CSV export (nfdump -r <file> -o csv): ts,te,td,sa,da,sp,dp,pr,flg,...,ipkt,ibyt,opkt,obyt"
    extensions = (".csv",)
    REQUIRED = ("ts", "td", "sa", "da", "sp", "dp", "pr", "ipkt", "ibyt")

    def iter_normalised(self, source, chunksize: int = 200_000):
        rep = IngestReport()
        text = read_text(source)
        reader = csv.reader(io.StringIO(text))
        header = next(reader, None)
        header = [h.strip() for h in header] if header else []
        missing = [c for c in self.REQUIRED if c not in header]
        if missing:
            rep.missing_columns = missing
            yield build_frame([], rep), rep
            return
        idx = {h: i for i, h in enumerate(header)}
        recs = []
        for row in reader:
            if not row or row[0].strip().lower() in ("summary", "flows", "") or len(row) < len(self.REQUIRED):
                continue  # nfdump appends a summary block after the flows
            rep.total_rows += 1
            g = lambda k, d="0": row[idx[k]].strip() if k in idx and idx[k] < len(row) else d  # noqa: E731
            ts = _nf_ts(g("ts", ""))
            if ts is None:
                rep.add_rejects("bad_timestamp", 1)
                continue
            try:
                td_ms = float(g("td")) * 1000.0
                pkts, byts = float(g("ipkt")), float(g("ibyt"))
                opkt, obyt = float(g("opkt")), float(g("obyt"))
            except ValueError:
                rep.add_rejects("non_numeric_or_infinite_feature", 1)
                continue
            flags = 0
            for ch, name in NFDUMP_FLAGS.items():
                if ch in g("flg", ""):
                    flags |= TCP_FLAG_BITS[name]
            rec = {"observed_at": ts, "src_ip": g("sa"), "dst_ip": g("da"), "src_port": g("sp"),
                   "dst_port": g("dp"), "protocol": g("pr", "OTHER")}
            rec.update(_features(pkts, byts, td_ms, flags))
            if opkt or obyt:  # bidirectional nfdump output
                rec.update({"bwd_packets": opkt, "bwd_bytes": obyt,
                            "bwd_pkt_len_mean": obyt / opkt if opkt else 0.0})
            recs.append(rec)
        yield build_frame(recs, rep), rep
