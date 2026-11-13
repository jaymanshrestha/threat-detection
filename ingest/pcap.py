"""Packet capture adapter (.pcap / .pcapng) using the pure-Python ``dpkt`` parser.

Payload lengths come from the IP/TCP/UDP header length fields, so truncated
(small snap-length) captures still yield exact byte counts.
Packets are aggregated into bidirectional flows (5-tuple, first packet = forward
direction, as in CICFlowMeter). Payloads are never stored: only header fields and
lengths are read. Flow termination: TCP RST, FIN seen in both directions, or
FLOW_TIMEOUT (120 s, CICFlowMeter's default) of total flow time / idle.

Feature fidelity vs CICFlowMeter (the model was trained on CICFlowMeter output):
  exact (same definition): flow_duration, fwd/bwd packet counts, fwd/bwd payload
    bytes, packet-length max/mean/std, flow/fwd/bwd packets per second, bytes per
    second, IAT mean/std/max, fwd/bwd IAT totals, TCP flag counts, down/up ratio,
    init TCP window (fwd/bwd), act_data_pkt_fwd, and all 60 s window counts.
  approximated: active_mean / idle_mean (idle = gaps > 5 s inside a flow; CICFlowMeter
    tracks them with its own activity timer), flow boundaries (CICFlowMeter has
    known quirks around FIN/RST handling and timeouts), zero-duration flows get
    rate 0 (CICFlowMeter emits Infinity/NaN, which our CSV ingestion rejects).
  as in CICFlowMeter, a packet arriving after a flow was closed by FIN/FIN (e.g. the
    final ACK) starts a new one-packet flow.
  not computed: bulk-transfer features and subflow features (not used by the model).
"""
import socket
import struct
from datetime import datetime

import numpy as np

from .base import BaseAdapter, register_adapter
from .flowbuild import build_frame, read_bytes
from .schema import IngestReport

FLOW_TIMEOUT = 120.0
ACTIVITY_TIMEOUT = 5.0


def _dpkt():
    try:
        import dpkt
        return dpkt
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pcap ingestion needs the 'dpkt' package: python -m pip install dpkt") from e


class _Flow:
    __slots__ = ("key", "fwd", "t0", "last", "pkts", "fin_fwd", "fin_bwd", "closed", "proto")

    def __init__(self, key, fwd, ts, proto):
        self.key, self.fwd, self.t0, self.last, self.proto = key, fwd, ts, ts, proto
        self.pkts = []  # (ts, is_fwd, payload_len, flags, window)
        self.fin_fwd = self.fin_bwd = self.closed = False


def _features(fl: _Flow):
    p = fl.pkts
    ts = np.array([x[0] for x in p])
    fwd = np.array([x[1] for x in p])
    ln = np.array([x[2] for x in p], dtype=float)
    flags = [x[3] for x in p]
    dur = float(ts[-1] - ts[0])
    dur_us = dur * 1e6
    f_ln, b_ln = ln[fwd], ln[~fwd]
    iat = np.diff(ts) * 1e6
    f_iat = np.diff(ts[fwd]) * 1e6
    b_iat = np.diff(ts[~fwd]) * 1e6
    n, nf, nb = len(p), int(fwd.sum()), int((~fwd).sum())
    rate = (lambda k: k / dur) if dur > 0 else (lambda k: 0.0)
    gaps = np.diff(ts)
    idle = gaps[gaps > ACTIVITY_TIMEOUT]
    if len(idle):
        bounds = np.flatnonzero(gaps > ACTIVITY_TIMEOUT)
        starts = np.r_[0, bounds + 1]
        ends = np.r_[bounds, len(ts) - 1]
        active = (ts[ends] - ts[starts]) * 1e6
    else:
        active = np.array([])
    count = lambda bit: float(sum(1 for fl_ in flags if fl_ & bit))  # noqa: E731
    win_f = next((x[4] for x in p if x[1] and x[4] is not None), -1)
    win_b = next((x[4] for x in p if not x[1] and x[4] is not None), -1)
    return {
        "flow_duration": dur_us, "fwd_packets": float(nf), "bwd_packets": float(nb),
        "fwd_bytes": float(f_ln.sum()), "bwd_bytes": float(b_ln.sum()),
        "fwd_pkt_len_max": float(f_ln.max()) if nf else 0.0, "fwd_pkt_len_mean": float(f_ln.mean()) if nf else 0.0,
        "bwd_pkt_len_max": float(b_ln.max()) if nb else 0.0, "bwd_pkt_len_mean": float(b_ln.mean()) if nb else 0.0,
        "flow_bytes_per_s": rate(float(ln.sum())), "flow_packets_per_s": rate(n),
        "flow_iat_mean": float(iat.mean()) if len(iat) else 0.0, "flow_iat_std": float(iat.std(ddof=1)) if len(iat) > 1 else 0.0,
        "flow_iat_max": float(iat.max()) if len(iat) else 0.0,
        "fwd_iat_total": float(f_iat.sum()) if len(f_iat) else 0.0, "bwd_iat_total": float(b_iat.sum()) if len(b_iat) else 0.0,
        "fwd_packets_per_s": rate(nf), "bwd_packets_per_s": rate(nb),
        "pkt_len_mean": float(ln.mean()), "pkt_len_std": float(ln.std(ddof=1)) if n > 1 else 0.0,
        "fin_flags": count(0x01), "syn_flags": count(0x02), "rst_flags": count(0x04), "psh_flags": count(0x08),
        "ack_flags": count(0x10), "urg_flags": count(0x20),
        "down_up_ratio": float(nb // nf) if nf else 0.0, "avg_packet_size": float(ln.sum() / n),
        "init_win_fwd": float(win_f), "init_win_bwd": float(win_b),
        "act_data_pkt_fwd": float((f_ln > 0).sum()),
        "active_mean": float(active.mean()) if len(active) else 0.0,
        "idle_mean": float(idle.mean() * 1e6) if len(idle) else 0.0,
    }


def _ip_layer(dpkt, linktype, buf):
    if linktype == 1:  # Ethernet
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type in (0x0800, 0x86DD) and not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            raise ValueError("truncated IP packet")
        return eth.data
    if linktype in (0, 108):  # BSD loopback / NULL (Windows Npcap loopback too)
        fam = struct.unpack("<I", buf[:4])[0] if linktype == 0 else struct.unpack("!I", buf[:4])[0]
        body = buf[4:]
        return dpkt.ip6.IP6(body) if fam in (24, 28, 30) else dpkt.ip.IP(body)
    if linktype in (101, 12, 14, 228, 229):  # raw IP
        return dpkt.ip6.IP6(buf) if buf and buf[0] >> 4 == 6 else dpkt.ip.IP(buf)
    if linktype == 113:  # Linux cooked (SLL)
        return dpkt.sll.SLL(buf).data
    if linktype == 276:  # Linux cooked v2 (SLL2): 20-byte header, protocol in first 2 bytes
        proto = struct.unpack("!H", buf[:2])[0]
        return dpkt.ip6.IP6(buf[20:]) if proto == 0x86DD else dpkt.ip.IP(buf[20:])
    raise ValueError(f"unsupported link type {linktype}")


def packets(data: bytes):
    """Yield (ts, linktype, raw) from pcap or pcapng bytes."""
    import io
    dpkt = _dpkt()
    bio = io.BytesIO(data)
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        rd = dpkt.pcapng.Reader(bio)
    else:
        rd = dpkt.pcap.Reader(bio)
    lt = rd.datalink()
    for ts, buf in rd:
        yield float(ts), lt, buf


def pcap_to_records(data: bytes, rep: IngestReport):
    dpkt = _dpkt()
    flows, done = {}, []
    stats = {"packets_total": 0, "packets_non_ip": 0, "packets_malformed": 0}

    def close(key):
        fl = flows.pop(key)
        done.append(fl)

    for ts, lt, buf in packets(data):
        stats["packets_total"] += 1
        try:
            ip = _ip_layer(dpkt, lt, buf)
        except Exception:  # noqa: BLE001 - malformed/truncated frame
            stats["packets_malformed"] += 1
            continue
        if isinstance(ip, dpkt.ip.IP):
            src, dst, proto = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.p
        elif isinstance(ip, dpkt.ip6.IP6):
            src, dst, proto = (socket.inet_ntop(socket.AF_INET6, ip.src), socket.inet_ntop(socket.AF_INET6, ip.dst),
                               ip.nxt)
        else:
            stats["packets_non_ip"] += 1
            continue
        l4 = ip.data
        sport = dport = 0
        flags, win, plen = 0, None, 0
        # payload length from the IP/TCP/UDP length fields, so captures with a small snap length
        # (tcpdump -s 160, as the lab uses to avoid storing payloads) still give exact byte counts
        ip_payload = (ip.len - ip.hl * 4) if isinstance(ip, dpkt.ip.IP) else ip.plen
        if isinstance(l4, dpkt.tcp.TCP):
            sport, dport, flags, win = l4.sport, l4.dport, l4.flags, l4.win
            plen = max(0, ip_payload - l4.off * 4) if ip_payload else len(l4.data)
        elif isinstance(l4, dpkt.udp.UDP):
            sport, dport = l4.sport, l4.dport
            plen = max(0, ip_payload - 8) if ip_payload else max(0, l4.ulen - 8)
        elif isinstance(l4, (bytes, bytearray)):
            if proto in (6, 17):  # header claimed TCP/UDP but could not be parsed
                stats["packets_malformed"] += 1
                continue
            plen = len(l4)
        else:
            plen = len(bytes(l4.data)) if hasattr(l4, "data") else 0
        a, b = (src, sport), (dst, dport)
        key = (min(a, b), max(a, b), proto)
        fl = flows.get(key)
        if fl is not None and (ts - fl.t0 > FLOW_TIMEOUT or ts - fl.last > FLOW_TIMEOUT):
            close(key)
            fl = None
        if fl is None:
            fl = flows[key] = _Flow(key, a, ts, proto)
        is_fwd = a == fl.fwd
        fl.pkts.append((ts, is_fwd, plen, flags, win))
        fl.last = ts
        if proto == 6:
            if flags & 0x01:
                fl.fin_fwd |= is_fwd
                fl.fin_bwd |= not is_fwd
            if flags & 0x04 or (fl.fin_fwd and fl.fin_bwd):
                close(key)
    done.extend(flows.values())
    for k, v in stats.items():
        rep.reasons[k] = v  # informational packet counters (not flow rejections)
    recs = []
    for fl in sorted(done, key=lambda f: f.t0):
        (sip, sp) = fl.fwd
        other = fl.key[1] if fl.key[0] == fl.fwd else fl.key[0]
        rec = {"observed_at": datetime.fromtimestamp(fl.t0), "src_ip": sip, "src_port": sp,
               "dst_ip": other[0], "dst_port": other[1], "protocol": fl.proto}
        rec.update(_features(fl))
        recs.append(rec)
    return recs


@register_adapter
class PcapAdapter(BaseAdapter):
    name = "pcap"
    description = "Packet capture (.pcap / .pcapng) aggregated into bidirectional flows (payloads discarded)"
    extensions = (".pcap", ".pcapng", ".cap")

    def iter_normalised(self, source, chunksize: int = 200_000):
        rep = IngestReport()
        data = read_bytes(source)
        try:
            recs = pcap_to_records(data, rep)
        except (ValueError, RuntimeError) as e:
            rep.missing_columns = [f"unreadable capture: {e}"]
            yield build_frame([], rep), rep
            return
        except Exception as e:  # noqa: BLE001 - dpkt raises various errors on garbage input
            rep.missing_columns = [f"unreadable capture: {type(e).__name__}"]
            yield build_frame([], rep), rep
            return
        rep.total_rows += len(recs)
        yield build_frame(recs, rep), rep
