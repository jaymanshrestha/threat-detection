"""Regenerate tests/fixtures/sample.pcap (synthetic, deterministic): one complete HTTP
TCP session, a 30-port SYN scan answered with RSTs, a DNS query/response, one ARP
frame (non-IP) and one truncated frame (malformed)."""
import socket
from pathlib import Path

import dpkt

A, T, D = "10.66.0.66", "10.66.0.10", "10.66.0.53"
MAC_A, MAC_T = b"\x02\x00\x00\x00\x00\x66", b"\x02\x00\x00\x00\x00\x10"


def frame(src, dst, l4, proto):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=64, data=l4)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=MAC_A, dst=MAC_T, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def tcp(sp, dp, flags, data=b"", win=64240, seq=1, ack=0):
    return dpkt.tcp.TCP(sport=sp, dport=dp, flags=flags, win=win, seq=seq, ack=ack, data=data)


def build(path):
    F = dpkt.tcp
    t = 1499331600.0  # 2017-07-06 09:00 UTC (arbitrary, fixed)
    pk = []
    # HTTP session
    pk += [(t, frame(A, T, tcp(50000, 80, F.TH_SYN), 6)),
           (t + 0.001, frame(T, A, tcp(80, 50000, F.TH_SYN | F.TH_ACK, win=65160), 6)),
           (t + 0.002, frame(A, T, tcp(50000, 80, F.TH_ACK), 6)),
           (t + 0.003, frame(A, T, tcp(50000, 80, F.TH_PUSH | F.TH_ACK, b"GET / HTTP/1.1\r\nHost: t\r\n\r\n"), 6)),
           (t + 0.010, frame(T, A, tcp(80, 50000, F.TH_PUSH | F.TH_ACK, b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 500), 6)),
           (t + 0.011, frame(A, T, tcp(50000, 80, F.TH_FIN | F.TH_ACK), 6)),
           (t + 0.012, frame(T, A, tcp(80, 50000, F.TH_FIN | F.TH_ACK), 6)),
           (t + 0.013, frame(A, T, tcp(50000, 80, F.TH_ACK), 6))]
    # SYN scan
    for i, port in enumerate(range(1, 31)):
        ts = t + 1 + i * 0.002
        pk.append((ts, frame(A, T, tcp(40000, port, F.TH_SYN, win=1024), 6)))
        pk.append((ts + 0.0005, frame(T, A, tcp(port, 40000, F.TH_RST | F.TH_ACK, win=0), 6)))
    # DNS
    pk.append((t + 2, frame(A, D, dpkt.udp.UDP(sport=53001, dport=53, data=b"\x12\x34" + b"q" * 30), 17)))
    pk.append((t + 2.004, frame(D, A, dpkt.udp.UDP(sport=53, dport=53001, data=b"\x12\x34" + b"r" * 60), 17)))
    # ARP and truncated
    arp = dpkt.ethernet.Ethernet(src=MAC_A, dst=b"\xff" * 6, type=dpkt.ethernet.ETH_TYPE_ARP, data=dpkt.arp.ARP())
    pk.append((t + 3, bytes(arp)))
    pk.append((t + 3.1, frame(A, T, tcp(1, 2, F.TH_SYN), 6)[:20]))
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, buf in sorted(pk, key=lambda x: x[0]):
            w.writepkt(buf, ts=ts)


if __name__ == "__main__":
    build(Path(__file__).with_name("sample.pcap"))
