"""Send syslog lines to the collector (for demos and testing the streaming path).

    python scripts/send_syslog.py --demo                 # benign firewall lines + a port scan, timestamped now
    python scripts/send_syslog.py --file firewall.log    # replay an existing log file
    python scripts/send_syslog.py --demo --tcp --rate 500

Only sends to the host you name (default 127.0.0.1).
"""
import argparse
import random
import socket
import time
from datetime import datetime, timezone


def demo_lines(scan_ports=1000, benign=300, scanner="203.0.113.50", target="192.168.10.50", seed=7):
    rnd = random.Random(seed)
    now = datetime.now(timezone.utc)
    lines = []
    internal = [f"192.168.10.{i}" for i in (5, 8, 12, 19, 25)]
    for i in range(benign):
        s = rnd.choice(internal)
        dport = rnd.choice([53, 80, 443, 443, 443, 123])
        proto = "UDP" if dport in (53, 123) else "TCP"
        lines.append((rnd.random() * 20, f"[UFW ALLOW] IN=eth0 OUT=eth1 SRC={s} DST=93.184.216.{rnd.randint(1, 50)} "
                                         f"LEN={rnd.randint(60, 1400)} TTL=64 PROTO={proto} SPT={rnd.randint(30000, 60000)} "
                                         f"DPT={dport}" + (" WINDOW=64240 ACK PSH URGP=0" if proto == "TCP" else "")))
    for i, port in enumerate(rnd.sample(range(1, 10000), scan_ports)):
        lines.append((5 + i * 0.01, f"[UFW BLOCK] IN=eth0 OUT= SRC={scanner} DST={target} LEN=44 TTL=45 PROTO=TCP "
                                    f"SPT={40000 + i % 20000} DPT={port} WINDOW=1024 RES=0x00 SYN URGP=0"))
    lines.sort()
    out = []
    for off, body in lines:
        ts = datetime.fromtimestamp(now.timestamp() + off - 25, timezone.utc).isoformat(timespec="milliseconds")
        out.append(f"<134>1 {ts} fw01 kernel - - - {body}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--tcp", action="store_true", help="use TCP (newline framing) instead of UDP")
    ap.add_argument("--file")
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--rate", type=float, default=1000, help="lines per second")
    a = ap.parse_args()
    if a.file:
        with open(a.file, encoding="utf-8", errors="replace") as fh:
            lines = [ln.rstrip("\n") for ln in fh if ln.strip()]
    elif a.demo:
        lines = demo_lines()
    else:
        ap.error("use --demo or --file")
    delay = 1.0 / a.rate if a.rate > 0 else 0
    if a.tcp:
        s = socket.create_connection((a.host, a.port), timeout=10)
        for ln in lines:
            s.sendall(ln.encode() + b"\n")
            if delay:
                time.sleep(delay)
        s.close()
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for ln in lines:
            s.sendto(ln.encode(), (a.host, a.port))
            if delay:
                time.sleep(delay)
    print(f"sent {len(lines)} syslog lines to {a.host}:{a.port} ({'TCP' if a.tcp else 'UDP'})")


if __name__ == "__main__":
    main()
