"""Send NetFlow v5 datagrams to the collector (demo traffic, timestamped now).

    python scripts/send_netflow.py                       # benign flows + a SYN flood towards one host
    python scripts/send_netflow.py --host 127.0.0.1 --port 2055
"""
import argparse
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ingest.netflow import encode_v5  # noqa: E402


def demo_records(flood=1200, benign=200, seed=11):
    rnd = random.Random(seed)
    now = time.time() - 30
    recs = []
    for i in range(benign):
        st = now + rnd.random() * 25
        recs.append(dict(start=st, end=st + rnd.random() * 3, src_ip=f"192.168.10.{rnd.choice([5, 8, 12])}",
                         dst_ip=f"93.184.216.{rnd.randint(1, 40)}", src_port=rnd.randint(30000, 60000),
                         dst_port=rnd.choice([80, 443, 443]), packets=rnd.randint(4, 60),
                         bytes=rnd.randint(400, 60000), tcp_flags=0x1b, protocol=6))
    for i in range(flood):
        st = now + 5 + i * 0.01
        recs.append(dict(start=st, end=st, src_ip="198.51.100.23", dst_ip="192.168.10.50",
                         src_port=1024 + i % 60000, dst_port=80, packets=1, bytes=40, tcp_flags=0x02, protocol=6))
    return sorted(recs, key=lambda r: r["start"])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2055)
    a = ap.parse_args()
    grams = encode_v5(demo_records())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for g in grams:
        s.sendto(g, (a.host, a.port))
        time.sleep(0.005)
    print(f"sent {len(grams)} NetFlow v5 datagrams to {a.host}:{a.port}")


if __name__ == "__main__":
    main()
