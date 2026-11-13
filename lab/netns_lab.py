"""Fallback lab for machines without Docker (Linux only): the same attack scenario inside a
fresh, empty network namespace created with `unshare -rn` (no root needed).

Inside the namespace only the loopback interface exists, so nothing can leave the machine.
The script asserts that, adds the lab addresses 10.66.0.10 (target) and 10.66.0.66 (attacker)
to loopback, starts a tiny HTTP server (:80) and SSH-banner service (:22) on the target address,
captures every packet with an AF_PACKET socket into lab/captures/netns_lab.pcap, and runs
lab/attack.py (benign -> port scan -> SYN flood -> benign).

    python lab/netns_lab.py            # re-executes itself under `unshare -rn`
"""
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
TARGET, ATTACKER = "10.66.0.10", "10.66.0.66"
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4


def in_isolated_ns():
    names = sorted(n for _, n in socket.if_nameindex())
    return names == ["lo"], names


def setup():
    ok, names = in_isolated_ns()
    if not ok:
        sys.exit(f"REFUSED: interfaces {names} present - this must run in an empty network namespace")
    for cmd in (["ip", "link", "set", "lo", "up"], ["ip", "addr", "add", f"{TARGET}/24", "dev", "lo"],
                ["ip", "addr", "add", f"{ATTACKER}/24", "dev", "lo"]):
        subprocess.run(cmd, check=True)


class Sniffer(threading.Thread):
    def __init__(self, path):
        super().__init__(daemon=True)
        import dpkt
        self.fh = open(path, "wb")
        self.w = dpkt.pcap.Writer(self.fh, snaplen=256, linktype=dpkt.pcap.DLT_EN10MB)
        self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.s.bind(("lo", 0))
        self.s.settimeout(0.2)
        self.stop = threading.Event()
        self.count = 0

    def run(self):
        while not self.stop.is_set():
            try:
                buf, addr = self.s.recvfrom(65535)
            except socket.timeout:
                continue
            if addr[2] == PACKET_OUTGOING:  # loopback shows each packet twice; keep the received copy
                continue
            self.w.writepkt(buf[:256], ts=time.time())
            self.count += 1

    def close(self):
        self.stop.set()
        self.join(2)
        self.w.close()


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = f"<h1>lab page {self.path}</h1>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def ssh_banner():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((TARGET, 22))
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        try:
            c.sendall(b"SSH-2.0-OpenSSH_9.6 lab\r\n")
        finally:
            c.close()


def main():
    if os.environ.get("TD_LAB_NS") != "1":
        if not shutil.which("unshare"):
            sys.exit("unshare not found - use the Docker lab instead (see LAB_SAFETY.md)")
        env = dict(os.environ, TD_LAB_NS="1")
        sys.exit(subprocess.call(["unshare", "-rn", sys.executable, __file__] + sys.argv[1:], env=env))
    import attack
    setup()
    cap_dir = HERE / "captures"
    cap_dir.mkdir(exist_ok=True)
    pcap = cap_dir / "netns_lab.pcap"
    sn = Sniffer(pcap)
    sn.start()
    httpd = http.server.ThreadingHTTPServer((TARGET, 80), Quiet)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Thread(target=ssh_banner, daemon=True).start()
    time.sleep(0.5)
    res = attack.run_all(TARGET, source=ATTACKER, use_tools=False)
    time.sleep(1)
    sn.close()
    httpd.shutdown()
    res.update({"mode": "network namespace (unshare -rn), loopback only - Docker not used",
                "pcap": str(pcap.relative_to(HERE.parent)), "packets_captured": sn.count,
                "interfaces": [n for _, n in socket.if_nameindex()]})
    (cap_dir / "netns_lab_phases.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
