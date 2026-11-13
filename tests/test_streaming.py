"""Streaming collectors (syslog UDP/TCP, NetFlow v5 UDP) and Server-Sent Events push."""
import socket
import time
from datetime import datetime
from pathlib import Path

from app.models import IngestionJob, NetworkEvent
from ingest.collectors import CollectorService, app_handler
from ingest.netflow import encode_v5
from tests.test_pages import _login

FX = Path(__file__).parent / "fixtures"
LINE = (b"<134>1 2017-07-06T09:01:06.123+00:00 edge01 kernel - - - [UFW BLOCK] IN=eth1 OUT= SRC=203.0.113.51 "
        b"DST=192.168.10.8 LEN=52 TTL=50 PROTO=TCP SPT=51515 DPT=445 WINDOW=64240 SYN URGP=0")


def _wait(pred, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def test_collectors_receive_udp_tcp_and_netflow():
    got = []
    svc = CollectorService(lambda p, b: got.append((p, b)), syslog_udp=0, syslog_tcp=0, netflow_udp=0,
                           flush_seconds=0.2).start()
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.sendto(LINE, ("127.0.0.1", svc.bound["syslog_udp"]))
        t = socket.create_connection(("127.0.0.1", svc.bound["syslog_tcp"]))
        t.sendall(LINE + b"\n" + str(len(LINE)).encode() + b" " + LINE + b"\n")  # newline + octet-counting framing
        t.close()
        t0 = datetime(2017, 7, 6, 9).timestamp()
        for g in encode_v5([dict(start=t0, end=t0 + 1, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1, dst_port=2,
                                 packets=1, bytes=40, tcp_flags=2, protocol=6)]):
            u.sendto(g, ("127.0.0.1", svc.bound["netflow_udp"]))
        assert _wait(lambda: svc.buf.received["syslog"] >= 3 and svc.buf.received["netflow_v5"] >= 1)
        assert _wait(lambda: any(p == "netflow_v5" for p, _ in got) and
                     sum(b.count(b"UFW BLOCK") for p, b in got if p == "syslog") >= 3)
        assert all(not b.split(b"\n")[-1].startswith(b"52 ") for p, b in got if p == "syslog")
    finally:
        svc.stop()


def test_collector_scores_into_database(app):
    svc = CollectorService(app_handler(app), syslog_udp=0, syslog_tcp=None, netflow_udp=None,
                           flush_seconds=0.2).start()
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for line in (FX / "syslog_sample.log").read_bytes().splitlines():
            u.sendto(line, ("127.0.0.1", svc.bound["syslog_udp"]))
        assert _wait(lambda: svc.flushes > 0 and svc.buf.received["syslog"] >= 11)
        time.sleep(0.5)
    finally:
        svc.stop()
    jobs = IngestionJob.query.filter(IngestionJob.source == "stream:syslog").all()
    assert jobs and sum(j.accepted for j in jobs) == 8
    assert NetworkEvent.query.count() == 8


def test_sse_stream_pushes_ticks(client, app):
    assert client.get("/api/stream").status_code == 401  # login required
    _login(client)
    app.config.update(STREAM_SECONDS=0.3, STREAM_POLL_SECONDS=0.1)
    r = client.get("/api/stream")
    assert r.status_code == 200 and r.mimetype == "text/event-stream"
    body = r.get_data(as_text=True)
    assert "retry: 3000" in body and "event: tick" in body and '"event_id"' in body
