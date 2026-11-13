"""Syslog, NetFlow v5, nfdump CSV and pcap adapters + per-format upload pages and API."""
import io
from datetime import datetime
from pathlib import Path

import dpkt
import pytest

from app.models import IngestionJob, NetworkEvent
from ingest import ADAPTERS, get_adapter
from ingest.netflow import encode_v5, parse_v5_datagram
from ingest.syslog import parse_line
from tests.test_pages import _login

FX = Path(__file__).parent / "fixtures"


def test_all_adapters_registered():
    assert {"cicids2017", "syslog", "netflow_v5", "nfdump_csv", "pcap"} <= set(ADAPTERS)


def test_syslog_fixture_rfc3164_rfc5424_ufw_iptables():
    df, rep = get_adapter("syslog").load((FX / "syslog_sample.log").read_bytes())
    assert rep.total_rows == 11 and rep.accepted == 8 and rep.rejected == 3
    assert rep.reasons == {"no_network_fields": 1, "unparseable_syslog": 1, "invalid_ip": 1}
    first = df.iloc[0]
    assert (first.src_ip, first.dst_ip, int(first.dst_port), first.protocol) == ("203.0.113.50", "192.168.10.50", 22, "TCP")
    assert first.syn_flags == 1 and first.init_win_fwd == 29200 and first.fwd_bytes == 60
    assert "2001:db8::5" in set(df.src_ip)  # IPv6 UFW line
    r5424 = df[df.dst_port == 445].iloc[0]
    assert r5424.observed_at.year == 2017  # RFC 5424 carries a full timestamp
    # window features are computed downstream; messages are sanitised and capped
    assert df["message"].str.len().max() <= 300
    assert not df["message"].str.contains("[\x00-\x1f]", regex=True).any()


def test_syslog_control_chars_and_junk():
    rec, reason = parse_line("Jul  6 09:01:02 fw kernel: [UFW BLOCK] SRC=10.0.0.1 DST=10.0.0.2 PROTO=TCP SPT=1 DPT=2 SYN \x1b[31mred\x07")
    assert reason is None and rec["src_ip"] == "10.0.0.1" and int(rec["dst_port"]) == 2
    assert not any(ord(c) < 32 for c in rec.get("message", ""))
    assert parse_line("garbage")[0] is None


def test_nfdump_csv():
    df, rep = get_adapter("nfdump_csv").load((FX / "nfdump_sample.csv").read_bytes())
    assert rep.total_rows == 5 and rep.accepted == 4 and rep.reasons == {"invalid_ip": 1}
    https = df[df.dst_port == 443].iloc[0]
    assert https.fwd_packets == 12 and https.bwd_packets == 10 and https.bwd_bytes == 8800
    assert https.flow_duration == pytest.approx(1.33e6, rel=1e-3)
    assert https.fin_flags == 1 and https.psh_flags == 1 and https.syn_flags == 1


def test_netflow_v5_roundtrip_and_errors():
    t0 = datetime(2017, 7, 6, 9, 0).timestamp()
    recs = [dict(start=t0 + i, end=t0 + i + 0.5, src_ip="172.16.0.1", dst_ip="192.168.10.50", src_port=1000 + i,
                 dst_port=80, packets=3, bytes=180, tcp_flags=0x12, protocol=6) for i in range(45)]
    grams = encode_v5(recs)
    assert len(grams) == 2  # 30 records max per datagram
    out, used = parse_v5_datagram(grams[0])
    assert len(out) == 30 and used == len(grams[0])
    assert out[0]["observed_at"] == datetime.fromtimestamp(t0)
    df, rep = get_adapter("netflow_v5").load(b"".join(grams))
    assert rep.accepted == 45 and df.flow_duration.iloc[0] == pytest.approx(5e5)
    assert df.syn_flags.iloc[0] == 1 and df.ack_flags.iloc[0] == 1 and df.bwd_packets.iloc[0] == 0
    with pytest.raises(ValueError):
        parse_v5_datagram(b"\x00\x09" + b"\x00" * 30)  # NetFlow v9 header
    df, rep = get_adapter("netflow_v5").load(grams[0][:-10])  # truncated
    assert rep.accepted < 30 and rep.rejected >= 1 or rep.missing_columns
    fx, rep = get_adapter("netflow_v5").load((FX / "netflow_v5_sample.bin").read_bytes())
    assert rep.accepted == 41


def test_pcap_bidirectional_flows():
    df, rep = get_adapter("pcap").load((FX / "sample.pcap").read_bytes())
    assert rep.reasons["packets_total"] == 72 and rep.reasons["packets_non_ip"] == 1
    assert rep.reasons["packets_malformed"] == 1
    http = df[(df.dst_port == 80) & (df.fwd_packets == 4)].iloc[0]
    assert http.src_ip == "10.66.0.66" and http.bwd_packets == 3
    assert http.fwd_bytes == 27 and http.bwd_bytes == 519  # payload bytes, headers excluded (CICFlowMeter style)
    assert http.init_win_fwd == 64240 and http.init_win_bwd == 65160
    assert http.syn_flags == 2 and http.fin_flags == 2 and http.act_data_pkt_fwd == 1
    assert http.flow_duration == pytest.approx(12000, rel=1e-3)  # microseconds
    scan = df[(df.src_port == 40000)]
    assert len(scan) == 30 and (scan.rst_flags == 1).all() and (scan.bwd_packets == 1).all()
    dns = df[df.protocol == "UDP"].iloc[0]
    assert dns.fwd_bytes == 32 and dns.bwd_bytes == 62


def test_pcap_snaplen_truncation_and_pcapng_and_garbage():
    raw = (FX / "sample.pcap").read_bytes()
    full, _ = get_adapter("pcap").load(raw)
    buf, buf_ng = io.BytesIO(), io.BytesIO()
    w, wng = dpkt.pcap.Writer(buf), dpkt.pcapng.Writer(buf_ng)
    for ts, b in dpkt.pcap.Reader(io.BytesIO(raw)):
        w.writepkt(b[:64], ts=ts)
        wng.writepkt(b, ts=ts)
    trunc, _ = get_adapter("pcap").load(buf.getvalue())
    assert trunc.fwd_bytes.sum() == full.fwd_bytes.sum() and trunc.bwd_bytes.sum() == full.bwd_bytes.sum()
    ng, _ = get_adapter("pcap").load(buf_ng.getvalue())
    assert len(ng) == len(full)
    df, rep = get_adapter("pcap").load(b"not a capture" * 10)
    assert df.empty and rep.missing_columns


@pytest.mark.parametrize("profile,fname", [("syslog", "syslog_sample.log"), ("nfdump_csv", "nfdump_sample.csv"),
                                           ("netflow_v5", "netflow_v5_sample.bin"), ("pcap", "sample.pcap")])
def test_upload_page_per_format(client, profile, fname):
    _login(client)
    assert client.get(f"/sources/upload/{profile}").status_code == 200
    r = client.post(f"/sources/upload/{profile}", data={"file": (io.BytesIO((FX / fname).read_bytes()), fname)},
                    content_type="multipart/form-data")
    assert r.status_code == 302
    job = IngestionJob.query.one()
    assert job.profile == profile and job.status == "Completed" and job.accepted > 0
    assert NetworkEvent.query.count() == job.accepted


def test_upload_rejects_wrong_extension_and_unknown_profile(client):
    _login(client)
    r = client.post("/sources/upload/pcap", data={"file": (io.BytesIO(b"x"), "evil.exe")},
                    content_type="multipart/form-data")
    # UC-08 E1: unsupported file -> 400 with a message, nothing stored (report SD-02 "400 Bad Request")
    assert r.status_code == 400 and IngestionJob.query.count() == 0
    assert b"Unsupported file type" in r.data
    assert client.get("/sources/upload/nope").status_code == 404


def test_api_ingest_profile(client, app):
    h = {"X-API-Key": app.config["INGEST_API_KEY"]}
    r = client.post("/api/v1/ingest?profile=syslog&filename=fw.log", data=(FX / "syslog_sample.log").read_bytes(), headers=h)
    assert r.status_code == 200 and r.json["accepted"] == 8
    assert client.post("/api/v1/ingest?profile=bogus", data=b"x", headers=h).status_code == 400
    assert NetworkEvent.query.filter(NetworkEvent.message.isnot(None)).count() == 8
