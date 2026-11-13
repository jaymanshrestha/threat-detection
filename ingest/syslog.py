"""Syslog adapter: RFC 3164 and RFC 5424 lines, with iptables / UFW / netfilter
style firewall messages (key=value fields such as SRC= DST= PROTO= SPT= DPT=).

Each firewall log line describes ONE packet, so it becomes a single-packet event:
fwd_packets=1, fwd_bytes=LEN (IP total length; CICFlowMeter counts payload bytes,
so this over-estimates), duration 0, TCP flags from the flag tokens, init window
from WINDOW=. The 60 s per-source window counts (port variety, flows per pair) are
computed exactly from these events, which is what the port-scan / flood rules and
most of the model signal rely on. Lines without network fields are counted and
rejected; free text is never fed to the models or the LLM.
"""
import re
from datetime import datetime, timezone

from .base import BaseAdapter, register_adapter
from .flowbuild import build_frame, clean_message, read_text
from .schema import IngestReport

RFC5424 = re.compile(r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) "
                     r"(?P<msgid>\S+) (?P<sd>-|(?:\[.*?\])+) ?(?P<msg>.*)$")
RFC3164 = re.compile(r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (?P<host>\S+) "
                     r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
KV = re.compile(r"\b([A-Z]{2,10})=(\S*)")
FLAGS = ("SYN", "ACK", "FIN", "RST", "PSH", "URG")
ACTION = re.compile(r"\[(UFW [A-Z ]+?)\]|\b(BLOCK|DROP|DENY|REJECT|ACCEPT|ALLOW)\b")


def parse_line(line: str, now: datetime = None):
    """Return a partial flow record dict, or (None, reason)."""
    now = now or datetime.now()
    line = line.strip("\r\n\x00 ")
    m = RFC5424.match(line)
    if m:
        try:
            ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
            if ts.tzinfo:
                ts = ts.astimezone().replace(tzinfo=None)
        except ValueError:
            return None, "bad_timestamp"
        host, app, msg = m["host"], m["app"], m["msg"]
    else:
        m = RFC3164.match(line)
        if not m:
            return None, "unparseable_syslog"
        try:
            ts = datetime.strptime(f"{now.year} {m['ts']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None, "bad_timestamp"
        if (ts - now).days > 1:  # RFC 3164 has no year: a December line read in January
            ts = ts.replace(year=now.year - 1)
        host, app, msg = m["host"], m["tag"], m["msg"]
    kv = dict(KV.findall(msg))
    if "SRC" not in kv or "DST" not in kv:
        return None, "no_network_fields"
    tokens = set(re.findall(r"\b[A-Z]{3}\b", msg))
    flags = {f: (1.0 if f in tokens else 0.0) for f in FLAGS}
    proto = kv.get("PROTO", "OTHER").upper()
    length = float(kv.get("LEN", 0) or 0)
    win = kv.get("WINDOW")
    act = ACTION.search(msg)
    rec = {
        "observed_at": ts, "src_ip": kv["SRC"], "dst_ip": kv["DST"],
        "src_port": kv.get("SPT", 0) or 0, "dst_port": kv.get("DPT", 0) or 0, "protocol": proto,
        "fwd_packets": 1.0, "fwd_bytes": length, "fwd_pkt_len_max": length, "fwd_pkt_len_mean": length,
        "pkt_len_mean": length, "avg_packet_size": length,
        "syn_flags": flags["SYN"], "ack_flags": flags["ACK"], "fin_flags": flags["FIN"],
        "rst_flags": flags["RST"], "psh_flags": flags["PSH"], "urg_flags": flags["URG"],
        "init_win_fwd": float(win) if win and win.isdigit() else -1.0,
        "message": clean_message(f"{host} {app}: {(act.group(1) or act.group(2)) if act else ''} {msg}"),
    }
    return rec, None


def parse_lines(lines, report: IngestReport, now=None):
    recs = []
    for line in lines:
        if not line.strip():
            continue
        report.total_rows += 1
        rec, reason = parse_line(line, now)
        if rec is None:
            report.add_rejects(reason, 1)
        else:
            recs.append(rec)
    return recs


@register_adapter
class SyslogAdapter(BaseAdapter):
    name = "syslog"
    description = "Syslog (RFC 3164 / RFC 5424) incl. iptables / UFW firewall lines - one event per packet log"
    extensions = (".log", ".txt", ".syslog")

    def iter_normalised(self, source, chunksize: int = 200_000):
        rep = IngestReport()
        recs = parse_lines(read_text(source).splitlines(), rep)
        yield build_frame(recs, rep), rep
