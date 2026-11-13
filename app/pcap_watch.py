"""Interval capture source (v5 report UC-08 A1, Should Have).

A packet-capture tool (e.g. `tcpdump -G 300 -w inbox/cap-%s.pcap` on the lab host) writes one file per
interval into PCAP_WATCH_DIR. Every PCAP_INTERVAL_SECONDS this watcher processes finished files through
the normal pipeline (profile "pcap": flows are built from packets, payloads are never stored) and then
deletes the raw capture (data minimisation). Unreadable captures are moved to rejected/ (UC-08 E5)."""
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import current_app

from .security import audit

SOURCE = "pcap-interval"
EXTS = (".pcap", ".pcapng", ".cap")
_state = {"last_scan": None, "last_file": None, "last_status": None, "thread": False}


def inbox():
    d = Path(current_app.config["PCAP_WATCH_DIR"])
    (d / "rejected").mkdir(parents=True, exist_ok=True)
    return d


def pending():
    return sorted(p for p in inbox().iterdir() if p.is_file() and p.suffix.lower() in EXTS)


def scan_once(min_age=0.0):
    """Process every finished capture in the inbox. Returns a list of (file, status, accepted, rejected)."""
    from .pipeline import ingest_bytes
    out = []
    for p in pending():
        if time.time() - p.stat().st_mtime < min_age:  # still being written
            continue
        job, _stats = ingest_bytes(p.read_bytes(), p.name, source=SOURCE, profile="pcap")
        if job.status == "Rejected":
            p.replace(p.parent / "rejected" / p.name)
            audit("Capture file rejected", actor=SOURCE, filename=p.name, reasons=job.reasons)
        else:
            p.unlink(missing_ok=True)
            audit("Capture file processed", actor=SOURCE, filename=p.name, job_id=job.id,
                  accepted=job.accepted, rejected=job.rejected)
        out.append((p.name, job.status, job.accepted, job.rejected))
        _state.update(last_file=p.name, last_status=job.status)
    _state["last_scan"] = datetime.now()
    return out


def status():
    cfg = current_app.config
    d = Path(cfg["PCAP_WATCH_DIR"])
    rejected = sorted((d / "rejected").glob("*")) if (d / "rejected").exists() else []
    return {"enabled": bool(cfg.get("PCAP_WATCH_ENABLED")), "running": _state["thread"], "dir": str(d),
            "interval": cfg["PCAP_INTERVAL_SECONDS"], "waiting": len(pending()) if d.exists() else 0,
            "rejected": [p.name for p in rejected[-5:]], **{k: _state[k] for k in ("last_scan", "last_file", "last_status")}}


def start_for_app(app):
    if _state["thread"]:
        return

    def loop():
        while True:
            time.sleep(app.config["PCAP_INTERVAL_SECONDS"])
            try:
                with app.app_context():
                    scan_once(min_age=5)
            except Exception:  # noqa: BLE001
                app.logger.exception("interval capture scan failed")

    threading.Thread(target=loop, name="pcap-watch", daemon=True).start()
    _state["thread"] = True
