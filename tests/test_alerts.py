"""Severity, de-duplication and email throttling."""
from datetime import datetime, timedelta

import pandas as pd

from alerts import notifier
from alerts.severity import classify
from app import pipeline
from app.extensions import db
from app.models import Notification, SecurityAlert
from ingest import get_adapter
from tests.conftest import FIXTURE


def test_severity_mapping():
    assert classify(0.95, 0.7) == "Critical"
    assert classify(0.5, 0.7, "DoS / Flood") == "Critical"
    assert classify(0.85, 0.7) == "High"
    assert classify(0.72, 0.7) == "Medium"
    assert classify(0.3, 0.7, "Port Scan") == "Low"
    assert classify(0.3, 0.7) == ""


def _alert(sev="Critical", **kw):
    a = SecurityAlert(src_ip="10.0.0.1", dst_ip="10.0.0.2", category="Port Scan", severity=sev, max_risk=0.95,
                      occurrence_count=1, first_seen=datetime.now(), last_seen=datetime.now(), **kw)
    db.session.add(a); db.session.commit()
    return a


def test_critical_emailed_once_then_throttled(app):
    a = _alert()
    notifier.on_alert(a, True, False); db.session.commit()
    notifier.on_alert(a, False, False); db.session.commit()
    notifier.on_alert(a, False, False); db.session.commit()
    statuses = [n.status for n in Notification.query.order_by(Notification.id)]
    assert statuses == ["Queued", "Suppressed"]
    assert notifier.process_queue() == 1
    n = Notification.query.filter_by(kind="immediate", status="Outbox").one()
    assert "Port Scan" in n.subject and "10.0.0.1" in n.body


def test_high_goes_to_digest(app):
    a = _alert("High")
    notifier.on_alert(a, True, False); db.session.commit()
    assert a.pending_digest and Notification.query.count() == 0
    n = notifier.build_digest(force=True)
    assert n.kind == "digest" and "1 High" in n.subject and not a.pending_digest


def test_global_hourly_cap(app):
    app.config["EMAIL_MAX_PER_HOUR"] = 2
    alerts = [_alert() for _ in range(4)]
    for a in alerts:
        notifier.on_alert(a, True, False); db.session.commit()
    assert Notification.query.filter_by(status="Queued").count() == 2
    assert Notification.query.filter_by(status="Suppressed").count() == 2
    assert sum(a.pending_digest for a in alerts) == 2


def test_severity_rise_bypasses_per_alert_throttle(app):
    a = _alert("Critical")
    a.last_emailed_at, a.last_emailed_severity = datetime.now() - timedelta(minutes=1), "High"
    db.session.commit()
    notifier.on_alert(a, False, True); db.session.commit()
    assert Notification.query.filter_by(status="Queued").count() == 1


def test_pipeline_dedups_scan_into_one_alert(app):
    # rules-only (no model file in this config) with low thresholds -> deterministic
    app.config["MODEL_PATH"] = "/nonexistent.joblib"
    app.config["RF_MODEL_PATH"] = "/nonexistent-rf.joblib"
    pipeline._models.clear(); pipeline.reset_window()
    pipeline._models.update({"key": (app.config["MODEL_PATH"], app.config["RF_MODEL_PATH"], app.config["RULES_PATH"])})
    from ml.detectors import RuleDetector
    pipeline._models.update({"isolation_forest": None, "random_forest": None,
                             "rules": RuleDetector(portscan_ports=20, flood_flows=10_000)})
    job, stats = pipeline.ingest_bytes(FIXTURE.read_bytes(), "sample.csv", source="test")
    assert job.status == "Completed" and stats["events"] == job.accepted
    alerts = SecurityAlert.query.all()
    scans = [a for a in alerts if a.category == "Port Scan"]
    assert len(scans) >= 1 and sum(a.occurrence_count for a in scans) == stats["flagged"]
    assert max(a.occurrence_count for a in scans) > 10  # many detections grouped into few alerts
    pipeline._models.clear()


def test_test_email_written_to_outbox_without_smtp(app, tmp_path):
    from app.security import audit  # noqa: F401
    n = notifier.send_test_email(None)
    assert n.status == "Outbox"
    files = list((tmp_path / "outbox").glob("*.eml"))
    assert len(files) == 1 and "[TEST]" in files[0].read_text()
