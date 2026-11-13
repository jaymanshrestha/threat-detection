"""FR-10 SMS notifications: number validation, throttling, outbox fallback, Twilio REST (mocked), page."""
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import requests

from alerts import notifier, sms
from app import settings
from app.extensions import db
from app.models import AuditLog, Notification, SecurityAlert
from tests.test_accessibility import _check_page
from tests.test_pages import _login

NUM = "+61412345678"


@pytest.fixture
def sms_app(app, tmp_path):
    app.config["SMS_OUTBOX_DIR"] = str(tmp_path / "sms_outbox")
    settings.put("sms_enabled", True)
    settings.put("sms_recipients", [NUM])
    return app


def _alert(sev="Critical", category="DoS / Flood", **kw):
    a = SecurityAlert(src_ip="203.0.113.9", dst_ip="192.168.10.50", category=category, severity=sev, max_risk=0.97,
                      occurrence_count=1, first_seen=datetime.now(), last_seen=datetime.now(), **kw)
    db.session.add(a)
    db.session.commit()
    return a


def _sms():
    return Notification.query.filter_by(channel="SMS").order_by(Notification.id).all()


def _twilio(app):
    app.config.update(SMS_ENABLED=True, TWILIO_ACCOUNT_SID="AC" + "1" * 32, TWILIO_AUTH_TOKEN="secret-token-xyz",
                      TWILIO_FROM_NUMBER="+15005550006")


class _Resp:
    def __init__(self, code, body):
        self.status_code, self._body, self.text = code, body, str(body)

    def json(self):
        return self._body


# ------------------------------------------------------------------ validation
@pytest.mark.parametrize("raw,expected", [
    ("+61412345678", "+61412345678"), ("+61 412 345 678", "+61412345678"), ("0412 345 678", "+61412345678"),
    ("0061412345678", "+61412345678"), ("+1 (415) 555-0100", "+14155550100"),
    ("0412345", None), ("61412345678", None), ("+0412345678", None), ("+61abc", None), ("", None),
    ("+1234567890123456", None)])
def test_e164_normalise(raw, expected):
    assert sms.normalise(raw) == expected


def test_message_is_short_and_has_no_ip(sms_app):
    a = _alert(category="Attack - supervised (type not classified) with a deliberately very long category name " * 3)
    text = notifier.sms_text(a)
    assert len(text) <= 160 and text.startswith("[CRITICAL] ") and f"/alerts/{a.id}" in text
    assert "203.0.113" not in text and "192.168" not in text
    sim = notifier.sms_text(_alert(is_simulated=True))
    assert sim.startswith("[CRITICAL SIMULATED] DoS / Flood at ")


# ------------------------------------------------------------------ throttling / de-dup
def test_sms_once_per_alert_then_suppressed_and_outbox(sms_app):
    a = _alert()
    for _ in range(3):
        notifier.on_alert(a, False, False)
        db.session.commit()
    assert [n.status for n in _sms()] == ["Queued", "Suppressed"]
    notifier.process_queue()
    n = _sms()[0]
    assert n.status == "Outbox" and n.recipients == NUM
    files = list(Path(sms_app.config["SMS_OUTBOX_DIR"]).glob("*.txt"))
    assert len(files) == 1 and "DoS / Flood" in files[0].read_text() and NUM in files[0].read_text()
    assert "Alert SMS sent" in [e.action for e in AuditLog.query]


def test_sms_severity_rise_and_min_severity(sms_app):
    h = _alert("High")
    notifier.on_alert(h, True, False)
    db.session.commit()
    assert _sms() == []  # default SMS minimum is Critical (FR-10)
    settings.put("sms_min_severity", "High")
    notifier.on_alert(h, False, False)
    db.session.commit()
    assert len(_sms()) == 1
    h.severity = "Critical"
    notifier.on_alert(h, False, True)  # severity rose inside the throttle window -> sent again
    db.session.commit()
    assert [n.status for n in _sms()] == ["Queued", "Queued"]


def test_sms_hourly_cap_and_off_switch(sms_app):
    sms_app.config["SMS_MAX_PER_HOUR"] = 2
    for _ in range(4):
        notifier.on_alert(_alert(), True, False)
        db.session.commit()
    assert [n.status for n in _sms()].count("Queued") == 2
    assert [n.status for n in _sms()].count("Suppressed") == 2
    assert "SMS limit 2/hour" in _sms()[-1].reason
    settings.put("sms_enabled", False)
    before = len(_sms())
    notifier.on_alert(_alert(), True, False)
    db.session.commit()
    assert len(_sms()) == before


def test_sms_throttle_expires(sms_app):
    a = _alert()
    a.last_sms_at, a.last_sms_severity = datetime.now() - timedelta(minutes=61), "Critical"
    db.session.commit()
    notifier.on_alert(a, False, False)
    db.session.commit()
    assert [n.status for n in _sms()] == ["Queued"]


def test_sms_works_without_email_recipients(sms_app):
    settings.put("alert_recipients", [])
    notifier.on_alert(_alert(), True, False)
    db.session.commit()
    assert len(_sms()) == 1 and Notification.query.filter(Notification.channel != "SMS").count() == 0


# ------------------------------------------------------------------ transport
def test_outbox_when_credentials_missing(sms_app):
    sms_app.config.update(SMS_ENABLED=True, TWILIO_ACCOUNT_SID="AC1", TWILIO_AUTH_TOKEN="", TWILIO_FROM_NUMBER="+1500")
    assert sms.transport(sms_app.config) == ("outbox", "missing TWILIO_AUTH_TOKEN")
    assert sms.deliver(sms_app.config, [NUM], "hi")[0] == "Outbox"


def test_twilio_success(sms_app, monkeypatch):
    _twilio(sms_app)
    calls = []

    def fake_post(url, data=None, auth=None, timeout=None):
        calls.append((url, data, auth))
        return _Resp(201, {"sid": "SM123", "status": "queued"})
    monkeypatch.setattr(sms.requests, "post", fake_post)
    notifier.on_alert(_alert(), True, False)
    db.session.commit()
    notifier.process_queue()
    n = _sms()[0]
    assert n.status == "Sent" and n.attempts == 1
    url, data, auth = calls[0]
    assert url == f"https://api.twilio.com/2010-04-01/Accounts/{'AC' + '1' * 32}/Messages.json"
    assert data["To"] == NUM and data["From"] == "+15005550006" and len(data["Body"]) <= 160
    assert auth == ("AC" + "1" * 32, "secret-token-xyz")
    assert not list(Path(sms_app.config["SMS_OUTBOX_DIR"]).glob("*.txt"))


def test_twilio_error_recorded_and_email_unaffected(sms_app, monkeypatch):
    _twilio(sms_app)
    monkeypatch.setattr(sms.time, "sleep", lambda s: None)
    monkeypatch.setattr(sms.requests, "post", lambda *a, **k: _Resp(
        400, {"code": 21608, "message": "The number is unverified.", "status": 400}))
    notifier.on_alert(_alert(), True, False)
    db.session.commit()
    notifier.process_queue()
    s = _sms()[0]
    assert s.status == "Failed" and s.attempts == 1 and "21608" in s.error and "verified" in s.error
    assert "secret-token-xyz" not in (s.error or "")
    email = Notification.query.filter(Notification.channel != "SMS").one()
    assert email.status == "Outbox"  # UC-09 E2: SMS failure never affects email
    assert "Alert SMS failed" in [e.action for e in AuditLog.query]


def test_twilio_network_error_retried(sms_app, monkeypatch):
    _twilio(sms_app)
    monkeypatch.setattr(sms.time, "sleep", lambda s: None)
    tries = []

    def boom(*a, **k):
        tries.append(1)
        if len(tries) < 3:
            raise requests.ConnectionError("no route")
        return _Resp(201, {"sid": "SM1"})
    monkeypatch.setattr(sms.requests, "post", boom)
    assert sms.deliver(sms_app.config, [NUM], "x") == ("Sent", 3, None)
    tries.clear()
    monkeypatch.setattr(sms.requests, "post", lambda *a, **k: _Resp(503, {"message": "busy"}))
    status, attempts, err = sms.deliver(sms_app.config, [NUM, "+61400000000"], "x")
    assert status == "Failed" and attempts == 3 and "503" in err


# ------------------------------------------------------------------ page
def test_sms_settings_page(client, app, tmp_path):
    app.config["SMS_OUTBOX_DIR"] = str(tmp_path / "sms_outbox")
    _login(client)
    page = client.get("/notifications").get_data(as_text=True)
    _check_page(page, "/notifications")
    assert "Demo outbox" in page and "TWILIO_AUTH_TOKEN not set" in page and "Planned" not in page
    rev = settings.get("notification_revision")
    r = client.post("/notifications/sms", data={"sms_numbers": "+61412345678, 12345", "sms_enabled": "on",
                                                "sms_min_severity": "Critical", "revision": rev}, follow_redirects=True)
    assert b"Invalid mobile number: 12345" in r.data and settings.get("sms_recipients") == []  # UC-05 E5
    many = ",".join(f"+614000000{i:02d}" for i in range(11))
    r = client.post("/notifications/sms", data={"sms_numbers": many, "sms_enabled": "on", "sms_min_severity": "Critical",
                                                "revision": rev}, follow_redirects=True)
    assert b"at most 10 mobile numbers" in r.data
    r = client.post("/notifications/sms", data={"sms_numbers": "", "sms_enabled": "on", "sms_min_severity": "Critical",
                                                "revision": rev}, follow_redirects=True)
    assert b"Add at least one mobile number" in r.data
    r = client.post("/notifications/sms", data={"sms_numbers": "0412 345 678", "sms_enabled": "on",
                                                "sms_min_severity": "High", "revision": rev}, follow_redirects=True)
    assert b"SMS settings saved" in r.data
    assert settings.get("sms_recipients") == [NUM] and settings.get("sms_enabled") and settings.get("sms_min_severity") == "High"
    r = client.post("/notifications/sms", data={"sms_numbers": NUM, "sms_min_severity": "Critical", "revision": rev},
                    follow_redirects=True)
    assert b"Another administrator changed" in r.data  # stale revision (UC-05 E7)
    r = client.post("/notifications/test-sms", follow_redirects=True)
    assert b"Test SMS written to the SMS outbox" in r.data
    n = Notification.query.filter_by(channel="SMS", kind="test").one()
    assert n.status == "Outbox"
    assert {"SMS settings changed", "Test SMS sent"} <= {e.action for e in AuditLog.query}
    page = client.get("/notifications").get_data(as_text=True)
    assert 'value="+61412345678"' in page and ">SMS<" in page


def test_sms_page_twilio_failure_banner(client, app, monkeypatch):
    _twilio(app)
    _login(client)
    settings.put("sms_recipients", [NUM])
    page = client.get("/notifications").get_data(as_text=True)
    assert "Twilio configured" in page and "+15005550006" in page and "secret-token-xyz" not in page
    monkeypatch.setattr(sms.requests, "post", lambda *a, **k: _Resp(401, {"code": 20003, "message": "Authenticate"}))
    r = client.post("/notifications/test-sms", follow_redirects=True)
    body = r.get_data(as_text=True)
    assert "Test SMS not delivered" in body and "20003" in body and "secret-token-xyz" not in body
    assert "SMS alert(s) were not delivered" in body and "alert email(s) failed" not in body
