"""Behaviour required by the v5 proposal's use cases (UC-01 .. UC-11) that the earlier MVP lacked."""
import io
import re
from datetime import datetime, timedelta
from pathlib import Path

import pyotp

from app import settings
from app.extensions import db
from app.models import (Administrator, AuditLog, Dataset, Incident, IncidentAlert, IncidentReport, Invitation,
                        Notification, SecurityAlert, SimulationRun)
from tests.conftest import FIXTURE
from tests.test_accessibility import _check_page
from tests.test_pages import _login
from tests.test_reports import _alert


def _actions():
    return [e.action for e in AuditLog.query.order_by(AuditLog.id)]


def _invite_link(app):
    eml = sorted(Path(app.config["OUTBOX_DIR"]).glob("*.eml"))[-1].read_text()
    return re.search(r"/invite/[A-Za-z0-9_\-]+", eml).group(0)


# ------------------------------------------------------------ UC-01 / UC-07
def test_uc07_invite_by_email_and_uc01_a3_first_sign_in(client, app):
    _login(client)
    assert client.post("/users", data={"email": "not-an-email"}).status_code == 400  # E1
    assert client.post("/users", data={"email": "ops@example.com"}).status_code == 400  # E2 duplicate
    r = client.post("/users", data={"email": "New.Analyst@Example.com"})
    assert r.status_code == 302
    u = Administrator.query.filter_by(email="new.analyst@example.com").one()
    assert u.invite_pending and not u.active and not u.mfa_enabled
    inv = Invitation.query.filter_by(administrator_id=u.id).one()
    assert inv.expires_at - datetime.now() <= timedelta(hours=24) and len(inv.token_hash) == 64
    n = Notification.query.filter_by(kind="invitation").one()
    assert n.status == "Outbox" and "<token>" in n.body  # the stored copy never contains the live token
    assert "Invited" in client.get("/users").get_data(as_text=True)
    link = _invite_link(app)

    # A4 resend: the earlier link stops working
    client.post(f"/users/{u.id}/resend")
    new_link = _invite_link(app)
    assert new_link != link
    client.post("/logout")
    r = client.get(link)
    assert r.status_code == 410 and b"expired or has already been used" in r.data  # UC-01 E6

    # UC-01 A3: set password -> enrol authenticator -> account activated
    page = client.get(new_link)
    assert page.status_code == 200
    _check_page(page.get_data(as_text=True), "/invite")
    assert client.post(new_link, data={"password": "short", "confirm": "short"}).status_code == 400
    r = client.post(new_link, data={"password": "invited-password-123", "confirm": "invited-password-123"})
    assert r.headers["Location"].endswith("/mfa/enrol")
    page = client.get("/mfa/enrol").get_data(as_text=True)
    secret = re.search(r"<code>([A-Z2-7]+)</code>", page).group(1)
    r = client.post("/mfa/enrol", data={"code": pyotp.TOTP(secret).now()})
    assert r.headers["Location"].endswith("/login")
    db.session.expire_all()
    u = db.session.get(Administrator, u.id)
    assert u.active and u.mfa_enabled and not u.invite_pending
    assert client.get(new_link).status_code == 410  # single use
    assert "Invitation accepted, MFA enrolled, account activated" in _actions()


def test_uc07_change_email_disable_rules(client):
    _login(client)
    me = Administrator.query.filter_by(email="ops@example.com").one()
    client.post("/users", data={"email": "second@example.com"})
    other = Administrator.query.filter_by(email="second@example.com").one()
    client.post(f"/users/{other.id}/email", data={"email": "renamed@example.com"})  # A1
    assert db.session.get(Administrator, other.id).email == "renamed@example.com"
    client.post(f"/users/{other.id}/email", data={"email": "ops@example.com"})  # E2 duplicate
    assert db.session.get(Administrator, other.id).email == "renamed@example.com"
    r = client.post(f"/users/{me.id}/toggle", follow_redirects=True)  # E3 own account
    assert b"cannot disable your own account" in r.data and db.session.get(Administrator, me.id).active
    assert "User email changed" in _actions()


def test_uc01_a1_login_returns_to_linked_alert(client):
    a = _alert()
    r = client.get(f"/alerts/{a.id}")
    assert r.status_code == 302 and "next=" in r.headers["Location"]
    client.get(r.headers["Location"])
    secret = pyotp.random_base32()
    from app.security import encrypt_secret, hash_password
    db.session.add(Administrator(email="ops@example.com", password_hash=hash_password("a-long-password-123"),
                                 totp_secret_enc=encrypt_secret(secret), mfa_enabled=True))
    db.session.commit()
    client.post("/login", data={"email": "ops@example.com", "password": "a-long-password-123"})
    r = client.post("/mfa", data={"code": pyotp.TOTP(secret).now()})
    assert r.headers["Location"].endswith(f"/alerts/{a.id}")
    # open redirects are refused
    assert client.get("/login?next=//evil.example.com/x").status_code == 302


# ------------------------------------------------------------ UC-02 simulator
def test_uc02_replay_from_lab_dataset(client):
    _login(client)
    r = client.post("/datasets/lab", data={"name": "Lab scan", "origin": "isolated lab", "authorisation_ref": "",
                                           "file": (io.BytesIO(FIXTURE.read_bytes()), "lab.csv")},
                    content_type="multipart/form-data", follow_redirects=True)
    assert b"authorisation reference is required" in r.data and Dataset.query.count() == 1  # E2
    client.post("/datasets/lab", data={"name": "Lab scan", "origin": "isolated lab", "authorisation_ref": "SUP-1",
                                       "file": (io.BytesIO(FIXTURE.read_bytes()), "lab.csv")},
                content_type="multipart/form-data")
    ds = Dataset.query.filter_by(name="Lab scan").one()
    assert ds.kind == "lab" and Path(ds.file_path).exists() and ds.authorisation_ref == "SUP-1"
    page = client.get("/simulator").get_data(as_text=True)
    assert "Lab scan" in page and f'value="{ds.id}:"' in page
    r = client.post("/simulator/start", data={"source": f"{ds.id}:", "speed": "100"}, follow_redirects=True)
    assert b"SIMULATED" in r.data
    run = SimulationRun.query.one()
    assert run.status == "Completed" and run.events_sent > 0 and run.speed == 100 and run.dataset_id == ds.id
    assert b"Last run summary" in r.data
    assert client.get(f"/simulator/runs/{run.id}").status_code == 200
    assert client.get(f"/simulator/runs/{run.id}/status").json["status"] == "Completed"
    assert client.post("/simulator/start", data={"source": f"{ds.id}:", "speed": "7"},
                       follow_redirects=True).data.count(b"1x, 10x or 100x") == 1
    # A6 delete lab dataset / E3 public dataset cannot be deleted
    pub = Dataset.query.filter_by(name="CIC-IDS2017").one()
    r = client.post(f"/datasets/{pub.id}/delete", follow_redirects=True)
    assert b"public dataset and cannot be deleted" in r.data
    client.post(f"/datasets/{ds.id}/delete")
    assert db.session.get(Dataset, ds.id) is None and not Path(ds.file_path).exists()


def test_uc02_one_replay_at_a_time_and_pause_resume_stop(client):
    _login(client)
    run = SimulationRun(dataset="CIC-IDS2017", file="x.csv", speed=10, status="Running")  # e.g. scripts/replay.py
    db.session.add(run)
    db.session.commit()
    r = client.post("/simulator/start", data={"source": "1:x", "speed": "10"}, follow_redirects=True)
    assert b"already in progress" in r.data  # E1
    client.post(f"/simulator/runs/{run.id}/pause")
    assert db.session.get(SimulationRun, run.id).status == "Paused"
    client.post(f"/simulator/runs/{run.id}/resume")
    assert db.session.get(SimulationRun, run.id).status == "Running"
    client.post(f"/simulator/runs/{run.id}/stop")
    assert db.session.get(SimulationRun, run.id).status == "Stopped"
    assert {"Replay paused", "Replay resumed", "Replay stopped"} <= set(_actions())


# ------------------------------------------------------------ UC-03 dashboard
def test_uc03_custom_range_and_layout(client):
    _login(client)
    ok = client.get("/api/summary?range=custom&from=2017-07-01T00:00&to=2017-07-08T00:00")
    assert ok.status_code == 200 and "incidents" in ok.json
    bad = client.get("/api/summary?range=custom&from=2017-01-01T00:00&to=2017-07-08T00:00")
    assert bad.status_code == 400 and "90 days" in bad.json["error"]  # E1
    from app.views import WIDGETS
    ids = list(WIDGETS)
    form = {"widget": ids, "show": [w for w in ids if w != "ports"]}
    form.update({f"pos_{w}": str(len(ids) - i) for i, w in enumerate(ids)})  # reverse order
    client.post("/dashboard/layout", data=form)
    page = client.get("/").get_data(as_text=True)
    assert 'id="c-ports"' not in page and page.index('data-widget="latest"') < page.index('data-widget="tiles"')
    form["pos_tiles"] = form["pos_latest"]  # duplicate position -> E3
    r = client.post("/dashboard/layout", data=form, follow_redirects=True)
    assert b"layout is not valid" in r.data
    client.post("/dashboard/layout/reset")
    page = client.get("/").get_data(as_text=True)
    assert 'id="c-ports"' in page and 'data-widget="model"' in page and 'data-widget="incidents"' in page
    assert {"Dashboard layout saved", "Dashboard layout reset"} <= set(_actions())


# ------------------------------------------------------------ UC-04 / UC-10 incidents
def test_uc04_uc10_incident_lifecycle(client):
    _login(client)
    a = _alert()  # Critical
    b = _alert(category="DoS / Flood")
    b.severity = "Medium"
    db.session.commit()
    page = client.get("/incidents").get_data(as_text=True)  # back-fills High/Critical alerts
    inc = Incident.query.one()
    assert IncidentAlert.query.filter_by(alert_id=a.id, incident_id=inc.id).one()
    assert f"Incident #{inc.id}" in page
    detail = client.get(f"/incidents/{inc.id}")  # Critical -> report generated automatically (A3)
    assert detail.status_code == 200
    _check_page(detail.get_data(as_text=True), "/incidents/id")
    rep = IncidentReport.query.filter_by(alert_id=a.id).one()
    assert rep.label == "Generated without AI" and b"Generated without AI" in detail.data  # E2 wording
    # E3 closing needs a note; E4 stale revision is refused
    r = client.post(f"/incidents/{inc.id}/status", data={"status": "Resolved", "note": "", "revision": inc.revision},
                    follow_redirects=True)
    assert b"Add a note" in r.data and db.session.get(Incident, inc.id).status == "New"
    r = client.post(f"/incidents/{inc.id}/status", data={"status": "Investigating", "revision": 99},
                    follow_redirects=True)
    assert b"changed by another administrator" in r.data
    client.post(f"/incidents/{inc.id}/status", data={"status": "Investigating", "revision": inc.revision})
    assert db.session.get(Incident, inc.id).status == "Investigating"
    # A6 merge the Medium alert in
    rev = db.session.get(Incident, inc.id).revision
    client.post(f"/incidents/{inc.id}/merge", data={"alert_ids": [str(b.id)], "revision": rev})
    assert IncidentAlert.query.filter_by(incident_id=inc.id).count() == 2
    # A5 edit report -> new version, original kept
    rev = db.session.get(Incident, inc.id).revision
    client.post(f"/incidents/{inc.id}/report/edit", data={
        "what_happened": "Analyst summary", "likely_impact": "x", "confidence": "High", "confidence_rationale": "y",
        "recommended_next_steps": "Block source\nCheck host", "unverified_claims": "", "revision": rev})
    reps = IncidentReport.query.filter_by(alert_id=a.id).order_by(IncidentReport.version).all()
    assert len(reps) == 2 and reps[0].content["what_happened"] != "Analyst summary"
    assert reps[1].generator.startswith("Edited by") and reps[1].content["recommended_next_steps"] == ["Block source", "Check host"]
    # A7 False Positive -> model failure cases
    rev = db.session.get(Incident, inc.id).revision
    client.post(f"/incidents/{inc.id}/status", data={"status": "False Positive", "note": "Scheduled scan",
                                                     "revision": rev})
    assert db.session.get(SecurityAlert, a.id).status == "Closed"
    # UC-10 filters + E1 empty result
    assert b"No incidents match these filters" in client.get("/incidents?status=New").data
    assert f"Incident #{inc.id}".encode() in client.get("/incidents?status=False+Positive&severity=Critical").data
    assert {"Incident status changed", "Incident alerts merged", "Incident report edited"} <= set(_actions())


def test_uc10_a2_open_incident_for_medium_alert(client):
    _login(client)
    a = _alert()
    a.severity = "Low"
    db.session.commit()
    page = client.get(f"/alerts/{a.id}").get_data(as_text=True)
    assert "Open incident for this alert" in page and "Detector · model version" in page and "rules_v1" in page
    r = client.post(f"/alerts/{a.id}/incident")
    inc = Incident.query.one()
    assert r.headers["Location"].endswith(f"/incidents/{inc.id}")
    assert IncidentReport.query.count() == 0  # Low: report only on request
    client.post(f"/incidents/{inc.id}/report")
    assert IncidentReport.query.count() == 1


# ------------------------------------------------------------ UC-05 notifications
def test_uc05_validation_and_concurrency(client):
    _login(client)
    page = client.get("/notifications").get_data(as_text=True)
    assert "Send test SMS" in page and "Channel" in page
    rev = settings.get("notification_revision")
    many = "\n".join(f"u{i}@example.com" for i in range(11))
    r = client.post("/notifications", data={"recipients": many, "min_severity": "High", "grouping": 10,
                                            "revision": rev}, follow_redirects=True)
    assert b"at most 10 recipients" in r.data  # E2
    r = client.post("/notifications", data={"recipients": "a@example.com", "min_severity": "High", "grouping": 3,
                                            "revision": rev}, follow_redirects=True)
    assert b"between 5 and 60" in r.data  # E3
    client.post("/notifications", data={"recipients": "a@example.com", "min_severity": "Critical", "grouping": 15,
                                        "revision": rev})
    assert settings.get("alert_min_severity") == "Critical"
    r = client.post("/notifications", data={"recipients": "b@example.com", "min_severity": "High", "grouping": 15,
                                            "revision": rev}, follow_redirects=True)  # stale revision
    assert b"Another administrator changed these settings" in r.data
    assert settings.get("alert_recipients") == ["a@example.com"]


# ------------------------------------------------------------ UC-06 models
def test_uc06_threshold_validation_and_rollback(client):
    _login(client)
    r = client.post("/settings/sensitivity", data={"threshold": "0.73"}, follow_redirects=True)
    assert b"steps of 0.05" in r.data  # E1
    client.post("/settings/sensitivity", data={"threshold": "0.85", "preset": "Low"})
    assert settings.get("sensitivity_threshold") == 0.85
    page = client.get("/models").get_data(as_text=True)
    assert 'data-preset="0.55"' in page and 'id="threshold-preview"' in page


# ------------------------------------------------------------ UC-08 data sources
def test_uc08_upload_errors_and_save_as_dataset(client):
    _login(client)
    r = client.post("/sources/upload/cicids2017", data={"file": (io.BytesIO(b"\x00\x01binary"), "x.csv")},
                    content_type="multipart/form-data")
    assert r.status_code == 400 and b"not a readable CSV" in r.data  # E1
    r = client.post("/sources/upload/cicids2017", data={"file": (io.BytesIO(b"a,b\n1,2\n"), "x.csv")},
                    content_type="multipart/form-data")
    assert r.status_code == 400 and b"missing required fields: Source IP" in r.data  # E2
    r = client.post("/sources/upload/pcap", data={"file": (io.BytesIO(b"not a capture"), "x.pcap")},
                    content_type="multipart/form-data")
    assert r.status_code == 400 and b"Capture file rejected" in r.data  # E5
    r = client.post("/sources/upload/cicids2017", data={
        "file": (io.BytesIO(FIXTURE.read_bytes()), "office.csv"), "save_dataset": "1", "ds_name": "Office export",
        "ds_origin": "Firewall", "ds_licence": "Internal"}, content_type="multipart/form-data", follow_redirects=True)
    assert b"records accepted" in r.data and b"Saved as replay dataset" in r.data  # main flow + A3
    assert Dataset.query.filter_by(name="Office export", kind="upload").one()
    page = client.get("/sources").get_data(as_text=True)
    for word in ("File upload", "Interval capture (.pcap)", "Error", "Active"):
        assert word in page


def test_uc08_a1_interval_capture_folder(client, app):
    _login(client)
    from app import pcap_watch
    inbox = pcap_watch.inbox()
    (inbox / "bad.pcap").write_bytes(b"garbage")
    good = Path(__file__).parent / "fixtures"
    caps = sorted(good.glob("*.pcap"))
    if caps:
        (inbox / "good.pcap").write_bytes(caps[0].read_bytes())
    r = client.post("/sources/pcap/scan", follow_redirects=True)
    assert b"Capture file rejected" in r.data and (inbox / "rejected" / "bad.pcap").exists()
    if caps:
        assert not (inbox / "good.pcap").exists()  # raw capture deleted after processing


# ------------------------------------------------------------ UC-11 audit
def test_uc11_audit_filters_empty_state(client):
    _login(client)
    r = client.get("/audit?action=zzz-no-such-action")
    assert b"No audit entries match these filters" in r.data
    assert client.get("/audit/export.csv?actor=ops").status_code == 200
