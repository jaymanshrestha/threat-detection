"""Login + MFA flow, lockout, TOTP replay protection, audit trail."""
import re
import time

import pyotp

from app.extensions import db
from app.models import Administrator, AuditLog
from app.security import hash_password

EMAIL, PW = "admin@example.com", "correct horse battery"


def _make_admin():
    db.session.add(Administrator(email=EMAIL, password_hash=hash_password(PW)))
    db.session.commit()


def _enrol(client):
    r = client.post("/login", data={"email": EMAIL, "password": PW})
    assert r.status_code == 302 and r.headers["Location"].endswith("/mfa/enrol")
    page = client.get("/mfa/enrol").get_data(as_text=True)
    assert "data:image/png;base64," in page or "data:image/svg+xml;base64," in page  # SVG if Pillow is absent
    secret = re.search(r"<code>([A-Z2-7]+)</code>", page).group(1)
    r = client.post("/mfa/enrol", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    return secret


def test_requires_login(client):
    assert client.get("/").status_code == 302
    assert client.get("/api/summary").status_code == 401


def test_full_enrol_and_mfa_login(client, app):
    _make_admin()
    secret = _enrol(client)
    assert client.get("/").status_code == 200
    u = Administrator.query.filter_by(email=EMAIL).first()
    assert u.mfa_enabled and u.totp_secret_enc and secret not in u.totp_secret_enc  # encrypted at rest
    assert u.password_hash.startswith("$argon2id$")
    client.post("/logout")
    assert client.get("/").status_code == 302
    # second login: password then TOTP (next time-step, previous one was consumed)
    r = client.post("/login", data={"email": EMAIL, "password": PW})
    assert r.headers["Location"].endswith("/mfa")
    u.last_totp_step = 0; db.session.commit()
    r = client.post("/mfa", data={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 302
    assert client.get("/models").status_code == 200
    actions = [a.action for a in AuditLog.query.all()]
    assert "MFA enrolled" in actions and actions.count("Login success") == 2


def test_wrong_totp_does_not_authenticate_and_replay_rejected(client):
    _make_admin()
    secret = _enrol(client)
    client.post("/logout")
    client.post("/login", data={"email": EMAIL, "password": PW})
    assert client.post("/mfa", data={"code": "000000"}).status_code == 401
    # the code used during enrolment (same time step) must not be accepted again
    assert client.post("/mfa", data={"code": pyotp.TOTP(secret).now()}).status_code == 401
    assert client.get("/").status_code == 302


def test_mfa_challenge_expires(client, app):
    _make_admin()
    _enrol(client)
    client.post("/logout")
    app.config["MFA_CHALLENGE_SECONDS"] = -1
    client.post("/login", data={"email": EMAIL, "password": PW})
    r = client.get("/mfa")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_generic_error_and_lockout(client):
    _make_admin()
    for _ in range(5):
        r = client.post("/login", data={"email": EMAIL, "password": "wrong-password!"})
        assert r.status_code == 401
    assert "temporarily locked" in r.get_data(as_text=True)
    # even the right password is refused while locked
    r = client.post("/login", data={"email": EMAIL, "password": PW})
    assert r.status_code == 401 and "locked" in r.get_data(as_text=True)
    r = client.post("/login", data={"email": "nobody@example.com", "password": "x"})
    assert "Invalid email or password." in r.get_data(as_text=True)
    actions = [a.action for a in AuditLog.query.all()]
    assert actions.count("Login failed") >= 5 and "Account locked" in actions


def test_audit_log_is_append_only(app):
    from app.security import audit
    e = audit("Test event", actor="pytest")
    e.action = "tampered"
    try:
        db.session.commit()
        assert False, "update should be rejected"
    except PermissionError:
        db.session.rollback()


def test_qr_svg_fallback_without_pillow():
    from app.auth import qr_data_uri
    uri = qr_data_uri("otpauth://totp/Threat:ops@example.com?secret=JBSWY3DPEHPK3PXP", force_svg=True)
    assert uri.startswith("data:image/svg+xml;base64,")
