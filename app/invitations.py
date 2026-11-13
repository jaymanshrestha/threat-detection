"""Account invitations (UC-07 main flow + A4, UC-01 A3).

An invitation is a single-use link valid for 24 hours. Only the SHA-256 of the token is stored,
so a database leak does not reveal usable links. Sending a new invitation revokes the old one."""
import hashlib
import secrets
from datetime import datetime, timedelta

from flask import current_app

from alerts.emailer import deliver

from .extensions import db
from .models import Administrator, Invitation, Notification
from .security import audit, hash_password

VALID_HOURS = 24


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def latest(user):
    return Invitation.query.filter_by(administrator_id=user.id).order_by(Invitation.id.desc()).first()


def state(user):
    """Account status shown on the Users page."""
    if user.invite_pending:
        inv = latest(user)
        if inv and not inv.revoked and not inv.used_at and inv.expires_at > datetime.now():
            return "Invited"
        return "Invitation expired"
    return "Active" if user.active else "Disabled"


def send(user, by=None):
    """Revoke any earlier link, create a new one and email it. Returns (invitation, notification)."""
    Invitation.query.filter_by(administrator_id=user.id, used_at=None, revoked=False).update({"revoked": True})
    token = secrets.token_urlsafe(32)
    inv = Invitation(administrator_id=user.id, token_hash=_h(token), created_by=getattr(by, "id", None),
                     expires_at=datetime.now() + timedelta(hours=VALID_HOURS))
    db.session.add(inv)
    cfg = current_app.config
    link = f"{cfg['PUBLIC_BASE_URL'].rstrip('/')}/invite/{token}"
    subject = "You have been invited to the SMB Threat Dashboard"
    body = (f"An administrator ({getattr(by, 'email', 'system')}) created an account for {user.email}.\n\n"
            f"Open this link to set your password and enrol your authenticator app:\n{link}\n\n"
            f"The link works once and expires in {VALID_HOURS} hours. If you did not expect this email, ignore it.")
    status, attempts, err = deliver(cfg, [user.email], subject, body, retries=1 if cfg.get("TESTING") else 3)
    n = Notification(kind="invitation", recipients=user.email, subject=subject, body=body.replace(token, "<token>"),
                     status=status, attempts=attempts, error=err,
                     sent_at=datetime.now() if status != "Failed" else None)
    db.session.add(n)
    db.session.flush()
    inv.notification_id = n.id
    db.session.commit()
    audit("Invitation sent" if status != "Failed" else "Invitation not delivered", user=by,
          target=user.email, status=status, expires_at=inv.expires_at.isoformat(timespec="minutes"))
    return inv, n


def create_account(email, by):
    """UC-07 main flow: account created from an email address only; no usable password until accepted."""
    user = Administrator(email=email, password_hash=hash_password(secrets.token_urlsafe(48)),
                         active=False, invite_pending=True)
    db.session.add(user)
    db.session.commit()
    audit("User invited", user=by, target=email)
    return user, *send(user, by)


def lookup(token):
    inv = Invitation.query.filter_by(token_hash=_h(token or "")).first()
    if not inv or inv.revoked or inv.used_at or inv.expires_at <= datetime.now():
        return None, None
    user = db.session.get(Administrator, inv.administrator_id)
    if not user or not user.invite_pending:
        return None, None
    return inv, user


def complete(user):
    inv = Invitation.query.filter_by(administrator_id=user.id, used_at=None, revoked=False).order_by(
        Invitation.id.desc()).first()
    if inv:
        inv.used_at = datetime.now()
    user.invite_pending = False
    user.active = True
