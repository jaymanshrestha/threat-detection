"""Password hashing (Argon2id), TOTP secret encryption and audit helper."""
import base64
import hashlib

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet
from flask import current_app, request

from .extensions import db
from .models import AuditLog

_ph = PasswordHasher()  # argon2-cffi defaults to Argon2id


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(stored: str, pw: str) -> bool:
    try:
        return _ph.verify(stored, pw)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _fernet() -> Fernet:
    key = current_app.config.get("TOTP_ENC_KEY")
    if not key:
        key = base64.urlsafe_b64encode(hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest())
    return Fernet(key)


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


def client_ip():
    try:
        return request.remote_addr
    except RuntimeError:
        return None


def audit(action: str, user=None, actor: str = None, commit=True, **details):
    """Append an audit entry. Never pass passwords, TOTP secrets or codes here."""
    entry = AuditLog(
        administrator_id=getattr(user, "id", None),
        actor=actor or getattr(user, "email", None) or "system",
        action=action,
        details=details or None,
        ip=client_ip(),
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry
