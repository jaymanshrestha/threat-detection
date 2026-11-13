"""Administrator login: email + password (Argon2id) -> short-lived MFA challenge
-> TOTP (pyotp). First login forces authenticator enrolment (QR code)."""
import base64
import io
import secrets
import time
from datetime import datetime, timedelta

import pyotp
import qrcode
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Regexp

from .extensions import db
from .models import Administrator, LoginAttempt, MfaChallenge
from .security import audit, client_ip, decrypt_secret, encrypt_secret, hash_password, verify_password

bp = Blueprint("auth", __name__)
GENERIC_ERROR = "Invalid email or password."
ISSUER = "SMB Threat Dashboard"


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])


class SetPasswordForm(FlaskForm):
    password = PasswordField("New password (min 12 characters)", validators=[DataRequired(), Length(min=12, max=256)])
    confirm = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password", message="Passwords do not match")])


INVITE_INVALID = ("This invitation has expired or has already been used. "
                  "Ask an administrator to send a new invitation.")


def safe_next(target):
    """Only same-site relative paths are allowed as post-login destinations (no open redirect)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    if target.startswith(("/login", "/mfa", "/logout", "/invite", "/api/")):
        return None
    return target.rstrip("?") or None


class CodeForm(FlaskForm):
    code = StringField("6-digit code", validators=[DataRequired(), Regexp(r"^\d{6}$", message="Enter 6 digits")])


# ------------------------------------------------------------- helpers ----
def _recent_failures(email: str) -> int:
    since = datetime.now() - timedelta(minutes=current_app.config["LOCKOUT_WINDOW_MINUTES"])
    return LoginAttempt.query.filter(
        LoginAttempt.email == email, LoginAttempt.success.is_(False), LoginAttempt.created_at >= since
    ).count()


def _ip_failures() -> int:
    since = datetime.now() - timedelta(minutes=current_app.config["LOCKOUT_WINDOW_MINUTES"])
    return LoginAttempt.query.filter(
        LoginAttempt.ip == client_ip(), LoginAttempt.success.is_(False), LoginAttempt.created_at >= since
    ).count()


def _record_failure(email, user, stage):
    db.session.add(LoginAttempt(email=email, administrator_id=getattr(user, "id", None),
                                ip=client_ip(), stage=stage, success=False))
    db.session.commit()
    audit("Login failed" if stage == "password" else "MFA failed", user=user, actor=email, stage=stage)
    if user and _recent_failures(email) >= current_app.config["LOCKOUT_THRESHOLD"]:
        user.locked_until = datetime.now() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
        db.session.commit()
        audit("Account locked", user=user, minutes=current_app.config["LOCKOUT_MINUTES"])


def _is_locked(user) -> bool:
    return bool(user and user.locked_until and user.locked_until > datetime.now())


def _cleanup_challenges():
    MfaChallenge.query.filter(MfaChallenge.expires_at < datetime.now()).delete()
    db.session.commit()


def _current_challenge():
    token = session.get("mfa_token")
    if not token:
        return None
    ch = MfaChallenge.query.filter_by(token=token).first()
    if not ch or ch.expires_at < datetime.now():
        if ch:
            db.session.delete(ch)
            db.session.commit()
        session.pop("mfa_token", None)
        return None
    return ch


def verify_totp(user, secret: str, code: str) -> bool:
    """Accept the current or adjacent 30 s step only; reject a step that was
    already used successfully (replay protection)."""
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // 30
    for step in (now_step - 1, now_step, now_step + 1):
        if secrets.compare_digest(totp.at(step * 30), code):
            if step <= (user.last_totp_step or 0):
                return False
            user.last_totp_step = step
            return True
    return False


def _finish_login(user, ch):
    """Completes sign-in and returns where to go next (UC-01 A1: the alert link that was opened)."""
    nxt = safe_next(session.get("next"))
    db.session.delete(ch)
    session.pop("mfa_token", None)
    user.locked_until = None
    user.last_login_at = datetime.now()
    db.session.add(LoginAttempt(email=user.email, administrator_id=user.id, ip=client_ip(), stage="mfa", success=True))
    db.session.commit()
    session.clear()
    session.permanent = True
    login_user(user, remember=False)
    session["last_activity"] = time.time()
    audit("Login success", user=user)
    return nxt or url_for("dash.overview")


def qr_data_uri(uri: str, force_svg: bool = False) -> str:
    """PNG via Pillow when available, otherwise a pure-Python SVG (no compiled dependency)."""
    if not force_svg:
        try:
            import PIL  # noqa: F401
            img = qrcode.make(uri)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
        except ImportError:
            pass
    from qrcode.image.svg import SvgPathFillImage
    img = qrcode.make(uri, image_factory=SvgPathFillImage, box_size=10)
    buf = io.BytesIO()
    img.save(buf)
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()


# -------------------------------------------------------------- routes ----
@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(safe_next(request.args.get("next")) or url_for("dash.overview"))
    if request.method == "GET" and safe_next(request.args.get("next")):
        session["next"] = safe_next(request.args.get("next"))
    form = LoginForm()
    if request.method == "POST":
        if _ip_failures() >= 4 * current_app.config["LOCKOUT_THRESHOLD"]:
            audit("Login rate limited", actor=request.form.get("email", "")[:255])
            return render_template("login.html", form=form, error="Too many attempts. Try again later."), 429
        if not form.validate_on_submit():
            return render_template("login.html", form=form, error="Enter a valid email and password."), 400
        email = form.email.data.strip().lower()
        user = Administrator.query.filter_by(email=email).first()
        if _is_locked(user):
            audit("Login blocked (locked)", user=user, actor=email)
            return render_template("login.html", form=form,
                                   error="This account is temporarily locked. Try again later."), 401
        if not user or not user.active or not verify_password(user.password_hash, form.password.data):
            _record_failure(email, user, "password")
            msg = GENERIC_ERROR
            if _is_locked(user):
                msg = "Too many failed attempts. This account is temporarily locked."
            return render_template("login.html", form=form, error=msg), 401
        _cleanup_challenges()
        ch = MfaChallenge(
            token=secrets.token_urlsafe(32), administrator_id=user.id,
            purpose="verify" if user.mfa_enabled else "enrol",
            expires_at=datetime.now() + timedelta(seconds=current_app.config["MFA_CHALLENGE_SECONDS"]),
        )
        if not user.mfa_enabled:
            ch.pending_secret_enc = encrypt_secret(pyotp.random_base32())
        db.session.add(ch)
        db.session.add(LoginAttempt(email=email, administrator_id=user.id, ip=client_ip(), stage="password", success=True))
        db.session.commit()
        session["mfa_token"] = ch.token
        audit("Password verified, MFA challenge issued", user=user)
        return redirect(url_for("auth.mfa_enrol" if ch.purpose == "enrol" else "auth.mfa"))
    return render_template("login.html", form=form, error=None)


@bp.route("/mfa", methods=["GET", "POST"])
def mfa():
    ch = _current_challenge()
    if not ch or ch.purpose != "verify":
        flash("Your sign-in session expired. Please sign in again.", "warning")
        return redirect(url_for("auth.login"))
    user = db.session.get(Administrator, ch.administrator_id)
    form = CodeForm()
    if request.method == "POST":
        if _is_locked(user):
            return render_template("mfa.html", form=form, error="This account is temporarily locked."), 401
        if form.validate_on_submit() and verify_totp(user, decrypt_secret(user.totp_secret_enc), form.code.data):
            return redirect(_finish_login(user, ch))
        _record_failure(user.email, user, "mfa")
        return render_template("mfa.html", form=form, error="Invalid or expired code."), 401
    return render_template("mfa.html", form=form, error=None, expires=ch.expires_at)


@bp.route("/mfa/enrol", methods=["GET", "POST"])
def mfa_enrol():
    ch = _current_challenge()
    if not ch or ch.purpose not in ("enrol", "invite"):
        flash("Your sign-in session expired. Please sign in again.", "warning")
        return redirect(url_for("auth.login"))
    user = db.session.get(Administrator, ch.administrator_id)
    secret = decrypt_secret(ch.pending_secret_enc)
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=ISSUER)
    form = CodeForm()
    if request.method == "POST":
        if form.validate_on_submit() and verify_totp(user, secret, form.code.data):
            user.totp_secret_enc = ch.pending_secret_enc
            user.mfa_enabled = True
            if ch.purpose == "invite":  # UC-01 A3: activate the invited account, then sign in normally
                from .invitations import complete
                complete(user)
                db.session.delete(ch)
                session.pop("mfa_token", None)
                db.session.commit()
                audit("Invitation accepted, MFA enrolled, account activated", user=user)
                flash("Your account is active. Sign in with your new password and authenticator code.", "info")
                return redirect(url_for("auth.login"))
            db.session.commit()
            audit("MFA enrolled", user=user)
            return redirect(_finish_login(user, ch))
        _record_failure(user.email, user, "mfa")
        return render_template("mfa_enrol.html", form=form, qr=qr_data_uri(uri), secret=secret, invite=ch.purpose == "invite",
                               error="Invalid code - check your authenticator app's clock."), 401
    return render_template("mfa_enrol.html", form=form, qr=qr_data_uri(uri), secret=secret, error=None,
                           invite=ch.purpose == "invite")


@bp.route("/invite/<token>", methods=["GET", "POST"])
def accept_invite(token):
    """UC-01 A3: first sign-in from an invitation - set a password, then enrol the authenticator."""
    from .invitations import lookup
    inv, user = lookup(token)
    if not inv:
        audit("Invitation link rejected", actor="anonymous", reason="expired, used or unknown")
        return render_template("invite.html", form=None, error=INVITE_INVALID), 410
    form = SetPasswordForm()
    if request.method == "POST":
        if not form.validate_on_submit():
            msg = next(iter(form.errors.values()))[0] if form.errors else "Check the form."
            return render_template("invite.html", form=form, email=user.email, error=msg), 400
        user.password_hash = hash_password(form.password.data)
        _cleanup_challenges()
        ch = MfaChallenge(token=secrets.token_urlsafe(32), administrator_id=user.id, purpose="invite",
                          pending_secret_enc=encrypt_secret(pyotp.random_base32()),
                          expires_at=datetime.now() + timedelta(seconds=max(
                              300, current_app.config["MFA_CHALLENGE_SECONDS"])))
        db.session.add(ch)
        db.session.commit()
        session["mfa_token"] = ch.token
        audit("Invitation password set", user=user)
        return redirect(url_for("auth.mfa_enrol"))
    return render_template("invite.html", form=form, email=user.email, error=None)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("Logout", user=current_user)
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
