"""Administration: users, audit log, notification settings, sensitivity."""
import csv
import io
from datetime import datetime

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import DecimalField, IntegerField, SelectField, StringField, TextAreaField
from wtforms.validators import DataRequired, Length, NumberRange

from alerts import notifier, sms
from alerts.severity import SEVERITIES
from email_validator import EmailNotValidError, validate_email

from . import settings
from .extensions import db
from .models import Administrator, AuditLog, Notification
from .security import audit

bp = Blueprint("admin", __name__)


class NewUserForm(FlaskForm):
    email = StringField("Email address", validators=[DataRequired(), Length(max=255)])


def _check_email(raw, exclude_id=None):
    """UC-07 E1/E2. Returns (normalised_email, error)."""
    raw = (raw or "").strip()
    try:
        email = validate_email(raw, check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        return None, "Enter a valid email address, for example name@company.com."
    other = Administrator.query.filter_by(email=email).first()
    if other and other.id != exclude_id:
        return None, "An account with this email address already exists."
    return email, None


class NotificationForm(FlaskForm):
    recipients = TextAreaField("Recipients (one per line, max 10)")
    min_severity = SelectField("Minimum severity for email", choices=[(s, s) for s in SEVERITIES])
    grouping = IntegerField("Alert grouping window (minutes)", validators=[NumberRange(5, 60)])


class SensitivityForm(FlaskForm):
    threshold = DecimalField("Sensitivity threshold", places=2, validators=[NumberRange(0, 1)])


@bp.route("/users", methods=["GET", "POST"])
@login_required
def users():
    """UC-07: add an account by email; the person receives a single-use 24 h invitation."""
    from . import invitations
    form = NewUserForm()
    if request.method == "POST":
        email, err = _check_email(form.email.data if form.validate_on_submit() else request.form.get("email"))
        if err:
            flash(err, "danger")
            return render_template("users.html", users=_user_rows(), form=form, invite_state=invitations.state), 400
        user, inv, n = invitations.create_account(email, current_user)
        if n.status == "Failed":  # UC-07 E4
            flash(f"Account created for {email}, but the invitation was not delivered ({n.error}). "
                  "Use Resend invitation once email is working.", "warning")
        else:
            flash(f"Invitation sent to {email}. The link works once and expires in 24 hours.", "info")
        return redirect(url_for("admin.users"))
    return render_template("users.html", users=_user_rows(), form=form, invite_state=invitations.state)


def _user_rows():
    return Administrator.query.order_by(Administrator.id).all()


@bp.route("/users/<int:uid>/resend", methods=["POST"])
@login_required
def resend_invite(uid):
    """UC-07 A4: a new link replaces the old one, which stops working."""
    from . import invitations
    u = db.session.get(Administrator, uid)
    if not u or not u.invite_pending:
        flash("That account has no pending invitation.", "danger")
        return redirect(url_for("admin.users"))
    _, n = invitations.send(u, current_user)
    if n.status == "Failed":
        flash(f"The invitation to {u.email} was not delivered ({n.error}). Try again later.", "warning")
    else:
        flash(f"New invitation sent to {u.email}. The previous link no longer works.", "info")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:uid>/email", methods=["POST"])
@login_required
def change_email(uid):
    """UC-07 A1: change an account's email address (confirmed in the browser, audit-logged)."""
    u = db.session.get(Administrator, uid)
    if not u:
        return redirect(url_for("admin.users"))
    email, err = _check_email(request.form.get("email"), exclude_id=u.id)
    if err:
        flash(err, "danger")
        return redirect(url_for("admin.users"))
    if email != u.email:
        old, u.email = u.email, email
        db.session.commit()
        audit("User email changed", user=current_user, old=old, new=email)
        flash(f"Email changed from {old} to {email}.", "info")
        if u.invite_pending:
            from . import invitations
            invitations.send(u, current_user)
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:uid>/toggle", methods=["POST"])
@login_required
def toggle_user(uid):
    u = db.session.get(Administrator, uid)
    if not u:
        return redirect(url_for("admin.users"))
    if u.active:
        if u.id == current_user.id:
            flash("You cannot disable your own account.", "danger")
            return redirect(url_for("admin.users"))
        if Administrator.query.filter_by(active=True).count() <= 1:
            flash("You cannot disable the last active administrator.", "danger")
            return redirect(url_for("admin.users"))
    elif u.invite_pending:
        flash("This account has not accepted its invitation yet. Use Resend invitation instead.", "warning")
        return redirect(url_for("admin.users"))
    u.active = not u.active
    db.session.commit()
    audit("User " + ("enabled" if u.active else "disabled"), user=current_user, target=u.email)
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:uid>/reset-mfa", methods=["POST"])
@login_required
def reset_mfa(uid):
    u = db.session.get(Administrator, uid)
    if u and u.id != current_user.id:
        u.mfa_enabled, u.totp_secret_enc, u.last_totp_step = False, None, 0
        db.session.commit()
        audit("MFA reset", user=current_user, target=u.email)
        flash(f"MFA reset for {u.email}; they must re-enrol at next sign-in.", "info")
    return redirect(url_for("admin.users"))


def _audit_query():
    q = AuditLog.query
    if request.args.get("action"):
        q = q.filter(AuditLog.action.ilike(f"%{request.args['action']}%"))
    if request.args.get("actor"):
        q = q.filter(AuditLog.actor.ilike(f"%{request.args['actor']}%"))
    for arg, op in (("from", "__ge__"), ("to", "__le__")):
        if request.args.get(arg):
            try:
                d = datetime.fromisoformat(request.args[arg])
                if arg == "to" and len(request.args[arg]) == 10:
                    d = d.replace(hour=23, minute=59, second=59)
                q = q.filter(getattr(AuditLog.created_at, op)(d))
            except ValueError:
                pass
    return q.order_by(AuditLog.id.desc())


@bp.route("/audit")
@login_required
def audit_log():
    page = max(int(request.args.get("page", 1)), 1)
    pg = _audit_query().paginate(page=page, per_page=100, error_out=False)
    return render_template("audit.html", page=pg, args=request.args)


@bp.route("/audit/export.csv")
@login_required
def audit_export():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_at", "actor", "action", "details", "ip"])
    for e in _audit_query().all():
        w.writerow([e.id, e.created_at, e.actor, e.action, e.details, e.ip])
    audit("Audit log exported", user=current_user)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit_log.csv"})


@bp.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    """UC-05 main flow, A3 cancel, A4 log; E1-E3 validation, E7 concurrent change."""
    form = NotificationForm()
    rev = settings.get("notification_revision")
    if request.method == "POST":
        if str(request.form.get("revision", "")) != str(rev):
            flash("Another administrator changed these settings while you were editing. Your changes were not "
                  "saved - the latest settings are shown.", "warning")
            return redirect(url_for("admin.notifications"))
        if not form.validate_on_submit():
            if form.grouping.errors:
                flash("The alert grouping window must be a whole number of minutes between 5 and 60.", "danger")
            else:
                flash("Check the highlighted settings: " + "; ".join(e for v in form.errors.values() for e in v), "danger")
            return redirect(url_for("admin.notifications"))
        recips = [r.strip() for r in (form.recipients.data or "").replace(",", "\n").splitlines() if r.strip()]
        clean = []
        for r in recips:
            try:
                clean.append(validate_email(r, check_deliverability=False).normalized)
            except EmailNotValidError:
                flash(f"Invalid recipient address: {r[:80]}. Settings were not saved.", "danger")
                return redirect(url_for("admin.notifications"))
        if len(clean) > 10:
            flash(f"You can add at most 10 recipients ({len(clean)} entered). Settings were not saved.", "danger")
            return redirect(url_for("admin.notifications"))
        old = {k: settings.get(k) for k in ("alert_recipients", "alert_min_severity", "grouping_minutes")}
        settings.put("alert_recipients", clean)
        settings.put("alert_min_severity", form.min_severity.data)
        settings.put("grouping_minutes", int(form.grouping.data))
        settings.put("notification_revision", int(rev or 0) + 1)
        audit("Notification settings changed", user=current_user, old=old,
              new={"alert_recipients": clean, "alert_min_severity": form.min_severity.data,
                   "grouping_minutes": int(form.grouping.data)})
        flash("Notification settings saved.", "info")
        return redirect(url_for("admin.notifications"))
    form.recipients.data = "\n".join(settings.get("alert_recipients"))
    form.min_severity.data = settings.get("alert_min_severity")
    form.grouping.data = settings.get("grouping_minutes")
    log = Notification.query.order_by(Notification.id.desc()).limit(100).all()
    return render_template("notifications.html", form=form, log=log, ip_mode=settings.get("ip_display_mode"),
                           llm_ip_mode=settings.get("llm_ip_mode"), revision=rev, sms_info=_sms_info())


def _sms_info():
    """What the SMS card shows. Credentials are never passed to the template - only whether they are set."""
    from flask import current_app
    cfg = current_app.config
    mode, why = sms.transport(cfg)
    return {"enabled": settings.get("sms_enabled"), "numbers": settings.get("sms_recipients"),
            "min_severity": settings.get("sms_min_severity"), "mode": mode, "why": why,
            "from_number": cfg.get("TWILIO_FROM_NUMBER") if mode == "twilio" else None,
            "credentials": {k: bool(cfg.get(k)) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER")},
            "max_numbers": cfg["SMS_MAX_RECIPIENTS"], "per_alert": cfg["SMS_PER_ALERT_MINUTES"],
            "per_hour": cfg["SMS_MAX_PER_HOUR"]}


def parse_numbers(raw, limit):
    """UC-05 A2 / E5. Returns (numbers, error)."""
    items = [x.strip() for x in (raw or "").replace(";", ",").replace("\n", ",").split(",") if x.strip()]
    clean = []
    for x in items:
        n = sms.normalise(x)
        if not n:
            return None, (f"Invalid mobile number: {x[:40]}. Use international (E.164) format, for example "
                          "+61412345678. SMS settings were not saved.")
        if n not in clean:
            clean.append(n)
    if len(clean) > limit:
        return None, f"You can add at most {limit} mobile numbers ({len(clean)} entered). SMS settings were not saved."
    return clean, None


@bp.route("/notifications/sms", methods=["POST"])
@login_required
def sms_settings():
    """FR-10 / UC-05 A2: SMS on/off, mobile numbers and minimum severity (credentials stay in .env)."""
    from flask import current_app
    rev = settings.get("notification_revision")
    if str(request.form.get("revision", "")) != str(rev):  # UC-05 E7
        flash("Another administrator changed these settings while you were editing. Your changes were not "
              "saved - the latest settings are shown.", "warning")
        return redirect(url_for("admin.notifications"))
    numbers, err = parse_numbers(request.form.get("sms_numbers"), current_app.config["SMS_MAX_RECIPIENTS"])
    if err:
        flash(err, "danger")
        return redirect(url_for("admin.notifications"))
    enabled = request.form.get("sms_enabled") == "on"
    sev = request.form.get("sms_min_severity", "Critical")
    if sev not in ("Critical", "High"):
        flash("SMS minimum severity must be Critical or High. SMS settings were not saved.", "danger")
        return redirect(url_for("admin.notifications"))
    if enabled and not numbers:
        flash("Add at least one mobile number before turning SMS alerts on. SMS settings were not saved.", "danger")
        return redirect(url_for("admin.notifications"))
    old = {k: settings.get(k) for k in ("sms_enabled", "sms_recipients", "sms_min_severity")}
    settings.put("sms_enabled", enabled)
    settings.put("sms_recipients", numbers)
    settings.put("sms_min_severity", sev)
    settings.put("notification_revision", int(rev or 0) + 1)
    audit("SMS settings changed", user=current_user, old=old,
          new={"sms_enabled": enabled, "sms_recipients": numbers, "sms_min_severity": sev})
    flash("SMS settings saved." + ("" if enabled else " SMS alerts are off."), "info")
    return redirect(url_for("admin.notifications"))


@bp.route("/notifications/test-sms", methods=["POST"])
@login_required
def test_sms():
    """UC-05 A2: send a test SMS and show whether it was delivered; E6 records a failure (email unaffected)."""
    if not settings.get("sms_recipients"):
        flash("Save at least one mobile number before sending a test SMS.", "danger")
        return redirect(url_for("admin.notifications"))
    n = notifier.send_test_sms(current_user)
    if n.status == "Failed":
        flash(f"Test SMS not delivered: {n.error or 'unknown error'}. The failure is recorded in the notification log; "
              "email alerts are not affected.", "danger")
    elif n.status == "Partial":
        flash(f"Test SMS delivered to some numbers only: {n.error}.", "warning")
    elif n.status == "Outbox":
        flash(f"Test SMS written to the SMS outbox (demo mode) for {n.recipients}. Configure Twilio in .env to send real SMS.", "info")
    else:
        flash(f"Test SMS delivered to {n.recipients} through Twilio.", "info")
    return redirect(url_for("admin.notifications"))


@bp.route("/notifications/test", methods=["POST"])
@login_required
def test_email():
    n = notifier.send_test_email(current_user)
    if n.status == "Failed":
        flash(f"Test email failed: {n.error or 'unknown error'}. Check the mail server settings.", "danger")
    else:
        flash(f"Test email delivered ({n.status}) to {n.recipients}.", "info")
    return redirect(url_for("admin.notifications"))


@bp.route("/notifications/<int:nid>")
@login_required
def notification_detail(nid):
    n = db.session.get(Notification, nid)
    return render_template("notification_detail.html", n=n)


@bp.route("/settings/sensitivity", methods=["POST"])
@login_required
def sensitivity():
    """UC-06 A2 (slider / presets, previewed in the browser) and E1 (invalid threshold)."""
    raw = (request.form.get("threshold") or "").strip()
    try:
        val = float(raw)
    except ValueError:
        val = -1.0
    steps = round(val / 0.05)
    if not 0 <= val <= 1 or abs(steps * 0.05 - val) > 1e-6:
        flash("The threshold must be between 0 and 1 in steps of 0.05. The current setting was kept.", "danger")
        return redirect(url_for("dash.models"))
    val = round(steps * 0.05, 2)
    old = settings.get("sensitivity_threshold")
    settings.put("sensitivity_threshold", val)
    audit("Sensitivity changed", user=current_user, old=old, new=val, preset=request.form.get("preset") or None)
    flash(f"Sensitivity threshold set to {val:.2f} (applies to new traffic only).", "info")
    return redirect(url_for("dash.models"))


def _evaluated(choice):
    from .views import _metrics
    m = _metrics() or {}
    return bool((m.get("results") or {}).get(choice, {}).get("test"))


@bp.route("/settings/model", methods=["POST"])
@login_required
def active_model():
    """UC-06 A4: activate a model version (confirmed in the browser) or roll back; E2 not evaluated."""
    from .pipeline import available_models
    rollback = request.form.get("rollback") == "1"
    choice = settings.get("previous_active_model") if rollback else request.form.get("active_model", "")
    if not choice or choice not in available_models():
        flash("That model is not available (train it first with python scripts/train_and_evaluate.py).", "danger")
        return redirect(url_for("dash.models"))
    if not _evaluated(choice):
        flash("This model version has not been evaluated on the test days yet, so it cannot be activated.", "danger")
        return redirect(url_for("dash.models"))
    old = settings.get("active_model")
    if choice == old:
        flash("That model is already active.", "info")
        return redirect(url_for("dash.models"))
    settings.put("active_model", choice)
    settings.put("previous_active_model", old)
    audit("Active model rolled back" if rollback else "Active model changed", user=current_user, old=old, new=choice)
    flash(f"Active model set to {choice}{' (rolled back)' if rollback else ''}. Applies to new traffic only; "
          "the rule baseline always runs.", "info")
    return redirect(url_for("dash.models"))


@bp.route("/settings/privacy", methods=["POST"])
@login_required
def privacy():
    from .privacy import MODES
    disp, llm = request.form.get("ip_display_mode"), request.form.get("llm_ip_mode")
    if disp not in MODES or llm not in ("hash", "truncate"):
        flash("Invalid privacy setting.", "danger")
        return redirect(url_for("admin.notifications"))
    old = {"ip_display_mode": settings.get("ip_display_mode"), "llm_ip_mode": settings.get("llm_ip_mode")}
    settings.put("ip_display_mode", disp)
    settings.put("llm_ip_mode", llm)
    audit("Privacy settings changed", user=current_user, old=old, new={"ip_display_mode": disp, "llm_ip_mode": llm})
    flash("Privacy settings saved.", "info")
    return redirect(url_for("admin.notifications"))


@bp.route("/style-guide")
@login_required
def style_guide():
    """Living style guide: palette with measured contrast, type scale and every shared component."""
    from . import design_tokens as dt
    icons = ["shield", "overview", "flag", "bell", "globe", "brain", "upload", "database", "mail", "users", "list",
             "activity", "alert", "zap", "radar", "layers", "play", "flame", "sun", "moon", "logout", "menu", "lock",
             "key", "file", "clock", "sparkles", "palette"]
    themes = {t: {"palette": dt.palette(t), "audit": dt.audit_before_after(t)} for t in dt.THEMES}
    return render_template("style_guide.html", themes=themes, type_scale=dt.TYPE_SCALE, icons=icons,
                           severities=SEVERITIES)
