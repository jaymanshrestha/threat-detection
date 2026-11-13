"""Alert -> email policy with de-duplication-aware throttling (FR-07, FR-08).

* Critical alerts: email immediately.
* High alerts: collected into a periodic summary (digest, default hourly).
* Max one email per alert every EMAIL_PER_ALERT_MINUTES unless severity rises.
* Max EMAIL_MAX_PER_HOUR emails overall; extra alerts roll into the next summary.
* Suppressed emails are recorded (status 'Suppressed') for review.
* Emails contain alert facts only - never raw log content.
* SMS (FR-10, UC-09 A4): alerts at or above the SMS minimum severity (default Critical) also get a short
  SMS - severity, category, time and a link only (no IP addresses) - with the same rules: one per alert
  every SMS_PER_ALERT_MINUTES unless severity rises, at most SMS_MAX_PER_HOUR. SMS problems are
  recorded but never affect email (UC-05 E6, UC-09 E2).
Detection only *queues* notifications; delivery happens in process_queue(), so
mail failures can never interrupt detection."""
from datetime import datetime, timedelta

from flask import current_app
from sqlalchemy import or_

from app import settings
from app.extensions import db
from app.models import Notification, SecurityAlert
from app.security import audit

from . import sms
from .emailer import deliver
from .severity import RANK, at_least


def _cfg():
    return current_app.config


def _recipients():
    return settings.get("alert_recipients")


EMAIL = or_(Notification.channel.is_(None), Notification.channel != "SMS")


def _sent_last_hour(channel_filter=EMAIL):
    since = datetime.now() - timedelta(hours=1)
    return Notification.query.filter(channel_filter, Notification.created_at >= since,
                                     Notification.status.in_(["Queued", "Sent", "Outbox", "Partial"])).count()


def sms_recipients():
    return settings.get("sms_recipients") if settings.get("sms_enabled") else []


def _fmt_alert(a: SecurityAlert) -> str:
    feats = ", ".join(f["feature"] for f in (a.top_features or [])[:3]) or "n/a"
    sim = " [SIMULATED replay]" if a.is_simulated else ""
    return (f"Severity: {a.severity}{sim}\nCategory: {a.category}\n"
            f"Source -> destination: {a.src_ip} -> {a.dst_ip}\n"
            f"Occurrences: {a.occurrence_count:,}\nFirst seen: {a.first_seen}\nLast seen: {a.last_seen}\n"
            f"Max risk score: {a.max_risk:.2f} (0-1 scale, not a probability)\n"
            f"Top contributing features: {feats}\n"
            f"Details: {_cfg()['PUBLIC_BASE_URL']}/alerts/{a.id}\n")


def _queue(kind, subject, body, alert=None, status="Queued", reason=None):
    n = Notification(alert_id=getattr(alert, "id", None), kind=kind, recipients=", ".join(_recipients()),
                     subject=subject, body=body, status=status, reason=reason)
    db.session.add(n)
    return n


def sms_text(alert: SecurityAlert) -> str:
    """UC-09 A4: severity, category and time only, plus a link - never IP addresses or log content."""
    when = (alert.last_seen or datetime.now()).strftime("%H:%M %d/%m")
    sim = " SIMULATED" if alert.is_simulated else ""
    tail = f" at {when}. Alert #{alert.id}: {_cfg()['PUBLIC_BASE_URL'].rstrip('/')}/alerts/{alert.id}"
    head = f"[{alert.severity.upper()}{sim}] "
    room = sms.MAX_LEN - len(head) - len(tail)
    cat = alert.category or "Threat"
    if len(cat) > room:
        cat = cat[: max(room - 3, 8)].rstrip() + "..."
    return sms.fit(head + cat + tail)


def _queue_sms(kind, body, alert=None, status="Queued", reason=None, recipients=None):
    n = Notification(alert_id=getattr(alert, "id", None), channel="SMS", kind=kind,
                     recipients=", ".join(recipients if recipients is not None else sms_recipients()),
                     subject=(body or f"[{getattr(alert, 'severity', '').upper()}] {getattr(alert, 'category', '')}")[:120],
                     body=body, status=status, reason=reason)
    db.session.add(n)
    return n


def on_alert_sms(alert: SecurityAlert):
    """FR-10 / UC-09 A4 - same de-duplication and throttling rules as email (FR-08)."""
    if not sms_recipients() or not at_least(alert.severity, settings.get("sms_min_severity")):
        return
    cfg = _cfg()
    throttle = timedelta(minutes=cfg["SMS_PER_ALERT_MINUTES"])
    recently = alert.last_sms_at and datetime.now() - alert.last_sms_at < throttle
    rose = alert.last_sms_severity and RANK[alert.severity] > RANK[alert.last_sms_severity]
    is_sms = Notification.channel == "SMS"
    if recently and not rose:
        exists = Notification.query.filter(is_sms, Notification.alert_id == alert.id, Notification.status == "Suppressed",
                                           Notification.created_at >= alert.last_sms_at).first()
        if not exists:
            _queue_sms("immediate", "", alert, status="Suppressed",
                       reason=f"per-alert SMS throttle ({cfg['SMS_PER_ALERT_MINUTES']} min)")
        return
    if _sent_last_hour(is_sms) >= cfg["SMS_MAX_PER_HOUR"]:
        since = datetime.now() - timedelta(hours=1)
        exists = Notification.query.filter(is_sms, Notification.alert_id == alert.id, Notification.status == "Suppressed",
                                           Notification.created_at >= since).first()
        if not exists:
            _queue_sms("immediate", "", alert, status="Suppressed",
                       reason=f"SMS limit {cfg['SMS_MAX_PER_HOUR']}/hour reached - see email and dashboard")
        return
    _queue_sms("immediate", sms_text(alert), alert)
    alert.last_sms_at = datetime.now()
    alert.last_sms_severity = alert.severity


def on_alert(alert: SecurityAlert, is_new: bool, severity_raised: bool):
    """Called by the detection pipeline after an alert is created/updated."""
    try:
        on_alert_sms(alert)
    except Exception:  # noqa: BLE001 - an SMS problem must never affect email or detection (UC-09 E2)
        current_app.logger.exception("SMS queueing failed")
    if not _recipients() or not at_least(alert.severity, settings.get("alert_min_severity")):
        return
    if alert.severity != "Critical":
        alert.pending_digest = True  # High (or Medium if min severity lowered) -> summary
        return
    throttle = timedelta(minutes=_cfg()["EMAIL_PER_ALERT_MINUTES"])
    recently = alert.last_emailed_at and datetime.now() - alert.last_emailed_at < throttle
    rose = alert.last_emailed_severity and RANK[alert.severity] > RANK[alert.last_emailed_severity]
    if recently and not rose:
        # record one suppression per alert per throttle period
        exists = Notification.query.filter(Notification.alert_id == alert.id, Notification.status == "Suppressed",
                                           Notification.created_at >= alert.last_emailed_at).first()
        if not exists:
            _queue("immediate", f"[{alert.severity.upper()}] {alert.category}", "", alert, status="Suppressed",
                   reason=f"per-alert throttle ({_cfg()['EMAIL_PER_ALERT_MINUTES']} min)")
        return
    if _sent_last_hour() >= _cfg()["EMAIL_MAX_PER_HOUR"]:
        if alert.pending_digest:  # already recorded and waiting for the summary
            return
        _queue("immediate", f"[{alert.severity.upper()}] {alert.category}", "", alert, status="Suppressed",
               reason=f"global cap {_cfg()['EMAIL_MAX_PER_HOUR']}/hour - moved to summary")
        alert.pending_digest = True
        return
    subject = (f"[CRITICAL] {alert.category} from {alert.src_ip} -> {alert.dst_ip} "
               f"({alert.occurrence_count:,} occurrence{'s' if alert.occurrence_count != 1 else ''})")
    _queue("immediate", subject, "A critical threat alert was raised.\n\n" + _fmt_alert(alert), alert)
    alert.last_emailed_at = datetime.now()
    alert.last_emailed_severity = alert.severity
    alert.pending_digest = False


def build_digest(force=False):
    """Queue one summary email for all alerts waiting for the digest."""
    pending = SecurityAlert.query.filter_by(pending_digest=True).order_by(SecurityAlert.max_risk.desc()).all()
    if not pending or not _recipients():
        return None
    if not force:
        last = Notification.query.filter_by(kind="digest").order_by(Notification.created_at.desc()).first()
        if last and datetime.now() - last.created_at < timedelta(minutes=_cfg()["DIGEST_INTERVAL_MINUTES"]):
            return None
    lines = [f"{len(pending)} alert(s) since the last summary:\n"]
    for a in pending[:50]:
        lines.append(_fmt_alert(a))
    if len(pending) > 50:
        lines.append(f"... and {len(pending) - 50} more on the dashboard.")
    counts = {}
    for a in pending:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    subject = "[SUMMARY] " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: -RANK[kv[0]]))
    n = _queue("digest", subject, "\n".join(lines))
    for a in pending:
        a.pending_digest = False
        a.last_emailed_at = datetime.now()
        a.last_emailed_severity = a.severity
    db.session.commit()
    return n


def send_test_email(user):
    n = _queue("test", "[TEST] Threat dashboard email test",
               "This is a test message from the SMB threat dashboard. No action required.")
    db.session.commit()
    process_queue()
    audit("Test email sent", user=user, status=n.status)
    return n


def send_test_sms(user):
    """UC-05 A2: send a test SMS to the saved numbers and report whether it was delivered (E6 records a failure)."""
    numbers = settings.get("sms_recipients")
    mode, _ = sms.transport(_cfg())
    n = _queue_sms("test", "[TEST] Threat dashboard SMS test. No action required.", recipients=numbers)
    db.session.commit()
    process_queue()
    audit("Test SMS sent", user=user, status=n.status, transport=mode, recipients=len(numbers))
    return n


def _deliver(cfg, n, recips):
    if n.channel == "SMS":
        try:
            return sms.deliver(cfg, recips, n.body or "")
        except Exception as e:  # noqa: BLE001 - recorded, never raised into email delivery
            return "Failed", 1, f"{type(e).__name__}: {str(e)[:200]}"
    return deliver(cfg, recips, n.subject, n.body)


def process_queue():
    """Deliver queued notifications (called by the background scheduler)."""
    cfg = _cfg()
    queued = Notification.query.filter_by(status="Queued").order_by(Notification.id).all()
    for n in queued:
        recips = [r.strip() for r in (n.recipients or "").split(",") if r.strip()]
        if not recips:
            n.status, n.error = "Failed", "no recipients configured"
            continue
        status, attempts, err = _deliver(cfg, n, recips)
        n.status, n.attempts, n.error = status, attempts, err
        n.sent_at = datetime.now() if status in ("Sent", "Outbox", "Partial") else None
        db.session.commit()
        what = "Alert SMS" if n.channel == "SMS" else "Alert email"
        audit(what + " " + ("sent" if status != "Failed" else "failed"), actor="system",
              notification_id=n.id, alert_id=n.alert_id, kind=n.kind, channel=n.channel or "Email",
              status=status, attempts=attempts, **({"error": err[:300]} if err else {}))
    db.session.commit()
    return len(queued)
