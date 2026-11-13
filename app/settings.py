"""Runtime settings stored in the DB (editable by admins), defaults from config."""
from flask import current_app

from .extensions import db
from .models import Setting


def defaults():
    c = current_app.config
    return {
        "sensitivity_threshold": c["SENSITIVITY_THRESHOLD"],
        "alert_recipients": [r.strip() for r in c["ALERT_RECIPIENTS"].split(",") if r.strip()],
        "alert_min_severity": c["ALERT_MIN_SEVERITY"],
        "grouping_minutes": c["ALERT_GROUPING_MINUTES"],
        "active_model": c["ACTIVE_MODEL"],
        "ip_display_mode": c["IP_DISPLAY_MODE"],
        "llm_ip_mode": c["LLM_IP_MODE"],
        "sms_enabled": bool(c["SMS_ENABLED"]),  # FR-10: send SMS alerts at all (transport is decided by .env)
        "sms_recipients": [r.strip() for r in c["SMS_RECIPIENTS"].split(",") if r.strip()],
        "sms_min_severity": c["SMS_MIN_SEVERITY"] if c["SMS_MIN_SEVERITY"] in ("Critical", "High") else "Critical",
        "previous_active_model": None,  # UC-06 A4 roll back
        "notification_revision": 0,  # UC-05 E7 concurrent-change check
    }


def get_raw(key, default=None):
    row = db.session.get(Setting, key)
    return row.value if row is not None else default


def get(key):
    row = db.session.get(Setting, key)
    return row.value if row is not None else defaults()[key]


def put(key, value):
    row = db.session.get(Setting, key)
    if row is None:
        db.session.add(Setting(key=key, value=value))
    else:
        row.value = value
    db.session.commit()
