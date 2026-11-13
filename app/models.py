"""Relational schema (mirrors proposal Table 11; SQLite for the MVP, any
SQLAlchemy URL such as PostgreSQL works via DATABASE_URL)."""
import json
from datetime import datetime

from flask_login import UserMixin
from sqlalchemy import event

from .extensions import db


def now():
    return datetime.now()


class JSONText(db.TypeDecorator):
    impl = db.Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else json.dumps(value, default=str)

    def process_result_value(self, value, dialect):
        return None if value is None else json.loads(value)


class Administrator(UserMixin, db.Model):
    __tablename__ = "administrators"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)  # Argon2id
    role = db.Column(db.String(32), default="Administrator", nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    totp_secret_enc = db.Column(db.Text)  # Fernet-encrypted base32 secret
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    last_totp_step = db.Column(db.Integer, default=0)  # replay protection
    locked_until = db.Column(db.DateTime)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=now)
    invite_pending = db.Column(db.Boolean, default=False)  # invited, has not completed first sign-in

    @property
    def is_active(self):
        return bool(self.active)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), index=True)
    administrator_id = db.Column(db.Integer, db.ForeignKey("administrators.id"))
    ip = db.Column(db.String(64))
    stage = db.Column(db.String(16))  # password | mfa
    success = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now, index=True)


class MfaChallenge(db.Model):
    __tablename__ = "mfa_challenges"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    administrator_id = db.Column(db.Integer, db.ForeignKey("administrators.id"), nullable=False)
    purpose = db.Column(db.String(16), default="verify")  # verify | enrol
    pending_secret_enc = db.Column(db.Text)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=now)


class AuditLog(db.Model):
    """Append-only: updates and deletes are blocked by ORM listeners below."""
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    administrator_id = db.Column(db.Integer, db.ForeignKey("administrators.id"))
    actor = db.Column(db.String(255))
    action = db.Column(db.String(64), nullable=False, index=True)
    details = db.Column(JSONText)
    ip = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=now, index=True)


@event.listens_for(AuditLog, "before_update")
@event.listens_for(AuditLog, "before_delete")
def _audit_immutable(mapper, connection, target):
    raise PermissionError("Audit log entries cannot be modified or deleted")


class Setting(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(JSONText)


class Dataset(db.Model):
    __tablename__ = "datasets"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    origin = db.Column(db.Text)
    licence = db.Column(db.Text)
    citation = db.Column(db.Text)
    profile = db.Column(db.String(64))
    size_info = db.Column(db.Text)
    is_public = db.Column(db.Boolean, default=True)
    kind = db.Column(db.String(16))  # public | lab | upload
    file_path = db.Column(db.Text)  # stored CSV for lab / uploaded replay datasets
    authorisation_ref = db.Column(db.Text)  # lab captures: written approval reference (UC-02 A1)
    row_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=now)


class IngestionJob(db.Model):
    __tablename__ = "ingestion_jobs"
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(32))  # upload | replay | api
    filename = db.Column(db.String(255))
    profile = db.Column(db.String(64))
    status = db.Column(db.String(16))  # Completed | Rejected | Error
    total_rows = db.Column(db.Integer, default=0)
    accepted = db.Column(db.Integer, default=0)
    rejected = db.Column(db.Integer, default=0)
    reasons = db.Column(JSONText)
    administrator_id = db.Column(db.Integer, db.ForeignKey("administrators.id"))
    run_id = db.Column(db.Integer, db.ForeignKey("simulation_runs.id"))
    created_at = db.Column(db.DateTime, default=now, index=True)


class SimulationRun(db.Model):
    __tablename__ = "simulation_runs"
    id = db.Column(db.Integer, primary_key=True)
    dataset = db.Column(db.String(128))
    file = db.Column(db.String(255))
    speed = db.Column(db.Float)
    attack_filter = db.Column(db.String(128))
    status = db.Column(db.String(16), default="Running")
    events_sent = db.Column(db.Integer, default=0)
    alerts_raised = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=now)
    ended_at = db.Column(db.DateTime)
    dataset_id = db.Column(db.Integer, db.ForeignKey("datasets.id"))
    events_planned = db.Column(db.Integer)
    started_by = db.Column(db.String(255))
    error = db.Column(db.Text)


class NetworkEvent(db.Model):
    __tablename__ = "network_events"
    id = db.Column(db.Integer, primary_key=True)
    observed_at = db.Column(db.DateTime, index=True)  # flow timestamp (source clock)
    received_at = db.Column(db.DateTime, default=now, index=True)
    src_ip = db.Column(db.String(64), index=True)
    src_port = db.Column(db.Integer)
    dst_ip = db.Column(db.String(64))
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.String(16))
    features = db.Column(JSONText)
    dataset_label = db.Column(db.String(64))  # ground truth from public dataset, display/eval only
    is_simulated = db.Column(db.Boolean, default=False)
    risk = db.Column(db.Float)  # denormalised IF risk for fast charts
    flagged = db.Column(db.Boolean, default=False, index=True)
    severity = db.Column(db.String(16))
    job_id = db.Column(db.Integer, db.ForeignKey("ingestion_jobs.id"))
    message = db.Column(db.Text)  # sanitised, truncated log text (syslog); never sent to models/LLM


class DetectionResult(db.Model):
    __tablename__ = "detection_results"
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("network_events.id"), index=True)
    detector = db.Column(db.String(64))
    model_version = db.Column(db.String(64))
    detector_type = db.Column(db.String(32))
    anomaly_score = db.Column(db.Float)
    flagged = db.Column(db.Boolean)
    predicted_label = db.Column(db.String(64))
    label_source = db.Column(db.String(32))  # Unclassified | Rule
    severity = db.Column(db.String(16))
    top_features = db.Column(JSONText)
    alert_id = db.Column(db.Integer, db.ForeignKey("security_alerts.id"), index=True)
    created_at = db.Column(db.DateTime, default=now)
    event = db.relationship("NetworkEvent")


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"
    id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.String(64), index=True)
    dst_ip = db.Column(db.String(64))
    category = db.Column(db.String(64))
    severity = db.Column(db.String(16), index=True)
    max_risk = db.Column(db.Float)
    occurrence_count = db.Column(db.Integer, default=0)
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime, index=True)
    status = db.Column(db.String(16), default="Open")
    is_simulated = db.Column(db.Boolean, default=False)
    top_features = db.Column(JSONText)
    last_emailed_at = db.Column(db.DateTime)
    last_emailed_severity = db.Column(db.String(16))
    last_sms_at = db.Column(db.DateTime)  # FR-10 SMS throttling, same rules as email
    last_sms_severity = db.Column(db.String(16))
    pending_digest = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=now)
    updated_at = db.Column(db.DateTime, default=now, onupdate=now)


class Notification(db.Model):
    __tablename__ = "notifications"
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("security_alerts.id"))
    channel = db.Column(db.String(16), default="Email")
    kind = db.Column(db.String(16))  # immediate | digest | test
    recipients = db.Column(db.Text)
    subject = db.Column(db.Text)
    body = db.Column(db.Text)
    status = db.Column(db.String(16), default="Queued")  # Queued|Sent|Outbox|Partial (SMS)|Failed|Suppressed
    attempts = db.Column(db.Integer, default=0)
    error = db.Column(db.Text)
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=now, index=True)
    sent_at = db.Column(db.DateTime)


class IncidentReport(db.Model):
    """Versioned plain-English incident reports (LLM or template). Never deleted."""
    __tablename__ = "incident_reports"
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("security_alerts.id"), index=True)
    version = db.Column(db.Integer, default=1)
    generator = db.Column(db.String(128))  # "LLM: <model>" | "Template"
    label = db.Column(db.String(128))
    facts = db.Column(JSONText)  # exactly what the LLM saw
    content = db.Column(JSONText)  # validated sections
    injection_flags = db.Column(JSONText)
    error = db.Column(db.Text)
    administrator_id = db.Column(db.Integer, db.ForeignKey("administrators.id"))
    created_at = db.Column(db.DateTime, default=now)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"))


class Invitation(db.Model):
    """Single-use account invitation (UC-07 / UC-01 A3). Only a SHA-256 of the token is stored."""
    __tablename__ = "invitations"
    id = db.Column(db.Integer, primary_key=True)
    administrator_id = db.Column(db.Integer, db.ForeignKey("administrators.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean, default=False, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("administrators.id"))
    notification_id = db.Column(db.Integer, db.ForeignKey("notifications.id"))
    created_at = db.Column(db.DateTime, default=now)


INCIDENT_STATUSES = ["New", "Investigating", "Resolved", "False Positive"]


class Incident(db.Model):
    """A group of related alerts under investigation (FR-09, UC-04 A3-A7, UC-10). Never deleted."""
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    severity = db.Column(db.String(16), index=True)
    status = db.Column(db.String(24), default="New", index=True)
    primary_alert_id = db.Column(db.Integer, db.ForeignKey("security_alerts.id"))
    resolution_note = db.Column(db.Text)
    is_simulated = db.Column(db.Boolean, default=False)
    revision = db.Column(db.Integer, default=1, nullable=False)  # optimistic concurrency (UC-04 E4)
    created_by = db.Column(db.Integer, db.ForeignKey("administrators.id"))
    created_at = db.Column(db.DateTime, default=now, index=True)
    updated_at = db.Column(db.DateTime, default=now, onupdate=now)


class IncidentAlert(db.Model):
    __tablename__ = "incident_alerts"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False, index=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("security_alerts.id"), nullable=False, unique=True)
    added_at = db.Column(db.DateTime, default=now)
