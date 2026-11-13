"""Central configuration. Every value can be overridden with an environment
variable (see .env.example). Nothing secret is hard-coded for production use."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
# The instance folder (SQLite DB, email outbox) is not shipped in the zip; create it.
(BASE_DIR / "instance").mkdir(parents=True, exist_ok=True)


def _bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    # Fernet key used to encrypt TOTP secrets at rest. If empty it is derived
    # from SECRET_KEY (acceptable for a lab prototype, documented in README).
    TOTP_ENC_KEY = os.getenv("TOTP_ENC_KEY", "")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "sqlite:///" + (BASE_DIR / "instance" / "threats.db").as_posix()
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # SQLite: wait for locks instead of failing (ingest + notifier thread write concurrently)
    SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 30}} if SQLALCHEMY_DATABASE_URI.startswith("sqlite") else {}

    # Session / auth policy (proposal FR-01)
    SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", "30"))
    MFA_CHALLENGE_SECONDS = int(os.getenv("MFA_CHALLENGE_SECONDS", "120"))
    LOCKOUT_THRESHOLD = int(os.getenv("LOCKOUT_THRESHOLD", "5"))
    LOCKOUT_WINDOW_MINUTES = int(os.getenv("LOCKOUT_WINDOW_MINUTES", "15"))
    LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)  # True behind TLS
    WTF_CSRF_TIME_LIMIT = 3600

    # Ingestion API (used by the replay simulator)
    INGEST_API_KEY = os.getenv("INGEST_API_KEY", "dev-ingest-key")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_MB", "200")) * 1024 * 1024

    # Detection
    MODEL_PATH = os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "isoforest_v1.joblib"))
    RULES_PATH = os.getenv("RULES_PATH", str(BASE_DIR / "models" / "rules_v1.json"))
    RF_MODEL_PATH = os.getenv("RF_MODEL_PATH", str(BASE_DIR / "models" / "random_forest_v1.joblib"))
    ACTIVE_MODEL = os.getenv("ACTIVE_MODEL", "isolation_forest")  # or random_forest (changeable in the UI)

    # Geo-map (offline DB-IP City Lite MMDB, CC BY 4.0) and IP privacy
    GEOIP_DB = os.getenv("GEOIP_DB", str(BASE_DIR / "data" / "geo" / "dbip-city-lite.mmdb"))
    SITE_NAME = os.getenv("SITE_NAME", "Head office")
    SITE_LAT = float(os.getenv("SITE_LAT", "-37.8136"))  # Melbourne by default
    SITE_LON = float(os.getenv("SITE_LON", "144.9631"))
    IP_DISPLAY_MODE = os.getenv("IP_DISPLAY_MODE", "full")  # full | truncate | hash
    LLM_IP_MODE = os.getenv("LLM_IP_MODE", "hash")  # truncate | hash (never full)
    IP_HASH_KEY = os.getenv("IP_HASH_KEY", "")

    # LLM incident reports (OpenAI-compatible chat completions API; empty key = template)
    LLM_API_BASE = os.getenv("LLM_API_BASE", "https://api.openai.com/v1")
    LLM_API_KEY = os.getenv("LLM_API_KEY", "")
    LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
    LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "30"))

    # Streaming collectors (in-app background threads or scripts/collector.py)
    ENABLE_COLLECTORS = _bool("ENABLE_COLLECTORS", False)
    COLLECTOR_BIND = os.getenv("COLLECTOR_BIND", "127.0.0.1")
    SYSLOG_UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "5514"))
    SYSLOG_TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "5514"))
    NETFLOW_UDP_PORT = int(os.getenv("NETFLOW_UDP_PORT", "2055"))
    COLLECTOR_FLUSH_SECONDS = float(os.getenv("COLLECTOR_FLUSH_SECONDS", "1.0"))
    METRICS_PATH = os.getenv("METRICS_PATH", str(BASE_DIR / "reports" / "metrics.json"))
    SENSITIVITY_THRESHOLD = float(os.getenv("SENSITIVITY_THRESHOLD", "0.70"))

    # Alerting (FR-07 / FR-08)
    ALERT_GROUPING_MINUTES = int(os.getenv("ALERT_GROUPING_MINUTES", "10"))
    EMAIL_PER_ALERT_MINUTES = int(os.getenv("EMAIL_PER_ALERT_MINUTES", "30"))
    EMAIL_MAX_PER_HOUR = int(os.getenv("EMAIL_MAX_PER_HOUR", "20"))
    DIGEST_INTERVAL_MINUTES = int(os.getenv("DIGEST_INTERVAL_MINUTES", "60"))
    ALERT_RECIPIENTS = os.getenv("ALERT_RECIPIENTS", "")
    ALERT_MIN_SEVERITY = os.getenv("ALERT_MIN_SEVERITY", "High")
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_STARTTLS = _bool("SMTP_STARTTLS", True)
    SMTP_FROM = os.getenv("SMTP_FROM", "threat-dashboard@localhost")
    OUTBOX_DIR = os.getenv("OUTBOX_DIR", str(BASE_DIR / "instance" / "outbox"))
    PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:5000")
    # SMS alerts (FR-10, UC-05 A2, UC-09 A4) via the Twilio REST API. Without SMS_ENABLED=true and all three
    # Twilio values, SMS messages are written to SMS_OUTBOX_DIR instead (demo mode). Secrets stay in .env only.
    SMS_ENABLED = _bool("SMS_ENABLED", False)
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
    TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "").strip()
    SMS_RECIPIENTS = os.getenv("SMS_RECIPIENTS", "")  # comma-separated E.164 numbers, e.g. +61412345678
    SMS_MIN_SEVERITY = os.getenv("SMS_MIN_SEVERITY", "Critical")
    SMS_MAX_PER_HOUR = int(os.getenv("SMS_MAX_PER_HOUR", "10"))
    SMS_PER_ALERT_MINUTES = int(os.getenv("SMS_PER_ALERT_MINUTES", "60"))
    SMS_MAX_RECIPIENTS = int(os.getenv("SMS_MAX_RECIPIENTS", "10"))
    SMS_OUTBOX_DIR = os.getenv("SMS_OUTBOX_DIR", str(BASE_DIR / "instance" / "sms_outbox"))
    DATASET_DIR = os.getenv("DATASET_DIR", str(BASE_DIR / "instance" / "datasets"))  # lab / uploaded replay datasets
    SIMULATOR_SYNC = False
    # UC-08 A1 interval capture: a capture tool drops one .pcap per interval into this folder
    PCAP_WATCH_ENABLED = os.getenv("PCAP_WATCH_ENABLED", "0") == "1"
    PCAP_WATCH_DIR = os.getenv("PCAP_WATCH_DIR", str(BASE_DIR / "instance" / "pcap_inbox"))
    PCAP_INTERVAL_SECONDS = int(os.getenv("PCAP_INTERVAL_SECONDS", "300"))  # tests run the in-app replay inline instead of in a thread
    START_SCHEDULER = _bool("START_SCHEDULER", True)

    RAW_EVENT_RETENTION_DAYS = int(os.getenv("RAW_EVENT_RETENTION_DAYS", "30"))


class TestConfig(Config):
    TESTING = True
    SIMULATOR_SYNC = True
    LLM_API_KEY = ""
    ENABLE_COLLECTORS = False
    ACTIVE_MODEL = "isolation_forest"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    WTF_CSRF_ENABLED = False
    START_SCHEDULER = False
    SMTP_HOST = ""
    # never pick up a developer's real Twilio settings from .env in tests
    SMS_ENABLED = False
    TWILIO_ACCOUNT_SID = TWILIO_AUTH_TOKEN = TWILIO_FROM_NUMBER = ""
    SMS_RECIPIENTS = ""
