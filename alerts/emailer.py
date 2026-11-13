"""Email transport: SMTP when configured, otherwise a local outbox folder (dev)."""
import smtplib
import ssl
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path


def build_message(sender, recipients, subject, body):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg["Date"] = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
    msg.set_content(body)
    return msg


def deliver(cfg, recipients, subject, body, retries=3, backoff=0.5):
    """Returns (status, attempts, error). status: Sent | Outbox | Failed."""
    msg = build_message(cfg["SMTP_FROM"], recipients, subject, body)
    if not cfg.get("SMTP_HOST"):
        out = Path(cfg["OUTBOX_DIR"])
        out.mkdir(parents=True, exist_ok=True)
        name = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".eml"
        (out / name).write_bytes(bytes(msg))
        return "Outbox", 1, None
    err = None
    for attempt in range(1, retries + 1):
        try:
            with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as s:
                if cfg.get("SMTP_STARTTLS"):
                    s.starttls(context=ssl.create_default_context())
                if cfg.get("SMTP_USER"):
                    s.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
                s.send_message(msg)
            return "Sent", attempt, None
        except Exception as e:  # noqa: BLE001 - record and retry, never crash detection
            err = f"{type(e).__name__}: {e}"
            time.sleep(backoff * attempt)
    return "Failed", retries, err
