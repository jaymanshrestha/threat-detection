"""SMS transport (FR-10, UC-05 A2, UC-09 A4): Twilio REST API, otherwise a local outbox folder.

Twilio is used only when SMS_ENABLED=true and TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and
TWILIO_FROM_NUMBER are all set in .env. Otherwise each message is written to
instance/sms_outbox/*.txt so the demo works without an account. Credentials are read from the
config only; they are never stored in the database, logged or shown in the UI.
"""
import re
import time
import unicodedata
from datetime import datetime
from pathlib import Path

import requests

TWILIO_URL = "https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
E164 = re.compile(r"^\+[1-9]\d{7,14}$")
MAX_LEN = 160  # one GSM-7 segment
# Twilio error codes worth explaining (https://www.twilio.com/docs/api/errors)
HINTS = {21608: "trial accounts can only send to verified numbers - verify it in the Twilio Console",
         21211: "the number is not a valid phone number", 21614: "the number cannot receive SMS",
         21408: "SMS to this country is not enabled in the Twilio geo permissions",
         20003: "Twilio rejected the credentials - check TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN",
         21606: "TWILIO_FROM_NUMBER is not an SMS-capable number on this account"}


def normalise(number):
    """Return an E.164 number or None. Spaces, dashes, dots and brackets are ignored; an Australian
    mobile written locally (04xx xxx xxx) is converted to +614xxxxxxxx."""
    n = re.sub(r"[\s\-().]", "", str(number or ""))
    if n.startswith("00"):
        n = "+" + n[2:]
    if re.fullmatch(r"04\d{8}", n):
        n = "+61" + n[1:]
    return n if E164.fullmatch(n) else None


def missing_credentials(cfg):
    return [k for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER") if not cfg.get(k)]


def transport(cfg):
    """('twilio', None) when live sending is configured, else ('outbox', reason)."""
    if not cfg.get("SMS_ENABLED"):
        return "outbox", "SMS_ENABLED is false"
    miss = missing_credentials(cfg)
    if miss:
        return "outbox", "missing " + ", ".join(miss)
    return "twilio", None


def fit(text, limit=MAX_LEN):
    """Plain ASCII (GSM-7 safe) and at most one segment."""
    text = unicodedata.normalize("NFKD", text.replace("\u2192", "->").replace("\u00b7", "-").replace("\u2013", "-"))
    text = text.encode("ascii", "ignore").decode()
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def _outbox(cfg, recipients, body):
    out = Path(cfg["SMS_OUTBOX_DIR"])
    out.mkdir(parents=True, exist_ok=True)
    name = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".txt"
    (out / name).write_text(f"To: {', '.join(recipients)}\nDate: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n{body}\n")
    return "Outbox", 1, None


def _send_one(cfg, to, body, retries, backoff):
    """Returns (ok, attempts, error). Network errors, 429 and 5xx are retried; other 4xx are final."""
    url = TWILIO_URL.format(sid=cfg["TWILIO_ACCOUNT_SID"])
    err = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.post(url, data={"To": to, "From": cfg["TWILIO_FROM_NUMBER"], "Body": body},
                              auth=(cfg["TWILIO_ACCOUNT_SID"], cfg["TWILIO_AUTH_TOKEN"]), timeout=10)
        except requests.RequestException as e:
            err = f"{type(e).__name__}: {str(e)[:200]}"
        else:
            if r.status_code in (200, 201):
                return True, attempt, None
            try:
                j = r.json()
            except ValueError:
                j = {}
            code = j.get("code")
            err = f"Twilio {r.status_code}" + (f" error {code}" if code else "") + f": {str(j.get('message') or r.text)[:200]}"
            if code in HINTS:
                err += f" ({HINTS[code]})"
            if r.status_code < 500 and r.status_code != 429:
                return False, attempt, err
        if attempt < retries:
            time.sleep(backoff * attempt)
    return False, retries, err


def deliver(cfg, recipients, body, retries=3, backoff=0.5):
    """Returns (status, attempts, error). status: Sent | Outbox | Partial | Failed."""
    body = fit(body)
    mode, _why = transport(cfg)
    if mode == "outbox":
        return _outbox(cfg, recipients, body)
    errors, attempts = [], 0
    for to in recipients:
        ok, n, err = _send_one(cfg, to, body, retries, backoff)
        attempts = max(attempts, n)
        if not ok:
            errors.append(f"{to}: {err}")
    if not errors:
        return "Sent", attempts, None
    status = "Failed" if len(errors) == len(recipients) else "Partial"
    return status, attempts, "; ".join(errors)[:1000]
