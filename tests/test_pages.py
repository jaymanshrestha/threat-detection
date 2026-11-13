"""Smoke test every page while logged in, plus CSV upload through the UI route."""
import io

import pyotp

from app.extensions import db
from app.models import Administrator, IngestionJob, NetworkEvent
from app.security import encrypt_secret, hash_password
from tests.conftest import FIXTURE


def _login(client):
    secret = pyotp.random_base32()
    db.session.add(Administrator(email="ops@example.com", password_hash=hash_password("a-long-password-123"),
                                 totp_secret_enc=encrypt_secret(secret), mfa_enabled=True))
    db.session.commit()
    client.post("/login", data={"email": "ops@example.com", "password": "a-long-password-123"})
    assert client.post("/mfa", data={"code": pyotp.TOTP(secret).now()}).status_code == 302


def test_all_pages_render(client):
    _login(client)
    for path in ["/", "/events", "/alerts", "/models", "/sources", "/datasets", "/notifications", "/users",
                 "/incidents", "/simulator",
                 "/audit", "/audit/export.csv", "/api/summary?range=1h", "/map", "/api/geo",
                 "/sources/upload/syslog", "/sources/upload/pcap", "/sources/upload/nfdump_csv",
                 "/sources/upload/netflow_v5", "/sources/upload/cicids2017"]:
        r = client.get(path)
        assert r.status_code == 200, path
    assert client.get("/api/summary?range=bogus").status_code == 400
    r = client.get("/")
    assert "Content-Security-Policy" in r.headers and r.headers["X-Frame-Options"] == "DENY"


def test_upload_csv(client):
    _login(client)
    r = client.post("/sources", data={"file": (io.BytesIO(FIXTURE.read_bytes()), "sample.csv")},
                    content_type="multipart/form-data")
    assert r.status_code == 302
    job = IngestionJob.query.one()
    assert job.status == "Completed" and job.accepted + job.rejected == 200
    assert NetworkEvent.query.count() == job.accepted
    assert client.get("/events").status_code == 200 and client.get("/alerts").status_code == 200


def test_ingest_api_requires_key(client):
    assert client.post("/api/v1/ingest", data=b"x").status_code == 401
    r = client.post("/api/v1/ingest", data=FIXTURE.read_bytes(), headers={"X-API-Key": "dev-ingest-key"})
    assert r.status_code == 200 and r.get_json()["accepted"] > 0
