"""Active-model selection (Isolation Forest vs Random Forest), models page, DB auto-migration."""
import sqlite3
from pathlib import Path

import pytest

from app import create_app, pipeline
from app import settings as app_settings
from app.extensions import db
from app.models import AuditLog, DetectionResult
from config import TestConfig
from ml.detectors import IsolationForestDetector, RandomForestDetector
from tests.conftest import FIXTURE
from tests.test_pages import _login

ROOT = Path(__file__).resolve().parents[1]
HAVE_MODELS = (ROOT / "models" / "isoforest_v1.joblib").exists() and (ROOT / "models" / "random_forest_v1.joblib").exists()


@pytest.mark.skipif(not HAVE_MODELS, reason="trained models not present (run scripts/train_and_evaluate.py)")
def test_switch_active_model_and_score(client, app):
    _login(client)
    pipeline._models.clear(); pipeline.reset_window()
    assert set(pipeline.available_models()) == {"isolation_forest", "random_forest"}
    assert isinstance(pipeline.detectors()[0], IsolationForestDetector)
    r = client.post("/settings/model", data={"active_model": "random_forest"})
    assert r.status_code == 302 and app_settings.get("active_model") == "random_forest"
    assert AuditLog.query.filter_by(action="Active model changed").count() == 1
    assert isinstance(pipeline.detectors()[0], RandomForestDetector)
    job, stats = pipeline.ingest_bytes(FIXTURE.read_bytes(), "sample.csv", source="test")
    assert job.status == "Completed"
    dets = {d.detector for d in DetectionResult.query.all()}
    assert "isolation_forest" not in dets
    page = client.get("/models").get_data(as_text=True)
    assert "Random Forest (supervised)" in page and "random_forest" in page and "Honest caveat" in page
    assert client.post("/settings/model", data={"active_model": "bogus"}).status_code == 302
    assert app_settings.get("active_model") == "random_forest"
    # UC-06 A4: roll back to the previous model version
    assert "Roll back to Isolation Forest" in client.get("/models").get_data(as_text=True)
    client.post("/settings/model", data={"rollback": "1"})
    assert app_settings.get("active_model") == "isolation_forest"
    assert AuditLog.query.filter_by(action="Active model rolled back").count() == 1
    pipeline._models.clear()


def test_auto_migration_adds_message_column(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE network_events (id INTEGER PRIMARY KEY, observed_at DATETIME, src_ip VARCHAR(64))")
    con.commit(); con.close()
    app = create_app(TestConfig, SQLALCHEMY_DATABASE_URI=f"sqlite:///{path.as_posix()}")
    with app.app_context():
        cols = {r[1] for r in db.session.execute(db.text("PRAGMA table_info(network_events)"))}
        assert "message" in cols
        db.session.remove()
