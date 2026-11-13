import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from config import TestConfig  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "cicids2017_sample.csv"


@pytest.fixture
def app(tmp_path):
    app = create_app(TestConfig, OUTBOX_DIR=str(tmp_path / "outbox"),
                     DATASET_DIR=str(tmp_path / "datasets"),
                     PCAP_WATCH_DIR=str(tmp_path / "pcap_inbox"), ALERT_RECIPIENTS="soc@example.com")
    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()
