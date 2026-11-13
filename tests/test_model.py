"""Model scoring: risk calibration, explanations and the trained artefact."""
from pathlib import Path

import numpy as np
import pytest

from ingest import get_adapter
from ingest.windows import add_window_features
from ml.detectors import IsolationForestDetector, RuleDetector
from tests.conftest import FIXTURE, ROOT

MODEL = ROOT / "models" / "isoforest_v1.joblib"


def _sample():
    df, _ = get_adapter("cicids2017").load(FIXTURE)
    return add_window_features(df.sort_values("observed_at", kind="stable").reset_index(drop=True))


def test_fit_score_and_calibration_are_monotone():
    df = _sample()
    det = IsolationForestDetector(n_estimators=50, max_samples=64).fit(df[df.label == "BENIGN"])
    raw = det.raw_score(df)
    det.calibrate(raw[: 100], float(np.quantile(raw, 0.6)), float(raw.max()))
    risk = det.to_risk(np.sort(raw))
    assert ((0 <= risk) & (risk <= 1)).all() and np.all(np.diff(risk) >= 0)
    out = det.detect(df, threshold=0.7)
    assert set(out.columns) == {"risk", "flagged", "category", "explanation"}
    flagged = out[out.flagged]
    assert flagged.explanation.map(lambda e: len(e) == 3 and e[0]["method"] == "feature deviation").all()


def test_rules_flag_port_scan_and_flood():
    df = _sample()
    rules = RuleDetector(portscan_ports=50, flood_flows=60)
    out = rules.detect(df)
    assert out.flagged.any()
    assert set(out.category[out.flagged]) <= {"Port Scan", "DoS / Flood"}


@pytest.mark.skipif(not MODEL.exists(), reason="run scripts/train_and_evaluate.py first")
def test_trained_artifact_scores_real_flows():
    det = IsolationForestDetector.load(MODEL)
    df = _sample()
    risk = det.risk(df)
    assert risk.shape == (len(df),) and np.isfinite(risk).all()
    # scan traffic should, on average, look riskier than the benign rows of the same capture
    assert risk[(df.label == "PortScan").to_numpy()].mean() > risk[(df.label == "BENIGN").to_numpy()].mean()
