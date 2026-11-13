"""Random Forest detector + explanations (SHAP if installed, exact Saabas path contributions otherwise)."""
import numpy as np
import pandas as pd
import pytest

from ingest import get_adapter
from ingest.windows import WindowState
from ml.detectors import RandomForestDetector
from ml.explain import SAABAS_METHOD, SHAP_METHOD, TreeExplainerWrapper, path_contributions, shap_available
from ml.features import MODEL_FEATURES, to_matrix
from tests.conftest import FIXTURE


@pytest.fixture(scope="module")
def frame():
    df, _ = get_adapter("cicids2017").load(FIXTURE.read_bytes())
    df = df.sort_values("observed_at", kind="stable").reset_index(drop=True)
    return pd.concat([df, WindowState().update(df)], axis=1)


@pytest.fixture(scope="module")
def rf(frame):
    y = (frame["label"] != "BENIGN").to_numpy()
    d = RandomForestDetector(n_estimators=15, max_depth=6, min_samples_leaf=2, max_samples=None, n_jobs=1)
    d.fit(frame, y)
    d.calibrate(d.proba(frame[~y]), 0.5)
    return d


def test_saabas_contributions_are_exact(rf, frame):
    X = to_matrix(frame, rf.features)
    base, contrib = path_contributions(rf.model, X)
    assert contrib.shape == (len(frame), len(MODEL_FEATURES))
    np.testing.assert_allclose(base + contrib.sum(1), rf.proba(frame), atol=1e-9)


@pytest.mark.skipif(not shap_available(), reason="shap not installed (Saabas fallback is used)")
def test_shap_additivity_and_label(rf, frame):
    w = TreeExplainerWrapper(rf.model)
    assert w.method == SHAP_METHOD
    base, contrib = w.explain(to_matrix(frame, rf.features))
    np.testing.assert_allclose(base + contrib.sum(1), rf.proba(frame), atol=1e-6)


def test_saabas_forced_by_env(rf, frame, monkeypatch):
    monkeypatch.setenv("EXPLAINER", "saabas")
    w = TreeExplainerWrapper(rf.model)
    assert w.method == SAABAS_METHOD
    ex = rf.__class__.explain  # explanation dicts carry the method label
    rf._explainer = None
    out = ex(rf, frame.head(3))
    assert out[0][0]["method"] == SAABAS_METHOD and "contribution" in out[0][0] and "base_value" in out[0][0]
    rf._explainer = None


def test_detect_calibration_and_roundtrip(rf, frame, tmp_path):
    r = rf.detect(frame, threshold=0.70)
    assert set(r.columns) == {"risk", "flagged", "category", "explanation"}
    assert r["risk"].between(0, 1).all()
    assert rf.to_risk(np.array([rf.knots_x[2]]))[0] == pytest.approx(0.70)
    flagged = r[r.flagged]
    assert len(flagged) and flagged["explanation"].notna().any()
    rf.save(tmp_path / "rf.joblib")
    back = RandomForestDetector.load(tmp_path / "rf.joblib")
    np.testing.assert_allclose(back.risk(frame), rf.risk(frame))
    assert back.explain(frame.head(1))[0][0]["method"] in (SHAP_METHOD, SAABAS_METHOD)
