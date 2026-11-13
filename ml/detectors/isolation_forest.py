"""Isolation Forest detector (unsupervised, trained on benign traffic only)."""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from ..features import MODEL_FEATURES, PREPROCESSING_VERSION, pretty, to_matrix
from .base import UNCLASSIFIED, Detector

DEFAULT_THRESHOLD = 0.70  # risk value that the validation-chosen raw cut-off maps to


class IsolationForestDetector(Detector):
    name = "Isolation Forest"
    detector_type = "Unsupervised"

    def __init__(self, version="v1", n_estimators=200, max_samples=256, random_state=42, features=None):
        self.version = version
        self.model = IsolationForest(
            n_estimators=n_estimators, max_samples=max_samples, random_state=random_state, n_jobs=-1
        )
        self.features = list(features or MODEL_FEATURES)
        self.preprocessing = PREPROCESSING_VERSION
        self.knots_x = None  # raw-score calibration knots
        self.knots_y = None
        self.center = None  # benign medians (log space) for explanations
        self.spread = None  # benign IQR (log space)
        self.meta = {}

    # ---- training -------------------------------------------------------
    def fit(self, benign_df: pd.DataFrame):
        x = to_matrix(benign_df, self.features)
        self.model.fit(x)
        self.center = np.median(x, axis=0)
        q75, q25 = np.percentile(x, [75, 25], axis=0)
        self.spread = np.maximum(q75 - q25, np.maximum(np.std(x, axis=0), 1e-3))
        return self

    def raw_score(self, df: pd.DataFrame) -> np.ndarray:
        """Original Isolation Forest anomaly score s(x) in (0, 1]; higher = more anomalous."""
        return -self.model.score_samples(to_matrix(df, self.features))

    def calibrate(self, benign_raw: np.ndarray, raw_threshold: float, raw_high: float):
        """Monotone piecewise-linear map from raw score to a 0-1 risk scale:
        benign median -> 0.35, validation-chosen cut-off -> 0.70 (default
        sensitivity), raw_high (top of the validation score range) -> 1.0.
        This is a ranking scale, NOT a probability of maliciousness."""
        med = float(np.median(benign_raw))
        raw_threshold = max(raw_threshold, med + 1e-6)
        raw_high = max(raw_high, raw_threshold + 1e-6)
        self.knots_x = np.array([0.0, med, raw_threshold, raw_high])
        self.knots_y = np.array([0.0, 0.35, DEFAULT_THRESHOLD, 1.0])

    def to_risk(self, raw: np.ndarray) -> np.ndarray:
        return np.clip(np.interp(raw, self.knots_x, self.knots_y), 0.0, 1.0)

    # ---- inference --------------------------------------------------------
    def risk(self, df: pd.DataFrame) -> np.ndarray:
        return self.to_risk(self.raw_score(df))

    def explain(self, df: pd.DataFrame, top_k: int = 3):
        """Top deviating features (robust z-score vs benign training traffic).
        This is a feature-deviation explanation, not SHAP."""
        z = (to_matrix(df, self.features) - self.center) / self.spread
        out = []
        for row in z:
            idx = np.argsort(-np.abs(row))[:top_k]
            out.append([
                {"feature": pretty(self.features[i]), "z": round(float(row[i]), 1),
                 "direction": "high" if row[i] > 0 else "low", "method": "feature deviation"}
                for i in idx
            ])
        return out

    def detect(self, df: pd.DataFrame, threshold: float = None) -> pd.DataFrame:
        threshold = DEFAULT_THRESHOLD if threshold is None else threshold
        risk = self.risk(df)
        flagged = risk >= threshold
        expl = [None] * len(df)
        if flagged.any():
            ex = self.explain(df[flagged])
            for j, i in enumerate(np.flatnonzero(flagged)):
                expl[i] = ex[j]
        return pd.DataFrame(
            {"risk": risk, "flagged": flagged, "category": UNCLASSIFIED, "explanation": expl},
            index=df.index,
        )

    # ---- persistence ------------------------------------------------------
    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path) -> "IsolationForestDetector":
        return joblib.load(path)
