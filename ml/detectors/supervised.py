"""Supervised Random Forest detector (binary: attack vs benign)."""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from ..explain import TreeExplainerWrapper
from ..features import MODEL_FEATURES, PREPROCESSING_VERSION, pretty, to_matrix
from .base import Detector

DEFAULT_THRESHOLD = 0.70
CATEGORY = "Attack - supervised (type not classified)"
MAX_EXPLAINED_PER_BATCH = 200


class RandomForestDetector(Detector):
    name = "Random Forest"
    detector_type = "Supervised"

    def __init__(self, version="v1", features=None, random_state=42, **params):
        self.version = version
        self.features = list(features or MODEL_FEATURES)
        self.preprocessing = PREPROCESSING_VERSION
        defaults = dict(n_estimators=100, max_depth=14, min_samples_leaf=20, max_features="sqrt",
                        class_weight="balanced_subsample", max_samples=0.25, n_jobs=-1, random_state=random_state)
        defaults.update(params)
        self.model = RandomForestClassifier(**defaults)
        self.knots_x = self.knots_y = None
        self.meta = {}
        self._explainer = None

    def fit(self, df: pd.DataFrame, y: np.ndarray):
        self.model.fit(to_matrix(df, self.features), np.asarray(y, dtype=bool))
        return self

    def proba(self, df):
        p = self.model.predict_proba(to_matrix(df, self.features))
        idx = list(self.model.classes_).index(True)
        return p[:, idx]

    raw_score = proba

    def calibrate(self, benign_proba, threshold):
        med = float(np.median(benign_proba))
        threshold = min(max(threshold, med + 1e-6), 1 - 1e-6)
        self.knots_x = np.array([0.0, med, threshold, 1.0])
        self.knots_y = np.array([0.0, 0.35, DEFAULT_THRESHOLD, 1.0])

    def to_risk(self, p):
        return np.clip(np.interp(p, self.knots_x, self.knots_y), 0, 1)

    def risk(self, df):
        return self.to_risk(self.proba(df))

    @property
    def explainer(self):
        if self._explainer is None or getattr(self._explainer, "forest", None) is None:
            self._explainer = TreeExplainerWrapper(self.model)
        return self._explainer

    @property
    def explanation_method(self):
        return self.explainer.method

    def explain(self, df, top_k=5):
        base, contrib = self.explainer.explain(to_matrix(df, self.features))
        x = df[self.features].to_numpy(dtype=float)
        out = []
        for i, row in enumerate(contrib):
            idx = np.argsort(-row)[:top_k]
            out.append([{"feature": pretty(self.features[j]), "contribution": round(float(row[j]), 4),
                         "value": round(float(x[i, j]), 3), "method": self.explainer.method,
                         "base_value": round(float(base), 4)} for j in idx])
        return out

    def detect(self, df, threshold=None):
        threshold = DEFAULT_THRESHOLD if threshold is None else threshold
        risk = self.risk(df)
        flagged = risk >= threshold
        expl = [None] * len(df)
        idx = np.flatnonzero(flagged)
        if len(idx):
            # explain the highest-risk flagged flow of each (src, dst) pair, capped per batch
            sub = pd.DataFrame({"i": idx, "r": risk[idx], "k": (df["src_ip"].to_numpy()[idx] + ">" +
                                                                df["dst_ip"].to_numpy()[idx])})
            pick = sub.sort_values("r", ascending=False).drop_duplicates("k")["i"].to_numpy()[:MAX_EXPLAINED_PER_BATCH]
            for i, e in zip(pick, self.explain(df.iloc[pick])):
                expl[i] = e
        return pd.DataFrame({"risk": risk, "flagged": flagged, "category": CATEGORY, "explanation": expl},
                            index=df.index)

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        e, self._explainer = self._explainer, None
        joblib.dump(self, path)
        self._explainer = e

    @staticmethod
    def load(path):
        return joblib.load(path)
