"""Explanations for tree ensembles.

* ``shap.TreeExplainer`` (exact Tree SHAP) when the optional ``shap`` package is
  installed and EXPLAINER is not set to "saabas".
* Otherwise an exact in-house *path-contribution* decomposition (Saabas /
  TreeInterpreter style): for every tree, the change in the predicted attack
  probability at each split along the decision path is credited to that split's
  feature. ``bias + sum(contributions) == predict_proba`` exactly. It is not a
  Shapley value (it depends on feature order along the path), which is why the UI
  labels which method produced each explanation.
"""
import os

import numpy as np
from scipy import sparse

SHAP_METHOD = "SHAP (shap.TreeExplainer)"
SAABAS_METHOD = "path contribution (Saabas/TreeInterpreter)"


def shap_available() -> bool:
    if os.getenv("EXPLAINER", "auto").lower() == "saabas":
        return False
    try:
        import shap  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 - shap may fail to import (numba/llvmlite) on new Pythons
        return False


def _tree_node_proba(tree, cls=1):
    v = tree.value[:, 0, :].astype(np.float64)
    s = v.sum(axis=1, keepdims=True)
    s[s == 0] = 1.0
    return (v / s)[:, cls]


def path_contributions(forest, X, cls=1):
    """Return (bias, contributions[n_samples, n_features]) for a fitted sklearn forest."""
    X = np.asarray(X, dtype=np.float32)
    n, f = X.shape
    contrib = np.zeros((n, f), dtype=np.float64)
    bias = 0.0
    for est in forest.estimators_:
        t = est.tree_
        p = _tree_node_proba(t, cls)
        parent = np.full(t.node_count, -1)
        for side in (t.children_left, t.children_right):
            kids = np.flatnonzero(side >= 0)
            parent[side[kids]] = kids
        nodes = np.flatnonzero(parent >= 0)
        delta = p[nodes] - p[parent[nodes]]
        feats = t.feature[parent[nodes]]
        D = sparse.csr_matrix((delta, (nodes, feats)), shape=(t.node_count, f))
        contrib += (est.decision_path(X) @ D).toarray()
        bias += p[0]
    k = len(forest.estimators_)
    return bias / k, contrib / k


class TreeExplainerWrapper:
    def __init__(self, forest, prefer_shap=True):
        self.forest = forest
        self.method = SAABAS_METHOD
        self._shap = None
        if prefer_shap and shap_available():
            try:
                import shap
                self._shap = shap.TreeExplainer(forest)
                self.method = SHAP_METHOD
            except Exception:  # noqa: BLE001
                self._shap = None

    def explain(self, X):
        """Return (base_value, contributions[n, f]) for the attack class."""
        X = np.asarray(X, dtype=np.float32)
        if self._shap is not None:
            sv = self._shap.shap_values(X, check_additivity=False)
            if isinstance(sv, list):
                sv = sv[1]
            elif sv.ndim == 3:
                sv = sv[:, :, 1]
            ev = self._shap.expected_value
            base = float(ev[1] if np.ndim(ev) else ev)
            return base, np.asarray(sv, dtype=np.float64)
        return path_contributions(self.forest, X)

    def __getstate__(self):  # never pickle the shap object (re-created on load)
        return {"forest": None, "method": self.method}

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._shap = None
