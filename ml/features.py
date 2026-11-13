"""Feature engineering shared by training, evaluation and live scoring.

The same function is used everywhere, so there is no train/serve skew."""
import numpy as np
import pandas as pd

from ingest.schema import FLOW_FEATURES
from ingest.windows import WINDOW_FEATURES

# All engineered candidates (stored for every event):
CANDIDATE_FEATURES = FLOW_FEATURES + WINDOW_FEATURES
# Subset used by the Isolation Forest. Chosen on the VALIDATION days only
# (Tue+Wed) by comparing 5 candidate subsets on validation ROC-AUC / best F1;
# the test days were not used for this choice (see reports/feature_selection.json).
MODEL_FEATURES = [
    "flow_duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "flow_packets_per_s", "pkt_len_mean", "init_win_fwd", "init_win_bwd",
] + WINDOW_FEATURES
PREPROCESSING_VERSION = "pp-v1 (signed log1p of CICFlowMeter stats + 60s per-source window counts)"

# Human-readable names used in explanations / emails
PRETTY = {
    "src_distinct_dports_in_window": "destination-port variety from source (60s)",
    "src_flows_in_window": "flows from source (60s)",
    "src_dst_flows_in_window": "flows source->destination (60s)",
    "flow_packets_per_s": "packet rate",
    "flow_bytes_per_s": "byte rate",
    "syn_flags": "SYN flag count",
    "rst_flags": "RST flag count",
    "init_win_fwd": "initial TCP window (fwd)",
    "init_win_bwd": "initial TCP window (bwd)",
}


def pretty(name: str) -> str:
    return PRETTY.get(name, name.replace("_", " "))


def to_matrix(df: pd.DataFrame, features=None) -> np.ndarray:
    x = df[list(features or MODEL_FEATURES)].to_numpy(dtype=np.float64)
    x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)
    return (np.sign(x) * np.log1p(np.abs(x))).astype(np.float32)
