"""Evaluation helpers: metrics, sweeps, detection delay, plots."""
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix, precision_recall_curve,
                             roc_auc_score, roc_curve)


def capture_hours(df: pd.DataFrame) -> float:
    """Total capture duration (hours) = sum over days of (last - first timestamp)."""
    spans = df.groupby("day")["observed_at"].agg(lambda s: (s.max() - s.min()).total_seconds() / 3600)
    return float(spans.sum())


def fp_alert_groups(df: pd.DataFrame, pred: np.ndarray, y: np.ndarray, category=None, window_min=10) -> int:
    """Approximate the app's de-duplication: flagged flows grouped by
    (source, destination, category, 10-minute bucket). Count groups that contain
    only benign flows (= false-positive alerts an analyst would see)."""
    f = df.loc[pred, ["src_ip", "dst_ip", "observed_at"]].copy()
    if f.empty:
        return 0
    f["cat"] = category[pred] if category is not None else "anomaly"
    f["bucket"] = f["observed_at"].dt.floor(f"{window_min}min")
    f["attack"] = y[pred]
    g = f.groupby(["src_ip", "dst_ip", "cat", "bucket"])["attack"].max()
    return int((~g.astype(bool)).sum())


def binary_metrics(y: np.ndarray, pred: np.ndarray, hours: float) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[False, True]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "precision": round(float(precision), 4), "recall": round(float(recall), 4),
        "f1": round(float(f1), 4), "false_positive_rate": round(float(fpr), 5),
        "fp_flows_per_hour": round(float(fp / hours), 1) if hours else None,
        "fp_per_1000_benign_flows": round(float(1000 * fp / (fp + tn)), 2) if fp + tn else None,
    }


def per_category_recall(labels: pd.Series, pred: np.ndarray) -> dict:
    d = pd.DataFrame({"label": labels.values, "pred": pred})
    g = d.groupby("label")["pred"].agg(["mean", "size", "sum"])
    return {k: {"flows": int(r["size"]), "flagged": int(r["sum"]), "rate": round(float(r["mean"]), 4)}
            for k, r in g.iterrows()}


def detection_delay(df: pd.DataFrame, pred: np.ndarray) -> dict:
    """Per attack session (day x attack label): minutes from the first attack flow
    to the first *flagged* attack flow. Timestamps have 1-minute resolution."""
    out = {}
    d = df[["day", "label", "observed_at"]].assign(pred=pred)
    for (day, label), g in d[d.label != "BENIGN"].groupby(["day", "label"]):
        first = g.observed_at.min()
        hit = g.loc[g.pred, "observed_at"]
        out[f"{day} / {label}"] = {
            "first_attack_flow": str(first),
            "first_detection": str(hit.min()) if len(hit) else None,
            "delay_minutes": round((hit.min() - first).total_seconds() / 60, 1) if len(hit) else None,
        }
    return out


def sweep(y, risk, df, hours, thresholds=None):
    thresholds = thresholds if thresholds is not None else np.round(np.arange(0.50, 0.951, 0.05), 2)
    rows = []
    for t in thresholds:
        m = binary_metrics(y, risk >= t, hours)
        rows.append({"threshold": float(t), **{k: m[k] for k in
                     ("precision", "recall", "f1", "false_positive_rate", "fp_flows_per_hour")},
                     "flagged": int((risk >= t).sum())})
    return rows


def curves(y, score):
    fpr, tpr, _ = roc_curve(y, score)
    p, r, _ = precision_recall_curve(y, score)
    return {"roc_auc": round(float(roc_auc_score(y, score)), 4),
            "pr_auc_average_precision": round(float(average_precision_score(y, score)), 4)}, (fpr, tpr), (p, r)


# ---------------------------------------------------------------- plots ----
# matplotlib is optional (it may lack wheels on brand-new Python versions): every
# plot function silently becomes a no-op when it cannot be imported.
def _optional(fn):
    def wrapper(*a, **k):
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            print(f"matplotlib not installed - skipping {fn.__name__}")
            return None
        return fn(*a, **k)
    wrapper.__name__ = fn.__name__
    return wrapper


@_optional
def plot_pr_compare(curves_by_name, rule_metrics, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(5.6, 4.2))
    for name, ((p, r), auc) in curves_by_name.items():
        ax.plot(r, p, label=f"{name} (AP={auc['pr_auc_average_precision']:.3f})")
    ax.scatter([rule_metrics["recall"]], [rule_metrics["precision"]], color="red", zorder=5,
               label=f"Rule baseline (P={rule_metrics['precision']:.2f}, R={rule_metrics['recall']:.2f})")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision"); ax.set_title("Precision-Recall - test days")
    ax.set_ylim(0, 1.02); ax.legend(loc="lower left", fontsize=8)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


@_optional
def plot_importance(global_explain, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    feats = global_explain["features"][::-1]
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    ax.barh([f["feature"] for f in feats], [f["mean_abs_contribution"] for f in feats], color="#0ea5e9")
    ax.set_xlabel("mean |contribution| to attack probability")
    ax.set_title(f"Random Forest global importance\n{global_explain['method']}", fontsize=9)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)

@_optional
def plot_confusion(cm_dict, title, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    cm = np.array([[cm_dict["tn"], cm_dict["fp"]], [cm_dict["fn"], cm_dict["tp"]]])
    fig, ax = plt.subplots(figsize=(4.6, 4))
    ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]:,}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=11)
    ax.set_xticks([0, 1], ["Pred benign", "Pred attack"])
    ax.set_yticks([0, 1], ["True benign", "True attack"])
    ax.set_title(title, fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


@_optional
def plot_curves(roc, pr, auc, path_roc, path_pr, label):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(4.8, 4))
    ax.plot(roc[0], roc[1], label=f"{label} (AUC={auc['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], "--", color="grey")
    ax.set_xlabel("False positive rate"); ax.set_ylabel("True positive rate"); ax.set_title("ROC - test days")
    ax.legend(loc="lower right"); fig.tight_layout(); fig.savefig(path_roc, dpi=130); plt.close(fig)
    fig, ax = plt.subplots(figsize=(4.8, 4))
    ax.plot(pr[1], pr[0], label=f"{label} (AP={auc['pr_auc_average_precision']:.3f})")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision"); ax.set_title("Precision-Recall - test days")
    ax.legend(loc="lower left"); fig.tight_layout(); fig.savefig(path_pr, dpi=130); plt.close(fig)


@_optional
def plot_sweep(rows, path, chosen, title="Threshold sweep - test days (IF)"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    t = [r["threshold"] for r in rows]
    fig, ax = plt.subplots(figsize=(5.6, 4))
    for k in ("precision", "recall", "f1"):
        ax.plot(t, [r[k] for r in rows], marker="o", label=k)
    ax.plot(t, [r["false_positive_rate"] for r in rows], marker="o", label="FPR")
    ax.axvline(chosen, ls="--", color="grey", label=f"default {chosen}")
    ax.set_xlabel("Sensitivity threshold (risk score)"); ax.set_title(title)
    ax.legend(); fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


@_optional
def plot_hist(risk, y, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(5.6, 4))
    bins = np.linspace(0, 1, 41)
    ax.hist(risk[~y], bins=bins, alpha=0.6, label="benign", density=True)
    ax.hist(risk[y], bins=bins, alpha=0.6, label="attack", density=True)
    ax.set_xlabel("Risk score (0-1)"); ax.set_ylabel("density"); ax.set_title("Risk score distribution - test days")
    ax.legend(); fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)
