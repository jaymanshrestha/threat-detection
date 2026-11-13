#!/usr/bin/env python
"""Train the Isolation Forest + calibrate the rule baseline, then evaluate on the
held-out test days. Writes models/ and reports/ artefacts.

Usage:  python scripts/train_and_evaluate.py [--select-features]
"""
import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sklearn.metrics import precision_recall_fscore_support, roc_auc_score  # noqa: E402

from alerts.severity import classify  # noqa: E402
from ml import evaluate as ev  # noqa: E402
from ml.data import FILES, SPLIT, load_day  # noqa: E402
from ml.detectors import DOS, IsolationForestDetector, RandomForestDetector, RuleDetector  # noqa: E402
from ml.detectors.isolation_forest import DEFAULT_THRESHOLD  # noqa: E402
from ml.features import MODEL_FEATURES  # noqa: E402
from ingest.windows import WINDOW_FEATURES  # noqa: E402

MODELS, REPORTS = ROOT / "models", ROOT / "reports"


def best_f1_threshold(y, raw, cands=None):
    cands = np.quantile(raw, np.linspace(0.50, 0.995, 200)) if cands is None else cands
    best = (-1, None)
    for t in np.unique(cands):
        f1 = precision_recall_fscore_support(y, raw >= t, average="binary", zero_division=0)[2]
        if f1 > best[0]:
            best = (f1, float(t))
    return best


def feature_selection(train, val, yv):
    base = ["flow_duration", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "flow_packets_per_s"]
    from ml.features import CANDIDATE_FEATURES
    cands = {
        "A_all_36": CANDIDATE_FEATURES,
        "B_19_flags": base + ["flow_bytes_per_s", "flow_iat_mean", "pkt_len_mean", "syn_flags", "rst_flags",
                              "ack_flags", "psh_flags", "fin_flags", "init_win_fwd", "init_win_bwd"] + WINDOW_FEATURES,
        "D_12_selected": MODEL_FEATURES,
        "E_10_no_initwin": base + ["pkt_len_mean"] + WINDOW_FEATURES,
        "F_flow_only_no_windows": [f for f in MODEL_FEATURES if f not in WINDOW_FEATURES],
    }
    res = {}
    for name, feats in cands.items():
        det = IsolationForestDetector(features=feats).fit(train)
        raw = det.raw_score(val)
        f1, _ = best_f1_threshold(yv, raw)
        res[name] = {"n_features": len(feats), "val_roc_auc": round(float(roc_auc_score(yv, raw)), 4),
                     "val_best_f1": round(float(f1), 4), "features": feats}
        print("  ", name, res[name]["val_roc_auc"], res[name]["val_best_f1"])
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--select-features", action="store_true", help="re-run validation feature-subset comparison")
    args = ap.parse_args()
    MODELS.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True)
    t0 = time.time()

    days, ingest_reports = {}, {}
    for d in FILES:
        days[d], rep = load_day(d)
        ingest_reports.update(rep)
    train = pd.concat([days[d] for d in SPLIT["train"]], ignore_index=True)
    val = pd.concat([days[d] for d in SPLIT["validation"]], ignore_index=True)
    test = pd.concat([days[d] for d in SPLIT["test"]], ignore_index=True)
    train_benign = train[train.label == "BENIGN"]
    yv = (val.label != "BENIGN").to_numpy()
    yt = (test.label != "BENIGN").to_numpy()
    print(f"train={len(train_benign):,} benign flows, val={len(val):,}, test={len(test):,}")

    if args.select_features:
        print("feature-subset comparison on validation:")
        (REPORTS / "feature_selection.json").write_text(json.dumps(feature_selection(train_benign, val, yv), indent=2))

    # ---------------- train ----------------
    det = IsolationForestDetector(version="v1")
    det.fit(train_benign)
    rules = RuleDetector.calibrate(train_benign)
    raw_val = det.raw_score(val)
    val_f1, raw_thr = best_f1_threshold(yv, raw_val)
    det.calibrate(raw_val[~yv], raw_thr, float(np.quantile(raw_val, 0.999)))
    det.meta = {"trained_at": datetime.now().isoformat(timespec="seconds"),
                "train_days": SPLIT["train"], "train_rows": int(len(train_benign)),
                "raw_threshold": raw_thr, "validation_best_f1": round(val_f1, 4)}
    det.save(MODELS / "isoforest_v1.joblib")
    rules.save(MODELS / "rules_v1.json")
    print("raw threshold", raw_thr, "val F1", val_f1, "rules", rules.to_dict())

    # ---------------- supervised Random Forest ----------------
    # Time-block split (no random rows): fit on Monday + Tuesday + Wednesday before
    # 10:40 (slowloris, Slowhttptest); tune the threshold on Wednesday from 10:40
    # (DoS Hulk, GoldenEye, Heartbleed - attack types the forest has not seen).
    wed = days["Wednesday"]
    cut = wed.observed_at.dt.normalize().iloc[0] + pd.Timedelta(hours=10, minutes=40)
    rf_train = pd.concat([days["Monday"], days["Tuesday"], wed[wed.observed_at < cut]], ignore_index=True)
    rf_tune = wed[wed.observed_at >= cut].reset_index(drop=True)
    y_rf_train = (rf_train.label != "BENIGN").to_numpy()
    y_tune = (rf_tune.label != "BENIGN").to_numpy()
    t_rf = time.time()
    rf = RandomForestDetector(version="v1").fit(rf_train, y_rf_train)
    p_tune = rf.proba(rf_tune)
    rf_f1, rf_thr = best_f1_threshold(y_tune, p_tune, cands=np.round(np.arange(0.02, 0.99, 0.01), 2))
    rf.calibrate(p_tune[~y_tune], rf_thr)
    rf.meta = {"trained_at": datetime.now().isoformat(timespec="seconds"),
               "train": "Monday + Tuesday + Wednesday < 10:40", "tune": "Wednesday >= 10:40",
               "train_rows": int(len(rf_train)), "train_attacks": int(y_rf_train.sum()),
               "proba_threshold": rf_thr, "tune_best_f1": round(rf_f1, 4),
               "fit_seconds": round(time.time() - t_rf, 1)}
    rf.save(MODELS / "random_forest_v1.joblib")
    print("RF threshold", rf_thr, "tune F1", rf_f1, rf.meta)

    # ---------------- evaluate ----------------
    hours_test, hours_val = ev.capture_hours(test), ev.capture_hours(val)
    risk_val = det.to_risk(raw_val)
    risk_test = det.risk(test)
    if_pred = risk_test >= DEFAULT_THRESHOLD
    rule_out = rules.detect(test)
    rule_pred = rule_out["flagged"].to_numpy()
    rule_cat = rule_out["category"].to_numpy()
    hybrid_pred = if_pred | rule_pred
    risk_rf_test = rf.risk(test)
    rf_pred = risk_rf_test >= DEFAULT_THRESHOLD
    risk_rf_tune = rf.to_risk(p_tune)
    hours_tune = ev.capture_hours(rf_tune)
    rule_val_pred = rules.detect(val)["flagged"].to_numpy()

    def block(pred, y, df, hours, cat=None):
        m = ev.binary_metrics(y, pred, hours)
        m["fp_alert_groups"] = ev.fp_alert_groups(df, pred, y, cat)
        m["fp_alerts_per_hour"] = round(m["fp_alert_groups"] / hours, 2)
        return m

    auc, roc, pr = ev.curves(yt, risk_test)
    auc_val, _, _ = ev.curves(yv, risk_val)
    auc_rf, roc_rf, pr_rf = ev.curves(yt, risk_rf_test)
    results = {
        "isolation_forest": {
            "test": {**block(if_pred, yt, test, hours_test), **auc,
                     "per_category_detection_rate": ev.per_category_recall(test.label, if_pred),
                     "detection_delay": ev.detection_delay(test, if_pred)},
            "validation": {**block(risk_val >= DEFAULT_THRESHOLD, yv, val, hours_val), **auc_val},
        },
        "rule_baseline": {
            "test": {**block(rule_pred, yt, test, hours_test, rule_cat),
                     "per_category_detection_rate": ev.per_category_recall(test.label, rule_pred),
                     "detection_delay": ev.detection_delay(test, rule_pred)},
            "validation": block(rule_val_pred, yv, val, hours_val),
        },
        "random_forest": {
            "test": {**block(rf_pred, yt, test, hours_test), **auc_rf,
                     "per_category_detection_rate": ev.per_category_recall(test.label, rf_pred),
                     "detection_delay": ev.detection_delay(test, rf_pred)},
            "validation": {**block(risk_rf_tune >= DEFAULT_THRESHOLD, y_tune, rf_tune, hours_tune),
                           **ev.curves(y_tune, risk_rf_tune)[0], "note": "tuning block = Wednesday >= 10:40"},
        },
        "hybrid_rf_or_rule": {
            "test": {**block(rf_pred | rule_pred, yt, test, hours_test),
                     "per_category_detection_rate": ev.per_category_recall(test.label, rf_pred | rule_pred),
                     "detection_delay": ev.detection_delay(test, rf_pred | rule_pred)},
        },
        "hybrid_if_or_rule (deployed in app)": {
            "test": {**block(hybrid_pred, yt, test, hours_test),
                     "per_category_detection_rate": ev.per_category_recall(test.label, hybrid_pred),
                     "detection_delay": ev.detection_delay(test, hybrid_pred)},
        },
    }
    sev = [classify(r, DEFAULT_THRESHOLD, c) for r, c in zip(risk_test[hybrid_pred], rule_cat[hybrid_pred])]
    sev_counts = pd.Series(sev).value_counts().to_dict()
    sev_by_truth = pd.crosstab(pd.Series(sev, name="severity"),
                               pd.Series(np.where(yt[hybrid_pred], "attack", "benign"), name="truth")).to_dict()

    sweep_test = ev.sweep(yt, risk_test, test, hours_test)
    sweep_val = ev.sweep(yv, risk_val, val, hours_val)
    sweep_test_rf = ev.sweep(yt, risk_rf_test, test, hours_test)
    sweep_tune_rf = ev.sweep(y_tune, risk_rf_tune, rf_tune, hours_tune)

    # global importance: mean |contribution| on a stratified test sample + impurity importance
    rng = np.random.default_rng(11)
    sample_idx = np.concatenate([rng.choice(np.flatnonzero(yt), 1000, replace=False),
                                 rng.choice(np.flatnonzero(~yt), 1000, replace=False)])
    from ml.features import pretty, to_matrix
    base_val, contrib = rf.explainer.explain(to_matrix(test.iloc[sample_idx], rf.features))
    global_imp = sorted([{"feature": pretty(f), "mean_abs_contribution": round(float(v), 5),
                          "impurity_importance": round(float(g), 5)}
                         for f, v, g in zip(rf.features, np.abs(contrib).mean(axis=0), rf.model.feature_importances_)],
                        key=lambda r: -r["mean_abs_contribution"])
    global_explain = {"method": rf.explainer.method, "base_value": round(float(base_val), 4),
                      "sample": "1,000 attack + 1,000 benign test flows", "features": global_imp}

    # failure cases (5 missed attacks, 5 false alarms) for the Models page
    def cases(mask, n=5, kind=""):
        idx = np.flatnonzero(mask)
        rng = np.random.default_rng(7)
        pick = rng.choice(idx, size=min(n, len(idx)), replace=False) if len(idx) else []
        rows = []
        for i in pick:
            r = test.iloc[i]
            rows.append({"kind": kind, "observed_at": str(r.observed_at), "src_ip": r.src_ip, "dst_ip": r.dst_ip,
                         "dst_port": int(r.dst_port), "true_label": r.label, "risk": round(float(risk_test[i]), 3),
                         "top_features": det.explain(test.iloc[[i]])[0]})
        return rows
    failures = cases(yt & ~hybrid_pred, kind="False negative (missed attack)") + \
        cases(~yt & hybrid_pred, kind="False positive (benign flagged)")

    split_info = {}
    for name, df in (("train", train), ("validation", val), ("test", test)):
        split_info[name] = {"days": SPLIT[name], "flows": int(len(df)),
                            "benign": int((df.label == "BENIGN").sum()),
                            "attack": int((df.label != "BENIGN").sum()),
                            "capture_hours": round(ev.capture_hours(df), 2),
                            "labels": df.label.value_counts().to_dict()}
    split_info["train"]["note"] = "Isolation Forest is fitted on benign flows only (Monday has no attacks)."

    metrics = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "dataset": {"name": "CIC-IDS2017 (GeneratedLabelledFlows / TrafficLabelling CSVs)",
                    "official_page": "https://www.unb.ca/cic/datasets/ids-2017.html",
                    "mirror_used": "https://huggingface.co/datasets/bencorn/CICIDS2017 (csvs/GeneratedLabelledFlows.zip)",
                    "citation": "Iman Sharafaldin, Arash Habibi Lashkari, Ali A. Ghorbani, 'Toward Generating a New "
                                "Intrusion Detection Dataset and Intrusion Traffic Characterization', ICISSP 2018."},
        "split": split_info,
        "ingestion": ingest_reports,
        "model": {"name": det.model_version, "type": det.detector_type, "preprocessing": det.preprocessing,
                  "features": det.features, "params": det.model.get_params(),
                  "raw_threshold": raw_thr, "risk_threshold_default": DEFAULT_THRESHOLD,
                  "calibration_knots": {"raw": det.knots_x.tolist(), "risk": det.knots_y.tolist()},
                  "threshold_selection": "raw score cut-off that maximises F1 on the validation days; "
                                         "mapped to risk 0.70 by the calibration"},
        "rule_baseline": rules.to_dict(),
        "supervised_model": {"name": rf.model_version, "type": rf.detector_type, "features": rf.features,
                             "params": {k: v for k, v in rf.model.get_params().items() if k != "n_jobs"},
                             "proba_threshold": rf_thr, "risk_threshold_default": DEFAULT_THRESHOLD,
                             "calibration_knots": {"proba": rf.knots_x.tolist(), "risk": rf.knots_y.tolist()},
                             "split": {"train": rf.meta["train"], "tune": rf.meta["tune"],
                                       "train_rows": rf.meta["train_rows"], "train_attacks": rf.meta["train_attacks"],
                                       "train_labels": rf_train.label.value_counts().to_dict(),
                                       "tune_labels": rf_tune.label.value_counts().to_dict()},
                             "threshold_selection": "probability cut-off maximising F1 on the Wednesday >= 10:40 "
                                                    "tuning block; mapped to risk 0.70",
                             "explanations": global_explain},
        "results": results,
        "severity_distribution_test_hybrid": {"counts": sev_counts, "by_truth": sev_by_truth},
        "sensitivity_sweep": {"test": sweep_test, "validation": sweep_val,
                              "random_forest_test": sweep_test_rf, "random_forest_tune": sweep_tune_rf},
        "failure_cases": failures,
        "notes": {
            "fp_per_hour": "fp_flows_per_hour = false-positive flows / capture hours of the split "
                           "(timestamps from the dataset). fp_alerts_per_hour groups flagged benign flows by "
                           "(src, dst, category, 10-min window) like the app's de-duplication.",
            "detection_delay": "minutes from first attack flow to first flagged attack flow per (day, label); "
                               "CIC-IDS2017 timestamps have 1-minute resolution on these days.",
            "risk_scale": "piecewise-linear transform of Isolation Forest score; not a probability.",
        },
        "runtime_seconds": None,
    }
    metrics["runtime_seconds"] = round(time.time() - t0, 1)
    (REPORTS / "metrics.json").write_text(json.dumps(metrics, indent=2, default=str))

    # plots
    ev.plot_confusion(results["isolation_forest"]["test"], "Isolation Forest - test (Thu+Fri)",
                      REPORTS / "confusion_isolation_forest.png")
    ev.plot_confusion(results["rule_baseline"]["test"], "Rule baseline - test (Thu+Fri)",
                      REPORTS / "confusion_rule_baseline.png")
    ev.plot_confusion(results["hybrid_if_or_rule (deployed in app)"]["test"], "Hybrid IF OR rule - test",
                      REPORTS / "confusion_hybrid.png")
    ev.plot_curves(roc, pr, auc, REPORTS / "roc_curve.png", REPORTS / "pr_curve.png", "Isolation Forest")
    ev.plot_sweep(sweep_test, REPORTS / "threshold_sweep.png", DEFAULT_THRESHOLD)
    ev.plot_hist(risk_test, yt, REPORTS / "risk_histogram.png")
    ev.plot_confusion(results["random_forest"]["test"], "Random Forest - test (Thu+Fri)",
                      REPORTS / "confusion_random_forest.png")
    ev.plot_sweep(sweep_test_rf, REPORTS / "threshold_sweep_random_forest.png", DEFAULT_THRESHOLD,
                  title="Threshold sweep - test days (RF)")
    ev.plot_pr_compare({"Isolation Forest": (pr, auc), "Random Forest": (pr_rf, auc_rf)},
                       results["rule_baseline"]["test"], REPORTS / "pr_curve_comparison.png")
    ev.plot_importance(global_explain, REPORTS / "global_importance_random_forest.png")
    print(json.dumps({k: {kk: v["test"].get(kk) for kk in ("precision", "recall", "f1", "false_positive_rate",
                                                             "fp_flows_per_hour", "fp_alerts_per_hour", "roc_auc")}
                      for k, v in results.items()}, indent=2))
    print("done in", metrics["runtime_seconds"], "s")


if __name__ == "__main__":
    main()
