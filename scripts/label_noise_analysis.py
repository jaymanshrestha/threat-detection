#!/usr/bin/env python
"""Supplementary analysis: how many test-day false positives come from traffic the
CIC-IDS2017 CSVs label BENIGN although the UNB attack schedule describes it as
attack activity. Headline metrics in reports/metrics.json are NOT changed.

  A) Thursday 15:04-15:45: compromised Vista host 192.168.10.8 port-scans all
     internal clients (infiltration 'second step' on the UNB dataset page).
  B) Reply-direction flows 192.168.10.50 -> 172.16.0.1 (victim web server replying
     through the firewall NAT to the attacker) during Friday attacks.
"""
import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ml.data import load_split  # noqa: E402
from ml.detectors import IsolationForestDetector, RuleDetector  # noqa: E402
from ml.detectors.isolation_forest import DEFAULT_THRESHOLD  # noqa: E402


def prf(pred, y, keep):
    tp = int((pred & y & keep).sum()); fp = int((pred & ~y & keep).sum())
    fn = int((~pred & y & keep).sum()); tn = int((~pred & ~y & keep).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "false_positive_rate": round(fp / (fp + tn), 5), "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main():
    det = IsolationForestDetector.load(ROOT / "models" / "isoforest_v1.joblib")
    rules = RuleDetector.load(ROOT / "models" / "rules_v1.json")
    te = load_split("test")
    y = (te.label != "BENIGN").to_numpy()
    a = ((te.src_ip == "192.168.10.8") & (te.day == "Thursday") & (te.observed_at.dt.hour >= 15)).to_numpy() & ~y
    b = ((te.src_ip == "192.168.10.50") & (te.dst_ip == "172.16.0.1")).to_numpy() & ~y
    keep = ~(a | b)
    if_pred = det.risk(te) >= DEFAULT_THRESHOLD
    rule_pred = rules.detect(te)["flagged"].to_numpy()
    out = {"description": __doc__.strip(), "excluded_benign_flows": {"A_vista_internal_scan": int(a.sum()),
                                                                       "B_victim_reply_flows": int(b.sum())}}
    for name, pred in (("isolation_forest", if_pred), ("rule_baseline", rule_pred),
                       ("hybrid_if_or_rule", if_pred | rule_pred)):
        fp = pred & ~y
        out[name] = {"false_positives_total": int(fp.sum()), "fp_from_A": int((fp & a).sum()),
                     "fp_from_B": int((fp & b).sum()),
                     "metrics_excluding_A_and_B": prf(pred, y, keep)}
    path = ROOT / "reports" / "label_noise_analysis.json"
    path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
