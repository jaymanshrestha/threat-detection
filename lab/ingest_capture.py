"""Ingest a lab capture through the pcap adapter and show what each detector flags.

    python lab/ingest_capture.py                                   # newest capture in lab/captures
    python lab/ingest_capture.py lab/captures/lab.pcap             # Docker lab output
    python lab/ingest_capture.py --api http://127.0.0.1:5000       # also send it to the running app
                                                                   # (uses INGEST_API_KEY from the environment)
Ground truth comes from the attack phase timestamps written by lab/attack.py: a flow is
labelled with the phase (scan / flood) whose time window contains it if it involves the
attacker; everything else is benign.
"""
import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from ingest import get_adapter  # noqa: E402
from ingest.windows import WindowState  # noqa: E402
from ml.detectors import IsolationForestDetector, RandomForestDetector, RuleDetector  # noqa: E402

CAP = ROOT / "lab" / "captures"


def label(df, phases_file):
    lab = np.array(["benign"] * len(df), dtype=object)
    if not phases_file or not Path(phases_file).exists():
        return lab, None
    ph = json.loads(Path(phases_file).read_text())
    att = ph.get("attacker")
    ts = np.array([t.to_pydatetime().timestamp() for t in df["observed_at"]])  # naive local time
    involved = ((df["src_ip"] == att) | (df["dst_ip"] == att)).to_numpy()
    for p in ph["phases"]:
        if p["phase"] in ("scan", "flood"):
            m = involved & (ts >= p["start"] - 0.5) & (ts <= p["end"] + 1.0)
            lab[m] = p["phase"]
    return lab, ph


def run(pcap, phases=None, threshold=0.70):
    data = Path(pcap).read_bytes()
    df, rep = get_adapter("pcap").load(data)
    if df.empty:
        sys.exit(f"no flows parsed from {pcap}: {rep.missing_columns or rep.reasons}")
    df = df.sort_values("observed_at", kind="stable").reset_index(drop=True)
    df = pd.concat([df, WindowState().update(df)], axis=1)
    lab, ph = label(df, phases)
    out = {"pcap": str(Path(pcap).relative_to(ROOT)) if str(pcap).startswith(str(ROOT)) else str(pcap),
           "flows": int(len(df)), "packet_stats": rep.reasons, "labels": pd.Series(lab).value_counts().to_dict(),
           "lab_mode": (ph or {}).get("mode") or ("Docker Compose lab (internal: true network; nmap + hping3)"
                                                 if phases and Path(phases).name == "attack_phases.json" else "unknown"), "detectors": {}}
    dets = {"rule_baseline": RuleDetector.load(ROOT / "models" / "rules_v1.json")}
    if (ROOT / "models" / "isoforest_v1.joblib").exists():
        dets["isolation_forest"] = IsolationForestDetector.load(ROOT / "models" / "isoforest_v1.joblib")
    if (ROOT / "models" / "random_forest_v1.joblib").exists():
        dets["random_forest"] = RandomForestDetector.load(ROOT / "models" / "random_forest_v1.joblib")
    flags = {}
    for name, d in dets.items():
        r = d.detect(df, threshold=threshold)
        f = r["flagged"].to_numpy()
        flags[name] = f
        per = {}
        for ph_name in sorted(set(lab)):
            m = lab == ph_name
            per[ph_name] = {"flows": int(m.sum()), "flagged": int(f[m].sum()), "rate": round(float(f[m].mean()), 4)}
        attack = lab != "benign"
        tp, fp = int((f & attack).sum()), int((f & ~attack).sum())
        out["detectors"][name] = {"per_phase": per, "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                                  "recall": round(tp / attack.sum(), 4) if attack.sum() else None,
                                  "categories": pd.Series(r["category"][f]).value_counts().to_dict()}
        if name == "random_forest" and f.any():
            i = int(np.flatnonzero(f)[np.argmax(r["risk"].to_numpy()[f])])
            out["detectors"][name]["example_explanation"] = r["explanation"].iat[i]
    hyb = flags.get("isolation_forest", 0) | flags["rule_baseline"]
    attack = lab != "benign"
    out["detectors"]["hybrid_if_or_rule"] = {
        "per_phase": {p: {"flows": int((lab == p).sum()), "flagged": int(hyb[lab == p].sum())} for p in sorted(set(lab))},
        "recall": round(float(hyb[attack].mean()), 4) if attack.any() else None}
    return out, df


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--phases", help="attack phases JSON (default: next to the capture)")
    ap.add_argument("--api", help="base URL of the running app to POST the capture to")
    ap.add_argument("--out", default=str(ROOT / "lab" / "results" / "lab_results.json"))
    a = ap.parse_args()
    pcap = Path(a.pcap) if a.pcap else max(CAP.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
    phases = a.phases or next((str(p) for p in (pcap.with_name(pcap.stem + "_phases.json"),
                                                pcap.with_name("attack_phases.json")) if p.exists()), None)
    res, _ = run(pcap, phases)
    if a.api:
        req = urllib.request.Request(f"{a.api.rstrip('/')}/api/v1/ingest?profile=pcap&filename={pcap.name}",
                                     data=pcap.read_bytes(), method="POST",
                                     headers={"X-API-Key": os.environ.get("INGEST_API_KEY", "dev-ingest-key"),
                                              "Content-Type": "application/vnd.tcpdump.pcap"})
        with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 - local app URL given by the user
            res["app_ingest"] = json.loads(r.read())
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(res, indent=2, default=str))
    print(f"capture: {res['pcap']}  flows: {res['flows']}  labels: {res['labels']}  mode: {res['lab_mode']}")
    for name, d in res["detectors"].items():
        per = ", ".join(f"{k}: {v['flagged']}/{v['flows']}" for k, v in d["per_phase"].items())
        print(f"  {name:20s} {per}   precision={d.get('precision')} recall={d.get('recall')}")
    if "app_ingest" in res:
        print("  sent to app:", res["app_ingest"])
    print(f"results written to {a.out}")


if __name__ == "__main__":
    main()
