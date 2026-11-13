#!/usr/bin/env python
"""Replay simulator (near-real-time fallback, FR-05).

Streams held-out CIC-IDS2017 test-day CSV rows into the running app through the
same ingestion API used by live sources, in timestamp order, one dataset-minute
per batch. Events are stored with is_simulated=True and labelled SIMULATED.

Example (Friday afternoon port scan, 30x real time):
  python scripts/replay.py --file Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv \
      --start 14:49 --end 15:05 --speed 30
"""
import argparse
import os
import sys
import time
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from ingest.validate import parse_timestamps  # noqa: E402
from ml.data import FILES, RAW_DIR, SPLIT  # noqa: E402

TEST_FILES = [f for d in SPLIT["test"] for f in FILES[d]]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                    help="test-day CSV in data/raw/TrafficLabelling (held out from training)")
    ap.add_argument("--start", default="14:49", help="dataset time HH:MM to start from")
    ap.add_argument("--end", default="15:05", help="dataset time HH:MM to stop at (inclusive minute)")
    ap.add_argument("--speed", type=float, default=30.0, help="replay speed multiplier (1 = real time)")
    ap.add_argument("--attack-filter", default=None, help="only replay BENIGN + this attack label")
    ap.add_argument("--max-rows-per-minute", type=int, default=0, help="0 = no cap (keeps window stats faithful)")
    ap.add_argument("--url", default=os.getenv("APP_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--api-key", default=os.getenv("INGEST_API_KEY", "dev-ingest-key"))
    args = ap.parse_args()

    if args.file not in TEST_FILES:
        sys.exit(f"Refusing to replay {args.file}: only held-out test-day files may be replayed: {TEST_FILES}")
    path = RAW_DIR / args.file
    lines = path.read_text(encoding="latin-1").splitlines()
    header, body = lines[0], [l for l in lines[1:] if l.strip(", ")]
    ts = parse_timestamps(pd.Series([l.split(",")[6] for l in body]), twelve_hour_fix=True)
    df = pd.DataFrame({"line": body, "ts": ts, "label": [l.rsplit(",", 1)[-1].strip() for l in body]}).dropna()
    day = df.ts.dt.normalize().iloc[0]
    start = day + pd.Timedelta(args.start + ":00")
    end = day + pd.Timedelta(args.end + ":00") + pd.Timedelta(minutes=1)
    df = df[(df.ts >= start) & (df.ts < end)]
    if args.attack_filter:
        df = df[df.label.isin(["BENIGN", args.attack_filter])]
    df = df.sort_values("ts", kind="stable")
    if df.empty:
        sys.exit("No rows in the selected window.")
    print(f"Replaying {len(df):,} flows from {args.file} {start:%H:%M}-{end:%H:%M} at {args.speed}x "
          f"({df.label.value_counts().to_dict()})")

    s = requests.Session()
    s.headers["X-API-Key"] = args.api_key
    r = s.post(f"{args.url}/api/v1/replay/start", json={"file": args.file, "speed": args.speed,
                                                         "attack_filter": args.attack_filter, "force": True})
    r.raise_for_status()
    run_id = r.json()["run_id"]
    status = "Completed"
    try:
        for minute, g in df.groupby(df.ts.dt.floor("min"), sort=True):
            t0 = time.time()
            if args.max_rows_per_minute and len(g) > args.max_rows_per_minute:
                g = g.iloc[:: max(1, len(g) // args.max_rows_per_minute)]
            payload = (header + "\n" + "\n".join(g.line) + "\n").encode("latin-1")
            resp = s.post(f"{args.url}/api/v1/ingest", params={"run_id": run_id, "filename": args.file},
                          data=payload, headers={"Content-Type": "text/csv"}, timeout=300)
            resp.raise_for_status()
            j = resp.json()
            took = time.time() - t0
            print(f"[{minute:%H:%M}] sent {len(g):>6,} accepted {j['accepted']:>6,} rejected {j['rejected']:>3} "
                  f"flagged {j['flagged']:>6,} new alerts {j['alerts_new']:>3} ({took:.1f}s)", flush=True)
            time.sleep(max(0.0, 60.0 / args.speed - took))
    except KeyboardInterrupt:
        status = "Stopped"
    finally:
        r = s.post(f"{args.url}/api/v1/replay/{run_id}/finish", json={"status": status})
        print("Run finished:", r.json())


if __name__ == "__main__":
    main()
