#!/usr/bin/env python
"""Download the free DB-IP "IP to City Lite" database (MMDB, CC BY 4.0, no licence key).

Attribution required: "IP Geolocation by DB-IP" (https://db-ip.com). Saved to
data/geo/dbip-city-lite.mmdb (~130 MB, not shipped in the zip).
Usage:  python scripts/download_geoip.py [--month YYYY-MM]
"""
import argparse
import datetime as dt
import gzip
import shutil
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / "data" / "geo" / "dbip-city-lite.mmdb"


def candidates(month):
    if month:
        yield month
        return
    d = dt.date.today().replace(day=1)
    for _ in range(3):  # this month, then the two previous ones
        yield d.strftime("%Y-%m")
        d = (d - dt.timedelta(days=1)).replace(day=1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--month")
    args = ap.parse_args()
    DEST.parent.mkdir(parents=True, exist_ok=True)
    gz = DEST.with_suffix(".mmdb.gz")
    for m in candidates(args.month):
        url = f"https://download.db-ip.com/free/dbip-city-lite-{m}.mmdb.gz"
        print("Downloading", url)
        try:
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with open(gz, "wb") as f:
                    for chunk in r.iter_content(1 << 20):
                        f.write(chunk)
            break
        except Exception as e:  # noqa: BLE001
            print("  failed:", e)
    else:
        sys.exit("Download failed. Get the 'IP to City Lite' MMDB manually from https://db-ip.com/db/download/ip-to-city-lite")
    with gzip.open(gz, "rb") as src, open(DEST, "wb") as dst:
        shutil.copyfileobj(src, dst)
    gz.unlink()
    print("Saved", DEST, f"({DEST.stat().st_size / 1e6:.0f} MB). Attribution: IP Geolocation by DB-IP (CC BY 4.0)")


if __name__ == "__main__":
    main()
