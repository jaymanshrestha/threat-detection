#!/usr/bin/env python
"""Download CIC-IDS2017 GeneratedLabelledFlows (TrafficLabelling CSVs, ~284 MB zip).

Primary: Hugging Face mirror of the official CIC distribution (the UNB
cicresearch.ca download server returned HTTP 500 when this project was built).
You can also download GeneratedLabelledFlows.zip manually from
https://www.unb.ca/cic/datasets/ids-2017.html and pass --zip path/to/file.zip.
Cite: Sharafaldin, Lashkari & Ghorbani, ICISSP 2018.
"""
import argparse
import hashlib
import shutil
import sys
import zipfile
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
URLS = [
    "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/811c007f08d693a8a8b4226c197c138391806ce6/csvs/GeneratedLabelledFlows.zip",
    "http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/CSVs/GeneratedLabelledFlows.zip",
]
SHA256 = "7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a"  # file used for reported results


def download(url, dest):
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        done = 0
        with open(dest, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r  {done / 1e6:7.1f} / {total / 1e6:.1f} MB", end="", flush=True)
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", help="use an already downloaded GeneratedLabelledFlows.zip")
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    z = Path(args.zip) if args.zip else RAW / "GeneratedLabelledFlows.zip"
    if not z.exists():
        for url in URLS:
            try:
                print("Downloading", url)
                download(url, z)
                break
            except Exception as e:  # noqa: BLE001
                print("  failed:", e)
        else:
            sys.exit("All download URLs failed; download manually from the UNB page.")
    h = hashlib.sha256(z.read_bytes()).hexdigest()
    print("sha256", h, "(matches reported run)" if h == SHA256 else "(differs from reported run!)")
    # Extract file by file, stripping the trailing space the official zip has in
    # its folder name ("TrafficLabelling "). Windows can't handle that name, so we
    # never create it on disk.
    target = RAW / "TrafficLabelling"
    target.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(z) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".csv"):
                continue
            name = Path(info.filename.replace("\\", "/")).name.strip()
            print("  extracting", name)
            with zf.open(info) as src, open(target / name, "wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
    print("CSV files:", sorted(p.name for p in (RAW / "TrafficLabelling").glob("*.csv")))


if __name__ == "__main__":
    main()
