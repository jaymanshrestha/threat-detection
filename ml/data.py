"""Dataset loading + day-based (capture-session) split for CIC-IDS2017."""
import json
from pathlib import Path

import pandas as pd

try:  # parquet is faster/smaller, but pyarrow may lack wheels on new Pythons (e.g. 3.15 on Windows)
    import pyarrow  # noqa: F401
    _EXT = ".parquet"
except ImportError:  # pragma: no cover - depends on platform
    _EXT = ".pkl"


def _read(path):
    return pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_pickle(path)


def _write(df, path):
    df.to_parquet(path, index=False) if path.suffix == ".parquet" else df.to_pickle(path)

from ingest import get_adapter
from ingest.windows import add_window_features

BASE = Path(__file__).resolve().parent.parent
RAW_DIR = BASE / "data" / "raw" / "TrafficLabelling"
CACHE_DIR = BASE / "data" / "processed"

FILES = {
    "Monday": ["Monday-WorkingHours.pcap_ISCX.csv"],
    "Tuesday": ["Tuesday-WorkingHours.pcap_ISCX.csv"],
    "Wednesday": ["Wednesday-workingHours.pcap_ISCX.csv"],
    "Thursday": ["Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                 "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"],
    "Friday": ["Friday-WorkingHours-Morning.pcap_ISCX.csv",
               "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
               "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"],
}
# Whole capture days are assigned to one split -> no attack session spans splits.
SPLIT = {"train": ["Monday"], "validation": ["Tuesday", "Wednesday"], "test": ["Thursday", "Friday"]}


def load_file(fname: str, use_cache=True):
    cache = CACHE_DIR / (fname.replace(".csv", _EXT))
    rep_file = cache.with_suffix(".ingest.json")
    if use_cache and cache.exists() and rep_file.exists():
        return _read(cache), json.loads(rep_file.read_text())
    df, rep = get_adapter("cicids2017").load(RAW_DIR / fname)
    # arrival order = timestamp order (stable keeps file order inside a minute)
    df = df.sort_values("observed_at", kind="stable").reset_index(drop=True)
    df = add_window_features(df)
    df["source_file"] = fname
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _write(df, cache)
    rep_file.write_text(json.dumps(rep.as_dict(), indent=2))
    return df, rep.as_dict()


def load_day(day: str, use_cache=True):
    frames, reports = [], {}
    for f in FILES[day]:
        df, rep = load_file(f, use_cache)
        df["day"] = day
        frames.append(df)
        reports[f] = rep
    return pd.concat(frames, ignore_index=True), reports


def load_split(name: str):
    frames = [load_day(d)[0] for d in SPLIT[name]]
    return pd.concat(frames, ignore_index=True)
