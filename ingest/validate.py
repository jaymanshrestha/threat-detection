"""Vectorised record validation helpers (FR-03)."""
import ipaddress
from functools import lru_cache

import numpy as np
import pandas as pd

PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "HOPOPT"}


@lru_cache(maxsize=200_000)
def _ip_ok(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def valid_ip(series: pd.Series) -> pd.Series:
    s = series.astype(str).str.strip()
    uniq = {v: _ip_ok(v) for v in s.unique()}
    return s.map(uniq).astype(bool)


def valid_port(series: pd.Series) -> pd.Series:
    num = pd.to_numeric(series, errors="coerce")
    return num.notna() & (num >= 0) & (num <= 65535) & (num == np.floor(num))


def protocol_name(series: pd.Series) -> pd.Series:
    num = pd.to_numeric(series, errors="coerce")
    return num.map(lambda n: PROTOCOLS.get(int(n), f"OTHER({int(n)})") if pd.notna(n) else None)


def parse_timestamps(series: pd.Series, twelve_hour_fix: bool = False) -> pd.Series:
    """Parse 'd/m/Y H:M[:S]'. CIC-IDS2017 GeneratedLabelledFlows writes afternoon
    times on a 12-hour clock without AM/PM (e.g. '3:30' = 15:30). The capture ran
    only during working hours (~08:30-17:10), so hours 1-7 are shifted by +12."""
    s = series.astype(str).str.strip()
    ts = pd.to_datetime(s, format="%d/%m/%Y %H:%M:%S", errors="coerce")
    missing = ts.isna()
    if missing.any():
        ts.loc[missing] = pd.to_datetime(s[missing], format="%d/%m/%Y %H:%M", errors="coerce")
    missing = ts.isna()
    if missing.any():  # ISO fallback for other CSV sources
        ts.loc[missing] = pd.to_datetime(s[missing], errors="coerce", format="ISO8601")
    if twelve_hour_fix:
        shift = ts.notna() & (ts.dt.hour < 8)
        ts.loc[shift] = ts.loc[shift] + pd.Timedelta(hours=12)
    return ts
