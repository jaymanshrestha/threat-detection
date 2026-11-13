"""Causal per-source sliding-window statistics (FR-03 'derived rates and
per-source destination-port diversity over explicitly defined windows').

Window = the 60-second (calendar minute) bucket of the flow timestamp; CIC-IDS2017
timestamps have one-minute resolution on most days, so a finer window is not
meaningful. Counts are *causal*: each flow only sees flows that arrived before it
(in arrival order) in the same bucket, so batch evaluation and live replay see
exactly the same values.
"""
from collections import OrderedDict

import numpy as np
import pandas as pd

WINDOW_FEATURES = ["src_flows_in_window", "src_distinct_dports_in_window", "src_dst_flows_in_window"]


class WindowState:
    def __init__(self, keep_buckets: int = 5):
        self.keep_buckets = keep_buckets
        self.buckets = OrderedDict()  # minute -> {"src": {ip: [count, set(ports)]}, "pair": {(s,d): count}}

    def _bucket(self, minute):
        b = self.buckets.get(minute)
        if b is None:
            b = {"src": {}, "pair": {}}
            self.buckets[minute] = b
            while len(self.buckets) > self.keep_buckets:
                self.buckets.popitem(last=False)
        return b

    def update(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return a DataFrame of window features aligned with df (arrival order)."""
        minutes = df["observed_at"].dt.floor("min").to_numpy()
        srcs = df["src_ip"].to_numpy()
        dsts = df["dst_ip"].to_numpy()
        ports = df["dst_port"].to_numpy()
        n = len(df)
        a = np.empty(n, dtype=np.float32)
        b_ = np.empty(n, dtype=np.float32)
        c = np.empty(n, dtype=np.float32)
        for i in range(n):
            bk = self._bucket(minutes[i])
            st = bk["src"].get(srcs[i])
            if st is None:
                st = [0, set()]
                bk["src"][srcs[i]] = st
            st[0] += 1
            st[1].add(ports[i])
            key = (srcs[i], dsts[i])
            bk["pair"][key] = bk["pair"].get(key, 0) + 1
            a[i], b_[i], c[i] = st[0], len(st[1]), bk["pair"][key]
        return pd.DataFrame(
            {WINDOW_FEATURES[0]: a, WINDOW_FEATURES[1]: b_, WINDOW_FEATURES[2]: c}, index=df.index
        )


def add_window_features(df: pd.DataFrame, state: WindowState = None) -> pd.DataFrame:
    state = state or WindowState()
    w = state.update(df)
    return pd.concat([df, w], axis=1)
