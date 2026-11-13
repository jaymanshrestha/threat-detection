"""Pluggable ingestion adapters. Register new formats with @register_adapter."""
from abc import ABC, abstractmethod
from typing import Iterator, Tuple

import pandas as pd

from .schema import IngestReport

ADAPTERS = {}


def register_adapter(cls):
    ADAPTERS[cls.name] = cls
    return cls


def get_adapter(name: str) -> "BaseAdapter":
    if name not in ADAPTERS:
        raise KeyError(f"Unknown ingestion profile '{name}'. Available: {list(ADAPTERS)}")
    return ADAPTERS[name]()


class BaseAdapter(ABC):
    name = "base"
    description = ""
    extensions = ()

    @abstractmethod
    def iter_normalised(self, source, chunksize: int = 200_000) -> Iterator[Tuple[pd.DataFrame, IngestReport]]:
        """Yield (normalised_dataframe, report_for_chunk) pairs."""

    def load(self, source, chunksize: int = 200_000):
        frames, report = [], IngestReport()
        for df, rep in self.iter_normalised(source, chunksize=chunksize):
            frames.append(df)
            report.merge(rep)
        out = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
        return out, report
