"""Detector plug-in interface. Each detector returns a DataFrame aligned with the
input events: risk (0-1), flagged (bool), category (str), explanation (list)."""
from abc import ABC, abstractmethod

import pandas as pd

UNCLASSIFIED = "Anomaly - unclassified"


class Detector(ABC):
    name: str = "detector"
    version: str = "v0"
    detector_type: str = "Unsupervised"  # or "Rule-based" / "Supervised"

    @property
    def model_version(self) -> str:
        return f"{self.name} {self.version}"

    @abstractmethod
    def detect(self, df: pd.DataFrame, threshold: float = None) -> pd.DataFrame:
        ...
