"""Transparent rule-based baseline (proposal FR-04 core).

R1 Port scan : one source contacts >= PORTSCAN_PORTS distinct destination ports
               within the 60 s window.
R2 DoS/flood : one source opens >= FLOOD_FLOWS flows to one destination within
               the 60 s window.
Thresholds are calibrated on the benign-only training day (Monday):
ceil(1.1 x the maximum value observed in benign traffic)."""
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd

from .base import Detector

PORT_SCAN = "Port Scan"
DOS = "DoS / Flood"


class RuleDetector(Detector):
    name = "Rule baseline"
    detector_type = "Rule-based"

    def __init__(self, portscan_ports=731, flood_flows=891, version="v1"):
        self.portscan_ports = int(portscan_ports)
        self.flood_flows = int(flood_flows)
        self.version = version

    @classmethod
    def calibrate(cls, benign_df: pd.DataFrame, margin=1.1):
        return cls(
            portscan_ports=math.ceil(margin * benign_df["src_distinct_dports_in_window"].max()),
            flood_flows=math.ceil(margin * benign_df["src_dst_flows_in_window"].max()),
        )

    def detect(self, df: pd.DataFrame, threshold: float = None) -> pd.DataFrame:
        ps = df["src_distinct_dports_in_window"].to_numpy() >= self.portscan_ports
        fl = df["src_dst_flows_in_window"].to_numpy() >= self.flood_flows
        flagged = ps | fl
        cat = np.where(ps, PORT_SCAN, np.where(fl, DOS, ""))
        expl = [None] * len(df)
        dports = df["src_distinct_dports_in_window"].to_numpy()
        flows = df["src_dst_flows_in_window"].to_numpy()
        for i in np.flatnonzero(flagged):
            if ps[i]:
                expl[i] = [{"feature": "destination-port variety from source (60s)", "value": float(dports[i]),
                            "rule": f">= {self.portscan_ports}", "method": "rule R1"}]
            else:
                expl[i] = [{"feature": "flows source->destination (60s)", "value": float(flows[i]),
                            "rule": f">= {self.flood_flows}", "method": "rule R2"}]
        return pd.DataFrame(
            {"risk": flagged.astype(float), "flagged": flagged, "category": cat, "explanation": expl},
            index=df.index,
        )

    def to_dict(self):
        return {"portscan_ports": self.portscan_ports, "flood_flows": self.flood_flows, "version": self.version}

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path):
        return cls(**json.loads(Path(path).read_text()))
