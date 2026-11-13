"""Internal (normalised) network-event schema shared by every ingestion adapter.

Each adapter (CSV profile, future Syslog / NetFlow / .pcap) maps its own input
columns onto these names, so the detectors never see source-specific columns.
"""
from dataclasses import dataclass, field

# Identity / context fields (validated strictly, never fed to the models raw)
IDENTITY_FIELDS = [
    "observed_at",  # pandas Timestamp (naive, dataset local time)
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",  # "TCP" | "UDP" | "ICMP" | "OTHER(<n>)"
]

# Flow statistics available to detectors (internal snake_case names)
FLOW_FEATURES = [
    "flow_duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_pkt_len_max",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "fwd_iat_total",
    "bwd_iat_total",
    "fwd_packets_per_s",
    "bwd_packets_per_s",
    "pkt_len_mean",
    "pkt_len_std",
    "fin_flags",
    "syn_flags",
    "rst_flags",
    "psh_flags",
    "ack_flags",
    "urg_flags",
    "down_up_ratio",
    "avg_packet_size",
    "init_win_fwd",
    "init_win_bwd",
    "act_data_pkt_fwd",
    "active_mean",
    "idle_mean",
]

# Fields where -1 is a documented "not observed" sentinel in CICFlowMeter output
SENTINEL_MINUS_ONE = {"init_win_fwd", "init_win_bwd"}

# Optional ground-truth label (public datasets only; never used for scoring)
LABEL_FIELD = "label"


@dataclass
class IngestReport:
    """Accepted / rejected counts with reasons (FR-03: never silently dropped)."""

    total_rows: int = 0
    accepted: int = 0
    rejected: int = 0
    reasons: dict = field(default_factory=dict)
    missing_columns: list = field(default_factory=list)

    def add_rejects(self, reason: str, n: int):
        if n:
            self.rejected += int(n)
            self.reasons[reason] = self.reasons.get(reason, 0) + int(n)

    def merge(self, other: "IngestReport"):
        self.total_rows += other.total_rows
        self.accepted += other.accepted
        self.rejected += other.rejected
        for k, v in other.reasons.items():
            self.reasons[k] = self.reasons.get(k, 0) + v
        for c in other.missing_columns:
            if c not in self.missing_columns:
                self.missing_columns.append(c)

    def as_dict(self):
        return {
            "total_rows": self.total_rows,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "reasons": dict(self.reasons),
            "missing_columns": list(self.missing_columns),
        }
