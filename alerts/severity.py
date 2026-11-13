"""Severity classification (proposal FR-07).

Critical : risk >= 0.90, or a rule identifies a denial-of-service flood
High     : 0.80 <= risk < 0.90
Medium   : sensitivity threshold <= risk < 0.80
Low      : flagged by the rule-based baseline only (risk below threshold)
"""
SEVERITIES = ["Low", "Medium", "High", "Critical"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
DOS_CATEGORY = "DoS / Flood"


def classify(risk: float, threshold: float, rule_category: str = "") -> str:
    if risk >= 0.90 or rule_category == DOS_CATEGORY:
        return "Critical"
    if risk >= 0.80:
        return "High"
    if risk >= threshold:
        return "Medium"
    if rule_category:
        return "Low"
    return ""


def at_least(severity: str, minimum: str) -> bool:
    return RANK.get(severity, -1) >= RANK.get(minimum, 99)
