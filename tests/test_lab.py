"""Attack-lab safety checks and capture scoring."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lab"))
import attack  # noqa: E402


@pytest.mark.parametrize("ip", ["8.8.8.8", "192.168.1.1", "10.66.1.10", "127.0.0.1"])
def test_attack_refuses_non_lab_targets(ip):
    with pytest.raises(SystemExit):
        attack.check_target(ip)


def test_attack_allows_lab_and_caps_rate():
    assert attack.check_target("10.66.0.10") == "10.66.0.10"
    assert attack.MAX_FLOOD_PPS <= 500 and attack.MAX_FLOOD_SECONDS <= 30
    pkt = attack._syn("10.66.0.66", "10.66.0.10", 1234, 80, 1)
    assert len(pkt) == 40 and pkt[33] == 0x02  # SYN flag


def test_compose_network_is_internal():
    text = "\n".join(ln.split("#")[0] for ln in (ROOT / "lab" / "docker-compose.yml").read_text().splitlines())
    assert "internal: true" in text and "ports:" not in text and "network_mode: host" not in text


def test_ingest_capture_scores_pcap():
    import ingest_capture
    res, df = ingest_capture.run(ROOT / "tests" / "fixtures" / "sample.pcap")
    assert res["flows"] == len(df) == 33 and "rule_baseline" in res["detectors"]
