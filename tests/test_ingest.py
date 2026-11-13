"""Ingestion: schema mapping, validation and rejection counting (real CIC-IDS2017 rows)."""
import io

from ingest import get_adapter
from ingest.validate import parse_timestamps
from ingest.windows import add_window_features
from tests.conftest import FIXTURE

import pandas as pd


def test_parses_real_sample():
    df, rep = get_adapter("cicids2017").load(FIXTURE)
    assert rep.total_rows == 200 and rep.accepted + rep.rejected == 200
    assert {"src_ip", "dst_ip", "dst_port", "protocol", "observed_at", "flow_duration", "label"} <= set(df.columns)
    assert set(df.label) == {"BENIGN", "PortScan"}
    assert df.protocol.isin(["TCP", "UDP", "ICMP", "HOPOPT"]).all()
    # 12-hour clock fix: afternoon capture must land in 13:00-17:59
    assert df.observed_at.dt.hour.between(13, 17).all()


def test_invalid_rows_are_counted_not_dropped_silently():
    text = FIXTURE.read_text(encoding="latin-1").splitlines()
    header, rows = text[0], text[1:6]
    parts = rows[0].split(","); parts[1] = "999.1.1.1"; bad = [",".join(parts)]  # invalid source IP
    parts = rows[1].split(","); parts[4] = "70000"; bad.append(",".join(parts))  # port out of range
    parts = rows[2].split(","); parts[6] = "not-a-date"; bad.append(",".join(parts))
    parts = rows[3].split(","); parts[7] = "-5"; bad.append(",".join(parts))  # negative duration
    data = "\n".join([header] + bad + [rows[4]]).encode("latin-1")
    df, rep = get_adapter("cicids2017").load(io.BytesIO(data))
    assert rep.accepted == 1 and rep.rejected == 4
    assert rep.reasons == {"invalid_ip": 1, "invalid_port": 1, "bad_timestamp": 1, "negative_value": 1}


def test_missing_columns_rejected():
    df, rep = get_adapter("cicids2017").load(io.BytesIO(b"a,b,c\n1,2,3\n"))
    assert df.empty and "Source IP" in rep.missing_columns


def test_timestamp_formats():
    ts = parse_timestamps(pd.Series(["03/07/2017 08:55:58", "7/7/2017 3:30", "6/7/2017 12:59"]), twelve_hour_fix=True)
    assert [t.strftime("%H:%M") for t in ts] == ["08:55", "15:30", "12:59"]


def test_window_features_are_causal():
    df = pd.DataFrame({"observed_at": pd.to_datetime(["2017-07-07 10:00:01"] * 3 + ["2017-07-07 10:01:00"]),
                       "src_ip": ["a", "a", "a", "a"], "dst_ip": ["b", "b", "c", "b"], "dst_port": [1, 2, 2, 3]})
    w = add_window_features(df)
    assert w.src_flows_in_window.tolist() == [1, 2, 3, 1]
    assert w.src_distinct_dports_in_window.tolist() == [1, 2, 2, 1]
    assert w.src_dst_flows_in_window.tolist() == [1, 2, 1, 1]
