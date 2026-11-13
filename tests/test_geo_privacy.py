"""Offline GeoIP lookup, threat-map API/page, IP display modes."""
from datetime import datetime

import pytest

from app import geo
from app import settings as app_settings
from app.extensions import db
from app.models import SecurityAlert
from app.privacy import display, is_internal, pseudonym, truncate
from tests.mmdb_writer import write_mmdb
from tests.test_pages import _login

REC = {"city": {"names": {"en": "Testville"}}, "country": {"iso_code": "US", "names": {"en": "United States"}},
       "location": {"latitude": 37.5, "longitude": -122.25}}


@pytest.fixture
def mmdb(tmp_path):
    p = tmp_path / "test-city.mmdb"
    write_mmdb(p, "8.8.8.0/24", REC)
    geo.reset_readers()
    yield p
    geo.reset_readers()


def test_builtin_reader_and_maxminddb_agree(mmdb):
    r = geo.MiniMMDBReader(mmdb)
    assert r.get("8.8.8.8") == REC and r.get("9.9.9.9") is None and r.get("8.8.9.1") is None
    maxminddb = pytest.importorskip("maxminddb")
    assert maxminddb.open_database(str(mmdb), mode=maxminddb.MODE_FILE).get("8.8.8.8") == REC


def test_locate_internal_and_public(mmdb):
    site = {"name": "HQ", "lat": -37.8, "lon": 144.9}
    assert geo.locate("192.168.10.5", mmdb, site) == {"lat": -37.8, "lon": 144.9, "city": "Internal network",
                                                      "site": "HQ", "country": None, "country_code": None,
                                                      "internal": True}  # UC-03 A4 wording
    g = geo.locate("8.8.8.8", mmdb, site)
    assert g["city"] == "Testville" and g["country_code"] == "US" and not g["internal"]
    assert geo.locate("1.2.3.4", mmdb, site) is None
    assert geo.locate("8.8.8.8", mmdb.with_name("missing.mmdb"), site) is None


def test_ip_privacy_modes(app):
    assert truncate("192.168.10.77") == "192.168.10.x"
    assert truncate("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert display("10.0.0.1", "full") == "10.0.0.1"
    h = display("10.0.0.1", "hash")
    assert h.startswith("ip-") and h == pseudonym("10.0.0.1") and h != pseudonym("10.0.0.2")
    assert "10.0.0.1" not in h
    assert is_internal("10.1.1.1") and is_internal("127.0.0.1") and not is_internal("8.8.8.8")


def test_map_page_geo_api_and_display_mode(client, app, mmdb):
    app.config.update(GEOIP_DB=str(mmdb), SITE_NAME="HQ", SITE_LAT=-37.8, SITE_LON=144.9)
    _login(client)
    now = datetime.now()
    db.session.add_all([
        SecurityAlert(src_ip="8.8.8.8", dst_ip="192.168.10.50", category="Port Scan", severity="Critical",
                      max_risk=0.95, occurrence_count=40, first_seen=now, last_seen=now),
        SecurityAlert(src_ip="1.2.3.4", dst_ip="192.168.10.50", category="Port Scan", severity="High",
                      max_risk=0.85, occurrence_count=3, first_seen=now, last_seen=now)])
    db.session.commit()
    r = client.get("/map")
    assert r.status_code == 200 and b"leaflet.js" in r.data and b"DB-IP" in r.data
    assert "img-src 'self' data:" in r.headers["Content-Security-Policy"]
    d = client.get("/api/geo").json
    assert len(d["lines"]) == 1 and d["lines"][0]["severity"] == "Critical" and d["unknown_locations"] == 1
    pts = {p["ip"]: p for p in d["points"]}
    assert pts["8.8.8.8"]["place"] == "Testville, United States" and pts["192.168.10.50"]["internal"]
    assert client.get("/api/geo?severity=High").json["lines"] == []
    # switch to truncated display via the audited settings form
    r = client.post("/settings/privacy", data={"ip_display_mode": "truncate", "llm_ip_mode": "hash",
                                               "csrf_token": ""})
    assert r.status_code in (302, 400)
    app_settings.put("ip_display_mode", "truncate")
    d = client.get("/api/geo").json
    assert {p["ip"] for p in d["points"]} >= {"8.8.8.x", "192.168.10.x"}
    s = client.get("/api/summary").json
    assert all("x" in a["src"] for a in s["recent_alerts"])
    assert b"8.8.8.8" not in client.get("/alerts").data
