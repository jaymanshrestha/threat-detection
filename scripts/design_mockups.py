#!/usr/bin/env python
"""Capture the high-fidelity mockups for docs/design from the running app.

  python scripts/design_mockups.py --email admin@example.com --password '...' [--totp-secret BASE32] [--enrol-shot]

Signs in (password + TOTP), then saves viewport screenshots of the key screens in the
dark theme, a few in the light theme, a mobile view and the full style guide page.
"""
import argparse
import hashlib
import re
import secrets
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path

from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screenshots import fresh_code  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
W, H = 1440, 900

DARK = [  # (file, path, full_page, wait_ms)
    ("03_dashboard", "/", False, 3500),
    ("04_alerts_list", "/alerts?sort=occurrences", False, 900),
    ("05_alert_detail", "/alerts/{alert}", False, 900),
    ("06_incident_report", "/alerts/{alert}#report", False, 900),
    ("07_threat_map", "/map", False, 6000),
    ("08_models", "/models", False, 1200),
    ("09_notifications", "/notifications", False, 900),
    ("10_flagged_events", "/events", False, 900),
    ("11_data_sources", "/sources", False, 900),
    ("12_audit_log", "/audit", False, 900),
]
LIGHT = [("13_dashboard_light", "/", False, 3500), ("14_alert_detail_light", "/alerts/{alert}", False, 900)]


def wait_dashboard(pg):
    for _ in range(120):
        if pg.inner_text("#t-events").strip() not in ("-", ""):
            break
        pg.wait_for_timeout(500)


def shoot(pg, url, out, full, wait):
    pg.goto(url)
    pg.wait_for_load_state("load")
    if url.endswith("/"):
        wait_dashboard(pg)
    pg.wait_for_timeout(wait)
    if "#" in url:
        pg.locator("#" + url.split("#", 1)[1]).scroll_into_view_if_needed()
        pg.mouse.wheel(0, -60)
        pg.wait_for_timeout(500)
    pg.screenshot(path=str(out), full_page=full)
    print("saved", out.name)


PORTSCAN = "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"


def el_shot(pg, selector, out):
    loc = pg.locator(selector).first
    loc.scroll_into_view_if_needed()
    pg.wait_for_timeout(400)
    loc.screenshot(path=str(out))
    print("saved", out.name)


def demo_invite_token(db_path, email):
    """Dev-only: give the pending demo account a known invitation token so the accept page can be captured."""
    token = secrets.token_urlsafe(32)
    c = sqlite3.connect(db_path)
    row = c.execute("select id from administrators where email=?", (email,)).fetchone()
    if not row:
        return None
    c.execute("update invitations set revoked=1 where administrator_id=? and used_at is null", (row[0],))
    c.execute("insert into invitations (administrator_id, token_hash, expires_at, revoked, created_at) "
              "values (?,?,?,0,?)", (row[0], hashlib.sha256(token.encode()).hexdigest(),
                                     datetime.now() + timedelta(hours=24), datetime.now()))
    c.commit()
    return token


def v5_screens(pg, b, base, out, alert):
    """Screens added for the v5 report's use cases (UC-02, UC-03, UC-04/10, UC-05, UC-06, UC-07, UC-08)."""
    pg.on("dialog", lambda d: d.accept())
    # UC-04 / UC-10 incidents
    pg.goto(base + "/incidents")
    pg.goto(base + f"/alerts/{alert}")
    link = pg.locator('a[href^="/incidents/"]').first
    href = link.get_attribute("href")
    pg.goto(base + href)
    if "Investigating" not in pg.inner_text(".facts-grid"):
        pg.select_option("#st", "Investigating")
        pg.fill("#note", "Checking the source host with the network team.")
        pg.click("form[action$='/status'] button[type=submit]")
        pg.wait_for_load_state()
    shoot(pg, base + href, out / "21_incident_detail.png", False, 900)
    shoot(pg, base + href + "#report", out / "22_incident_report.png", False, 900)
    shoot(pg, base + "/incidents", out / "20_incidents.png", False, 900)
    # UC-02 simulator: running, then a completed run summary
    pg.goto(base + "/simulator")
    if pg.locator("#sim-progress").count() == 0:
        pg.select_option("#sim-src", pg.locator("#sim-src option", has_text=PORTSCAN).first.get_attribute("value"))
        pg.check("input[name=speed][value='10']")
        pg.select_option("#sim-filter", "PortScan")
        pg.fill("#sim-start", "14:49")
        pg.fill("#sim-end", "15:05")
        pg.click("form[action$='/simulator/start'] button[type=submit]")
        pg.wait_for_load_state()
    pg.wait_for_timeout(9000)
    pg.screenshot(path=str(out / "18_simulator_running.png"))
    print("saved 18_simulator_running.png")
    pg.click("form[action$='/stop'] button[type=submit]")
    pg.wait_for_load_state()
    pg.wait_for_timeout(4000)  # the progress poller redirects once the run has stopped
    for _ in range(3):
        try:
            pg.goto(base + "/simulator")
            break
        except Exception:
            pg.wait_for_timeout(1500)
    pg.select_option("#sim-src", pg.locator("#sim-src option", has_text=PORTSCAN).first.get_attribute("value"))
    pg.check("input[name=speed][value='100']")
    pg.fill("#sim-start", "14:49")
    pg.fill("#sim-end", "15:05")
    pg.click("form[action$='/simulator/start'] button[type=submit]")
    pg.wait_for_load_state()
    for _ in range(120):
        pg.wait_for_timeout(1000)
        if pg.locator("#sim-progress").count() == 0:
            break
    pg.wait_for_timeout(3000)  # let the poller's redirect to the summary finish
    for _ in range(3):
        try:
            shoot(pg, base + "/simulator", out / "19_simulator_summary.png", False, 900)
            break
        except Exception:
            pg.wait_for_timeout(2000)
    # UC-07 users + UC-01 A3 invitation
    pg.goto(base + "/users")
    if "new.analyst@example.com" not in pg.content():
        pg.fill("#new-email", "new.analyst@example.com")
        pg.click("form[data-confirm^='Create this account'] button[type=submit]")
        pg.wait_for_load_state()
    pg.wait_for_timeout(1200)
    pg.screenshot(path=str(out / "23_users_invite.png"))
    print("saved 23_users_invite.png")
    token = demo_invite_token(str(ROOT / "instance" / "threats.db"), "new.analyst@example.com")
    if token:
        ctx2 = b.new_context(viewport={"width": W, "height": H})
        p2 = ctx2.new_page()
        p2.goto(base + f"/invite/{token}")
        p2.fill("#password", "correct-horse-battery")
        p2.fill("#confirm", "correct-horse-battery")
        p2.wait_for_timeout(600)
        p2.screenshot(path=str(out / "24_invite_accept.png"))
        print("saved 24_invite_accept.png")
        p2.goto(base + "/invite/expired-or-used-token")
        p2.wait_for_timeout(500)
        p2.screenshot(path=str(out / "24b_invite_expired.png"))
        print("saved 24b_invite_expired.png")
        ctx2.close()
    # UC-08 upload error (E1) and data sources
    pg.goto(base + "/sources/upload/cicids2017")
    pg.set_input_files("#upload-file", files=[{"name": "printer-export.csv", "mimeType": "text/csv",
                                               "buffer": b"\x00\x01\x02 binary export"}])
    pg.click("form.stack button[type=submit]")
    pg.wait_for_load_state()
    pg.wait_for_timeout(600)
    pg.screenshot(path=str(out / "25_upload_error.png"))
    print("saved 25_upload_error.png")
    shoot(pg, base + "/sources", out / "11_data_sources.png", False, 900)
    # UC-03 layout editor + full dashboard with model panel and incident timeline
    pg.goto(base + "/")
    wait_dashboard(pg)
    pg.wait_for_timeout(2500)
    pg.screenshot(path=str(out / "27_dashboard_full.png"), full_page=True)
    print("saved 27_dashboard_full.png")
    pg.click("#layout-editor summary")
    el_shot(pg, "#layout-editor", out / "26_dashboard_layout.png")
    # UC-06 presets + preview
    pg.goto(base + "/models")
    pg.click("[data-preset='0.55']")
    el_shot(pg, "div.card:has(#sens-form)", out / "28_models_sensitivity.png")
    shoot(pg, base + "/datasets", out / "29_datasets.png", False, 900)
    pg.goto(base + "/notifications")
    el_shot(pg, "#sms", out / "30_notifications_sms.png")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--totp-secret")
    ap.add_argument("--alert", default="334", help="alert id with an incident report")
    ap.add_argument("--out", default=str(ROOT / "docs" / "design" / "mockups"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    base = args.url.rstrip("/")
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": W, "height": H}, device_scale_factor=1)
        pg = ctx.new_page()
        pg.goto(base + "/login")
        pg.fill("#email", args.email)
        pg.fill("#password", args.password)
        pg.wait_for_timeout(900)
        pg.screenshot(path=str(out / "01_login.png"))
        pg.click("button[type=submit]")
        pg.wait_for_load_state()
        secret = args.totp_secret
        pg.wait_for_timeout(900)
        if "/mfa/enrol" in pg.url:
            secret = re.search(r"[A-Z2-7]{16,}", pg.inner_text("code")).group(0)
            pg.screenshot(path=str(out / "02b_mfa_enrol.png"))
            print("ENROLLED_TOTP_SECRET", secret)
        else:
            pg.fill("#code", "123")
            pg.screenshot(path=str(out / "02_mfa_verify.png"))
        pg.fill("#code", fresh_code(secret))
        pg.click("button[type=submit]")
        pg.wait_for_load_state()
        if pg.url.rstrip("/") != base:
            sys.exit(f"login failed at {pg.url}")
        for name, path, full, wait in DARK:
            shoot(pg, base + path.format(alert=args.alert), out / f"{name}.png", full, wait)
        v5_screens(pg, b, base, out, args.alert)
        shoot(pg, base + "/style-guide", out / "15_style_guide_full.png", True, 900)
        sg = out.parent / "styleguide"
        sg.mkdir(exist_ok=True)
        for sec in ["sg-palette", "sg-contrast", "sg-type", "sg-spacing", "sg-buttons", "sg-badges", "sg-forms", "sg-cards", "sg-icons", "sg-rules"]:
            pg.locator("#" + sec).screenshot(path=str(sg / f"{sec}.png"))
        print("saved style guide sections")
        pg.click("#theme-btn")  # stored in localStorage for the rest of the session
        for name, path, full, wait in LIGHT:
            shoot(pg, base + path.format(alert=args.alert), out / f"{name}.png", full, wait)
        shoot(pg, base + "/style-guide", out / "16_style_guide_light_full.png", True, 900)
        pg.click("#theme-btn")
        pg.set_viewport_size({"width": 390, "height": 844})
        shoot(pg, base + "/", out / "17_dashboard_mobile.png", False, 3000)
        b.close()


if __name__ == "__main__":
    main()
