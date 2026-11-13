#!/usr/bin/env python
"""Log in with password + TOTP (enrolling MFA on first run) using headless
Chromium and save screenshots of the main pages. Demo/verification helper.

  python scripts/screenshots.py --email admin@example.com --password '...' [--totp-secret BASE32]
"""
import argparse
import re
import sys
import time
from pathlib import Path

import pyotp
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
PAGES = [("01_overview", "/"), ("02_flagged_events", "/events"), ("03_alerts", "/alerts"),
         ("05_models", "/models"), ("06_data_sources", "/sources"), ("07_datasets", "/datasets"),
         ("08_notifications", "/notifications"), ("09_users", "/users"), ("10_audit_log", "/audit"),
         ("11_threat_map", "/map"), ("13_upload_pcap", "/sources/upload/pcap"),
         ("14_upload_syslog", "/sources/upload/syslog")]
# (name, path) pairs passed with --extra name=/path, e.g. an alert with an incident report


def fresh_code(secret, last=[None]):
    """Wait for a new 30 s step so a code is never reused (server rejects replays)."""
    totp = pyotp.TOTP(secret)
    step = int(time.time()) // 30
    if last[0] is not None and step <= last[0]:
        time.sleep(30 - time.time() % 30 + 1)
        step = int(time.time()) // 30
    last[0] = step
    return totp.now()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:5000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--totp-secret", default=None)
    ap.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    ap.add_argument("--auth-shots", action="store_true", help="also capture login / MFA pages")
    ap.add_argument("--extra", action="append", default=[], help="name=/path extra page to capture")
    ap.add_argument("--only-extra", action="store_true")
    ap.add_argument("--viewport-only", action="store_true", help="capture the viewport instead of the full page")
    ap.add_argument("--height", type=int, default=900)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1440, "height": args.height}, device_scale_factor=1)
        pg.goto(args.url + "/login")
        if args.auth_shots:
            pg.wait_for_timeout(900)  # let the entrance animation finish
            pg.screenshot(path=str(out / "00a_login.png"))
        pg.fill("#email", args.email)
        pg.fill("#password", args.password)
        pg.click("button[type=submit]")
        pg.wait_for_load_state()
        secret = args.totp_secret
        if "/mfa/enrol" in pg.url:
            secret = re.search(r"[A-Z2-7]{16,}", pg.inner_text("code")).group(0)
            if args.auth_shots:
                pg.wait_for_timeout(900)
                pg.screenshot(path=str(out / "00b_mfa_enrol_qr.png"))
            print("ENROLLED_TOTP_SECRET", secret)
        elif args.auth_shots:
            pg.wait_for_timeout(900)
            pg.screenshot(path=str(out / "00b_mfa_verify.png"))
        if not secret:
            sys.exit("MFA verification needs --totp-secret")
        pg.fill("#code", fresh_code(secret))
        pg.click("button[type=submit]")
        pg.wait_for_load_state()
        if pg.url.rstrip("/") != args.url.rstrip("/"):
            sys.exit(f"login failed, at {pg.url}: {pg.inner_text('body')[:300]}")
        print("logged in")
        pages = [] if args.only_extra else list(PAGES)
        pages += [tuple(e.split("=", 1)) for e in args.extra]
        for name, path in pages:
            pg.goto(args.url + path)
            # pages with a live SSE connection never reach "networkidle"
            pg.wait_for_load_state("load")
            if path == "/":  # wait for the first /api/summary refresh (and the count-up animation)
                for _ in range(120):  # (wait_for_function needs eval, which the CSP blocks)
                    if pg.inner_text("#t-events").strip() not in ("-", ""):
                        break
                    pg.wait_for_timeout(500)
            pg.wait_for_timeout(6000 if path.startswith("/map") else 2500 if path == "/" else 800)
            pg.screenshot(path=str(out / f"{name}.png"), full_page=not args.viewport_only)
            if path == "/alerts":
                pg.goto(args.url + "/alerts?sort=occurrences")  # largest grouped alert
                link = pg.locator("table tbody tr td a").first
                if link.count():
                    link.click()
                    pg.wait_for_load_state("load")
                    pg.wait_for_timeout(800)
                    pg.screenshot(path=str(out / "04_alert_detail.png"), full_page=True)
            print("saved", name)
        b.close()


if __name__ == "__main__":
    main()
