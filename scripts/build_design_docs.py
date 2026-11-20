#!/usr/bin/env python
"""Build the UI/UX design pack in docs/design/.

  python scripts/build_design_docs.py

Produces: wireframes/*.png (greyscale, low fidelity), user_flow.png + user_flow_hifi.png,
style_guide.png, ACCESSIBILITY.md, REQUIREMENTS_MAPPING.md and UI_UX_Design.pdf.
High-fidelity mockups come from the running app: run scripts/design_mockups.py first.
"""
import html
import shutil
import sys
from datetime import date
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
D = ROOT / "docs" / "design"
SRC, WF, MO, SG = D / "src", D / "wireframes", D / "mockups", D / "styleguide"
sys.path.insert(0, str(SRC))

from app import design_tokens as dt  # noqa: E402
from wireframes import SCREENS  # noqa: E402

# ------------------------------------------------------------------ content
FLOW = [  # key task: UC-01 Log In -> UC-03 Monitor -> UC-04 Investigate -> UC-10 incident (UC-09 email entry, UC-02 branch)
    ("01_login", "UC-01 · Log in (steps 2-4)", "Email + password. E1 invalid email, E2 one generic error, E3 lockout after 5 failures in 15 min."),
    ("02_mfa", "UC-01 · MFA code (steps 5-6)", "6-digit TOTP. E4 expires after 2 min, E5 wrong code counts towards the lockout. A3 invited users enrol here."),
    ("03_dashboard", "UC-03 · Dashboard", "Health, traffic, ports, flagged events, model panel and incident timeline; time range incl. custom (E1 > 90 days)."),
    ("09_simulator", "UC-02 · Simulator (branch)", "Pick a dataset, 1x/10x/100x and an attack filter; progress, pause/stop, run summary; output labelled SIMULATED."),
    ("04_alerts_list", "UC-04 · Alerts (steps 1-2)", "De-duplicated alerts with severity, detector, risk, first/last seen and count."),
    ("05_alert_detail", "UC-04 · Alert detail (steps 3-5)", "Detector + model version, grouped detections, \"Why was this flagged?\" (SHAP for RF, E1 if none)."),
    ("11_incident_detail", "UC-04 A3-A7 · Incident", "AI report (\"AI-generated: review before acting\" / \"Generated without AI\"), edit as new version, merge, status + note."),
    ("10_incidents", "UC-10 · Incident timeline (branch)", "Newest first; filter by severity, status and date; E1 empty result. A1: opened from the dashboard timeline."),
]
MOCKUP_FOR = {"01_login": "01_login", "02_mfa": "02_mfa_verify", "03_dashboard": "03_dashboard", "09_simulator": "18_simulator_running",
              "04_alerts_list": "04_alerts_list", "05_alert_detail": "05_alert_detail", "11_incident_detail": "21_incident_detail",
              "10_incidents": "20_incidents"}

MOCKUPS = [
    ("01_login", "UC-01 Login", "Glass card, two-step indicator, labelled fields; Sign in stays disabled until the email is valid and a password is entered (E1)."),
    ("02_mfa_verify", "UC-01 MFA verification", "Large numeric code field with one-time-code autofill and a helper line; same card layout as login for continuity."),
    ("24_invite_accept", "UC-01 A3 Accept invitation", "First sign-in from a single-use 24-hour link: set a password, then enrol the authenticator (step 2)."),
    ("24b_invite_expired", "UC-01 E6 Invitation expired or used", "One clear message telling the person to ask for a new invitation."),
    ("03_dashboard", "UC-03 Dashboard (overview)", "KPI row, threat-map preview, incident timeline and latest alerts, then trend charts; live status through server push; time-range selector."),
    ("27_dashboard_full", "UC-03 Dashboard with model panel and incident timeline", "Full page: charts, Detection model panel, Incident timeline (UC-10 A1) and latest alerts."),
    ("26_dashboard_layout", "UC-03 A2/A3 Customise layout", "Show, hide and reorder widgets; saved per administrator; Reset to default; invalid layouts rejected (E3)."),
    ("18_simulator_running", "UC-02 Simulator - replay in progress", "Run facts, events sent / alerts raised with a progress bar, Pause / Stop replay; Start is disabled while a replay runs (E1)."),
    ("19_simulator_summary", "UC-02 Simulator - run summary", "Completed run: events replayed, alerts raised, duration and links to every alert and incident (A4/A5)."),
    ("29_datasets", "UC-02 A1/A6 Datasets", "Origin, licence and size for each dataset; register a lab capture (authorisation reference required, E2); delete lab data (public data cannot be deleted, E3)."),
    ("04_alerts_list", "UC-04 Alerts list", "Labelled severity filter, severity badges that always include the word, alert numbers as links."),
    ("05_alert_detail", "UC-04 Alert detail", "Breadcrumb, detector and model version, incident link, SHAP contribution bars (red raises risk, green lowers it)."),
    ("06_incident_report", "UC-04 A3 Incident report on the alert", "AI label, version links, structured sections, unverified claims and a source-facts toggle (A4)."),
    ("20_incidents", "UC-10 Incidents timeline", "Status tiles, filters for severity, status and date, and a newest-first timeline with report labels."),
    ("21_incident_detail", "UC-04 A6/A7 Incident detail", "Status with a required closing note (E3), alerts in the incident, Merge related alerts, explanation."),
    ("22_incident_report", "UC-04 A5 / UC-10 A2 Incident report", "Request / regenerate report, Edit report (saved as a new version; the AI original is kept)."),
    ("07_threat_map", "UC-03 A4 Threat map", "Markers sized by alert count and coloured by severity; private addresses shown as Internal network."),
    ("08_models", "UC-06 Models", "Rule baseline and Isolation Forest metrics, Random Forest for comparison, confusion matrices and failure cases."),
    ("28_models_sensitivity", "UC-06 A2 Sensitivity presets and preview", "Low / Medium / High presets and a slider; the preview shows precision, recall and false positives per hour before applying."),
    ("09_notifications", "UC-05 Notifications", "Recipients (max 10), minimum severity, grouping window 5-60 min, send test email, Cancel, notification log with channel."),
    ("30_notifications_sms", "UC-05 A2 SMS alerts", "SMS on/off, mobile numbers (E.164, validated), minimum severity, gateway status (Twilio or demo outbox, credentials never shown) and Send test SMS with its result."),
    ("23_users_invite", "UC-07 Users and invitations", "Add an account by email only; status Active / Invited / Disabled; Resend invitation, Change email, Disable."),
    ("11_data_sources", "UC-08 Data sources", "Each source with Active / Paused / Error, events in the last hour and the last event; interval .pcap capture folder (A1)."),
    ("25_upload_error", "UC-08 E1 Upload rejected", "Unsupported file: one clear message, nothing stored; missing fields are listed for E2, invalid rows counted for E3."),
    ("12_audit_log", "UC-11 Audit log", "Filter by date, user and action, Clear filters, Export CSV (A1); empty result message (E1)."),
    ("13_dashboard_light", "Dashboard - light theme", "The same layout in the light theme; every colour pair re-checked for contrast."),
    ("14_alert_detail_light", "Alert detail - light theme", "Darker severity text shades keep badges above 4.5:1 on light backgrounds."),
    ("17_dashboard_mobile", "Dashboard - mobile (390 px)", "Sidebar collapses into a menu button; tiles stack two per row."),
]

REQUIREMENTS = [  # (FR, title, priority, screens, how the design supports it, status) - FR-01..FR-10 unchanged in v5
    ("FR-01", "Administrator Login and MFA", "Must", "Login, MFA verify / enrol, Accept invitation",
     "Two-step indicator; labelled fields; TOTP with autofill; lockout and expiry messages; single-use 24 h invitation links.", "Implemented"),
    ("FR-02", "Access Control and Audit Logging", "Must", "Users, Audit log (every page requires sign-in)",
     "Invite by email, change email, disable, resend invitation with confirmations; filterable, exportable append-only audit table.", "Implemented"),
    ("FR-03", "Network Log Ingestion and Processing", "Must", "Data sources, Upload (per-format tabs)",
     "Source status (Active/Paused/Error); format tabs; accepted/rejected counts with reasons; interval .pcap capture folder.", "Implemented"),
    ("FR-04", "AI Threat Detection and Model Evaluation", "Must / Should", "Models, Alert detail, Flagged events",
     "Metrics, confusion matrices, failure cases (incl. analyst false positives), presets + preview, activate / roll back, SHAP bars.", "Implemented"),
    ("FR-05", "Isolated Attack Simulation, Replay and Log Generation", "Must / Should", "Simulator, Datasets, Dashboard replay tile",
     "In-app replay at 1x/10x/100x with attack filter, progress, pause/stop, summary; lab captures with authorisation reference.", "Implemented"),
    ("FR-06", "Dashboard and Threat Visualisation", "Must / Should", "Dashboard, Threat map",
     "KPI tiles, timelines, severity/category charts, top ports/sources, model panel, incident timeline, geo-map; custom range; saved layout.", "Implemented"),
    ("FR-07", "Threat Classification and Email Notifications", "Must", "Notifications, Alert detail (emails sent)",
     "Recipients, minimum severity and grouping window form; test email result; notification log with channel, status and reason.", "Implemented"),
    ("FR-08", "Alert De-duplication and Throttling", "Must", "Alerts list, Notifications",
     "Occurrence counter per alert, 'last email' column, suppressed emails shown with their reason.", "Implemented"),
    ("FR-09", "AI-Assisted Incident Reporting", "Should", "Incidents, Incident detail, Alert detail - report",
     "Incidents with status/notes/merge; AI report labelled 'AI-generated: review before acting', template fallback 'Generated without AI', edits kept as versions.", "Implemented"),
    ("FR-10", "SMS Notifications", "Could", "Notifications (SMS card), notification log (channel SMS), dashboard banner",
     "Twilio REST API (demo outbox without credentials); validated E.164 numbers; test SMS with result; Critical-only by default; same per-alert / hourly limits and log records as email; failures recorded, never affect email.", "Implemented"),
]

# (id, name, priority from the v5 report, screens, flows covered, status, note)
USE_CASES = [
    ("UC-01", "Log In", "Must", "Login → MFA → Dashboard; Accept invitation",
     "Main 1-7; A1 return to the linked alert; A2 log out; A3 invitation (set password + enrol); E1-E6", "Implemented", ""),
    ("UC-02", "Replay a Dataset Simulation", "Must (lab capture, incident report: Should)", "Simulator, Datasets, run summary",
     "Main 1-7; A1 lab capture + authorisation ref; A2 pause/resume; A3 stop; A4/A5 open alert/incident; A6 delete lab data; E1-E3", "Implemented", ""),
    ("UC-03", "Monitor the Real-Time Dashboard", "Must (threat map: Should)", "Dashboard, Threat map",
     "Main incl. last hour / 24 h / 7 days / custom; A1 open alert; A2 customise + save layout; A3 reset; A4 map 'Internal network'; E1 > 90 days; E2 paused banner; E3 invalid layout", "Implemented", ""),
    ("UC-04", "Investigate a Threat", "Must (incident handling, AI report: Should)", "Alerts → Alert detail → Incident detail",
     "Main 1-6; A1 from email; A2 SHAP (≤ 5 features); A3 incident + report (auto for Critical/High); A4 source facts; A5 edit as new version; A6 merge; A7 status; E1-E4", "Implemented", ""),
    ("UC-05", "Configure Alert Notifications", "Must (SMS: Could)", "Notifications",
     "Main 1-7 incl. test email result; A1 change; A2 SMS numbers + test SMS; A3 cancel; A4 notification log with channel; E1-E3; E5 invalid mobile number; E6 SMS not delivered (recorded, email unaffected); E7 concurrent change", "Implemented",
     "Numbers are accepted in any E.164 format (Australian 04xx numbers are converted to +61); up to 10 numbers by default (report: three) - set SMS_MAX_RECIPIENTS=3 to match."),
    ("UC-06", "Review Model Performance and Tune Sensitivity", "Must (RF, sensitivity tuning, model versions: Should)", "Models",
     "Main (rule baseline + IF metrics, confusion matrices, ≥ 5 failure cases); A1 RF; A2 presets + preview; A3 cancel; A4 activate / roll back; E1 invalid threshold; E2 not evaluated", "Implemented", ""),
    ("UC-07", "Manage Administrator Accounts", "Must", "Users",
     "Main (email only, confirm, 24 h single-use invitation, audit); A1 change email; A2 disable; A3 cancel; A4 resend; E1-E4", "Implemented", ""),
    ("UC-08", "Manage Data Sources and Upload Network Data", "Must (interval pcap: Should)", "Data sources, Upload",
     "Main (status, events last hour, last event, accepted/rejected with reasons); A1 interval .pcap folder; A2 check sources; A3 save as replay dataset; E1-E5", "Implemented", ""),
    ("UC-09", "Receive Threat Alert", "Must (SMS: Could)", "Alert email → Login → Alert detail; Notifications log; dashboard banner",
     "Main 1-6 (Critical immediately, 30 min / 20 per hour limits, link, no raw logs); A1 hourly summary; A2 limit reached; A3 severity rises; A4 SMS (severity, category, time + link, no IPs); A5 open the alert; A6 below minimum; E1 retries + banner; E2 SMS not delivered (recorded, separate banner, email unaffected)", "Implemented",
     "SMS limits: one per alert per 60 min unless severity rises, 10 per hour (configurable)."),
    ("UC-10", "Review Incidents", "Should", "Incidents, Incident detail, dashboard incident timeline",
     "Main 1-6; A1 from the dashboard timeline; A2 request report for Medium/Low; E1 no matching incidents; E2 'Generated without AI'", "Implemented", ""),
    ("UC-11", "Review Audit Log", "Must", "Audit log",
     "Main (filter by date, user, action); A1 CSV export of the filtered entries; E1 empty result", "Implemented", ""),
]

FLOW_UC = [("UC-01", "Login → MFA → Dashboard; invitation link → set password → enrol → Login"),
           ("UC-02", "Dashboard → Simulator → (progress, pause / stop) → run summary → Alert / Incident"),
           ("UC-03", "Dashboard (time range, layout) → Threat map / Flagged events"),
           ("UC-04", "Alerts → Alert detail → Incident detail (report, edit, merge, status)"),
           ("UC-05", "Notifications → save / test / cancel → notification log"),
           ("UC-06", "Models → preset or slider → preview → apply; activate / roll back"),
           ("UC-07", "Users → add by email → invitation email → (UC-01 A3)"),
           ("UC-08", "Data sources → Upload (format tab) → accepted / rejected summary; capture folder"),
           ("UC-09", "Critical alert email → Login (+ MFA) → Alert detail"),
           ("UC-10", "Incidents (filters) → Incident detail; or dashboard incident timeline → Incident detail"),
           ("UC-11", "Audit log → filter → export CSV")]

# Conflicts between the v5 report (Sections 5 and 6) and the built prototype
CONFLICTS_FIXED = [
    ("SD-02 (UC-08 E2)", "Rejected upload returns 400 Bad Request with the missing fields listed", "The upload page now answers 400 with the missing fields (was a redirect)."),
    ("SD-05 (UC-02)", "Replay start returns 202 Accepted and runs in the background; E1 rejects a second replay", "/api/v1/replay/start now returns 202; the Simulator page starts a background replay and refuses a second one (409 on the API)."),
    ("SD-04 / UC-04 A3, E2", "Report labels 'AI-generated: review before acting' and 'Generated without AI'", "Labels changed to the report's wording (older stored reports are shown with the new wording)."),
    ("Table 13 :SimulatorPage", "A Simulator page", "Added (/simulator)."),
    ("Section 6.2.3 tools", "GitHub Actions and Gitleaks", "Added .github/workflows/ci.yml (pytest + gitleaks)."),
    ("UC-03 A4", "Private addresses shown as 'Internal network'", "Map popups now say Internal network (site name kept separately)."),
    ("Section 6.2.1 SMS / FR-10", "Twilio trial for SMS alerts", "Built: Twilio REST API through requests (no extra dependency), demo outbox when not configured."),
]
CONFLICTS_OPEN = [
    ("Section 6.2.1 back end", "FastAPI (Python)", "Flask 3 with Jinja templates (server-rendered).", "Rewrite of every route; not trivial. Flask meets the same requirements; recommend updating Table 19."),
    ("Section 6.2.1 front end", "React 19 + Vite + TypeScript SPA", "Server-rendered Jinja pages + small vanilla JS files (strict CSP, no inline JS).", "Full front-end rewrite; recommend updating Table 19 or describing the Jinja UI."),
    ("Section 6.2.1 database", "PostgreSQL 17", "SQLite (WAL) by default; PostgreSQL works through DATABASE_URL (SQLAlchemy).", "Deployment choice only; can run on PostgreSQL without code changes."),
    ("Section 6.2.1 background work", "Celery 5 + Redis 8 workers", "In-process threads (notifier, replay, capture folder, collectors).", "Would add two services; behaviour (detection never blocked by email) is the same."),
    ("SD-02 messages 7-8", "Detection started asynchronously after upload", "Uploads are scored synchronously before the summary is shown.", "Needs a task queue (see Celery); the summary still lists accepted/rejected rows."),
    ("Section 6.2.1 charts / live updates", "Apache ECharts, WebSockets", "Chart.js and Server-Sent Events (one-way push, polling fallback).", "Equivalent function; recommend updating Table 19."),
    ("Section 6.2.1 location data", "MaxMind GeoLite2 + geoip2", "DB-IP Lite (CC BY 4.0) MMDB with a built-in reader; GeoLite2 .mmdb files also work.", "GeoLite2 needs a MaxMind account/licence key; code accepts either file."),
    ("Section 6.2.1 email", "Mailpit for development email", "Any SMTP server (a local aiosmtpd sink was used) or a file outbox.", "Mailpit works unchanged as the SMTP server."),
    ("Section 6.2.1 LLM", "OpenAI API (Ollama as alternative)", "Any OpenAI-compatible endpoint; demo used a local Qwen 2.5 1.5B model.", "Configuration only (LLM_API_BASE / LLM_MODEL)."),
    ("Section 6.1.3 deployment", "Docker Compose + Nginx + Certbot (TLS)", "Runs directly with Python (setup.bat / run_windows.ps1); Docker is used only for the attack lab.", "Packaging work; no TLS proxy in the prototype."),
    ("Section 6.2.3 accessibility tooling", "axe-core checks", "Own automated checks (contrast tokens + label/name test on every page).", "axe-core could be added to the Playwright scripts."),
    ("Section 3 / Table 13 data model and participants", "Dashboard_Settings and Model_Versions tables; :AuthController, :AlertController, :SimulationController, :IngestionService, :ReplayService …",
     "Settings table (key/value, incl. per-user layout); model versions = trained files + metrics.json; Flask blueprints auth, dash, admin, api, inc, sim.", "Naming difference only; recommend a note mapping report participants to modules."),
    ("UC-05 step 4 vs UC-09 A1", "Minimum severity default Critical, yet High alerts go into the hourly summary", "Default minimum severity is High so the UC-09 A1 summary works out of the box.", "Internal inconsistency in the report; either default works (setting is editable)."),
]
OTHER_FIXES = [
    "Every form control now has a visible label tied to it with for/id (severity filters on Alerts and Flagged events, audit-log filters, add-administrator form and file inputs had none).",
    "Buttons that only show an icon have an aria-label; per-row buttons on Users name the user (\"Disable ops@example.com\"). On phones the Sign out text is hidden visually but kept for screen readers (it used to be display:none, leaving the button without a name).",
    "Visible 2px focus ring on buttons, links, tabs and fields when using the keyboard (inputs previously had a faint 20% glow only).",
    "Form field borders raised from about 1.2:1 to at least 3.4:1 so the field outline is visible (WCAG 1.4.11 non-text contrast).",
    "v2 redesign: gradients, glow and glass panels removed. Primary buttons are one flat indigo accent (#3b5bdb, white text 5.67:1); cards are opaque, so contrast is measured on the exact colour text sits on.",
    "Severity badges use dedicated text shades (--low-fg, --med-fg, --high-fg, --crit-fg); the vibrant colours are kept for dots, charts and the map. Severity is always written as a word, never colour alone.",
    "Charts are announced as images with a description (role=\"img\", aria-label \"Chart: ...\"); the same numbers are in the tables. Model plots have descriptive alt text instead of file names.",
    "Breadcrumbs on the alert page, aria-current on the active nav item and tab, role=\"search\" on filter forms, and a label for the threat-map region.",
    "Consistent page structure: one H1 plus a one-line subtitle on every page; labels in a shared .field style; buttons always declare type=\"submit\" or type=\"button\".",
    "The threshold control on Models is now a slider kept in sync with the number field.",
    "Existing: skip-to-content link, reduced-motion support, one system font stack (Segoe UI on Windows) at 14px body, 12px minimum for small text.",
    "New v5 screens (Simulator, Incidents, Incident detail, Accept invitation, layout editor, SMS card) use the same tokens and pass the same label and contrast checks; status pills always contain the status word; the replay progress bar is a labelled role=\"progressbar\" and the sensitivity preview is announced with aria-live.",
]


# ------------------------------------------------------------------ helpers
def esc(s):
    return html.escape(str(s))


def render_wireframes(pg):
    WF.mkdir(parents=True, exist_ok=True)
    css = (SRC / "wireframe.css").as_uri()
    for name, title, fn in SCREENS:
        f = SRC / f"wf_{name}.html"
        f.write_text(f'<!doctype html><html><head><meta charset="utf-8"><link rel="stylesheet" href="{css}"><title>{title}</title></head><body>{fn()}</body></html>')
        pg.set_viewport_size({"width": 1284, "height": 804})
        pg.goto(f.as_uri())
        pg.wait_for_timeout(150)
        pg.locator(".screen").screenshot(path=str(WF / f"{name}.png"))
        print("wireframe", name)


def flow_html(kind):
    folder = WF if kind == "wf" else MO
    pos = {"01_login": (40, 120), "02_mfa": (540, 120), "03_dashboard": (1040, 120), "09_simulator": (1540, 120),
           "11_incident_detail": (40, 660), "05_alert_detail": (540, 660), "04_alerts_list": (1040, 660), "10_incidents": (1540, 660)}
    nodes = ""
    for key, label, cap in FLOW:
        x, y = pos[key]
        img = folder / f"{key if kind == 'wf' else MOCKUP_FOR[key]}.png"
        branch = "(branch)" in label
        nodes += (f'<div class="node{" branch" if branch else ""}" style="left:{x}px;top:{y}px"><div class="lab">{esc(label)}</div>'
                  f'<img src="{img.as_uri()}"><div class="cap">{esc(cap)}</div></div>')
    # arrows: (path, label, label x, label y, dashed)
    A = [("M462 286 L536 286", "UC-01<br>step 4", 470, 236, False),
         ("M962 286 L1036 286", "UC-01<br>step 6", 966, 236, False),
         ("M1462 286 L1536 286", "UC-02<br>nav: Simulator", 1466, 236, True),
         ("M1250 470 L1250 654", "UC-03 A1 / UC-04 step 1<br>click an alert or nav: Alerts", 1262, 545, False),
         ("M1036 826 L966 826", "UC-04<br>step 2", 972, 776, False),
         ("M536 826 L466 826", "UC-04 A3<br>incident", 470, 776, False),
         ("M1440 470 C1520 560 1660 560 1750 654", "UC-10 A1: incident timeline<br>or nav: Incidents", 1590, 520, True),
         ("M1750 1012 L1750 1210 L250 1210 L250 1016", "UC-10 step 4 - open an incident", 1260, 1196, True),
         ("M1960 290 C2010 400 2010 800 1962 826", "UC-02 A5<br>run → incident", 1880, 560, True),
         ("M750 116 C750 50 250 50 250 116", "UC-01 E4/E5: wrong code or 2-min expiry → \"Start again\"", 300, 40, True),
         ("M750 1068 L750 1012", "UC-09 → UC-01 A1: alert email link<br>(sign-in + MFA first)", 772, 1018, False)]
    paths = "".join(f'<path d="{d}" class="{"dash" if dash else "solid"}" marker-end="url(#ah{"d" if dash else ""})"/>' for d, *_r, dash in A)
    labels = "".join(f'<div class="alab" style="left:{lx}px;top:{ly}px">{lab}</div>' for _d, lab, lx, ly, _x in A)
    dark = kind != "wf"
    accent = "#8b5cf6" if dark else "#333"
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{{font-family:Inter;src:url("{(ROOT / 'app/static/vendor/inter/InterVariable.woff2').as_uri()}") format("woff2");font-weight:100 900}}
body{{margin:0;font-family:Inter,Arial,sans-serif}}
.canvas{{position:relative;width:2040px;height:1260px;background:{'#0b1022' if dark else '#ffffff'};color:{'#e6ecff' if dark else '#111'}}}
.title{{position:absolute;left:1040px;top:14px;width:960px;font-size:26px;font-weight:800}}
.title small{{display:block;font-size:14px;font-weight:500;color:{'#93a1c4' if dark else '#555'}}}
.node{{position:absolute;width:420px}}
.node .lab{{font-weight:800;font-size:17px;margin-bottom:6px}}
.node img{{width:420px;display:block;border-radius:8px;border:3px solid {accent};box-shadow:0 6px 20px rgba(0,0,0,.25)}}
.node.branch img{{border-style:dashed;border-color:{'#22d3ee' if dark else '#777'}}}
.node .cap{{font-size:13px;line-height:1.35;margin-top:6px;color:{'#a9b6dc' if dark else '#444'}}}
svg{{position:absolute;inset:0}}
svg>path{{fill:none;stroke-width:4}} .solid{{stroke:{accent}}} .dash{{stroke:{'#22d3ee' if dark else '#777'};stroke-dasharray:10 8}}
.alab{{position:absolute;font-size:12.5px;font-weight:700;line-height:1.25;background:{'#0b1022' if dark else '#fff'};padding:2px 4px;color:{'#e6ecff' if dark else '#222'}}}
.mail{{position:absolute;left:540px;top:1072px;width:420px;height:64px;border:3px solid {accent};border-radius:12px;display:flex;align-items:center;justify-content:center;gap:10px;font-weight:800;background:{'#111830' if dark else '#f2f2f2'}}}
.legend{{position:absolute;left:1040px;top:1070px;font-size:14px;line-height:1.9;color:{'#a9b6dc' if dark else '#333'}}}
.legend i{{display:inline-block;width:46px;height:0;border-top:4px solid {accent};vertical-align:middle;margin-right:8px}}
.legend i.d{{border-top:4px dashed {'#22d3ee' if dark else '#777'}}}
</style></head><body><div class="canvas">
<div class="title">User flow - investigate a threat<small>UC-01 Log In → UC-03 Monitor → UC-04 Investigate a Threat → UC-10 Review Incidents (UC-09 email entry, UC-02 replay branch) · {'high-fidelity screens' if dark else 'low-fidelity wireframes'}</small></div>
<svg width="2040" height="1260"><defs>
<marker id="ah" markerUnits="userSpaceOnUse" markerWidth="18" markerHeight="18" refX="14" refY="9" orient="auto"><path d="M0,0 L18,9 L0,18 z" fill="{accent}" stroke="none"/></marker>
<marker id="ahd" markerUnits="userSpaceOnUse" markerWidth="18" markerHeight="18" refX="14" refY="9" orient="auto"><path d="M0,0 L18,9 L0,18 z" fill="{'#22d3ee' if dark else '#777'}" stroke="none"/></marker></defs>{paths}</svg>
{nodes}{labels}
<div class="mail">✉ UC-09 Critical alert email (entry point)</div>
<div class="legend"><div><i></i>Main path of the key task</div><div><i class="d"></i>Optional branch / error or recovery path</div></div>
</div></body></html>"""


def render_flow(pg):
    for kind, out in [("wf", "user_flow.png"), ("hifi", "user_flow_hifi.png")]:
        f = SRC / f"flow_{kind}.html"
        f.write_text(flow_html(kind))
        pg.set_viewport_size({"width": 2040, "height": 1260})
        pg.goto(f.as_uri())
        pg.wait_for_timeout(300)
        pg.locator(".canvas").screenshot(path=str(D / out))
        print("flow", out)


def a11y_rows():
    return {t: dt.audit_before_after(t) for t in dt.THEMES}


def write_markdown():
    A = a11y_rows()
    md = ["# Accessibility summary (WCAG 2.1 AA)", "",
          "Generated by `scripts/build_design_docs.py` from `app/design_tokens.py` - the same values the stylesheet uses "
          "(`tests/test_accessibility.py` fails if they drift apart or any pair drops below AA).", "",
          "Text needs 4.5:1; large text and UI parts (field borders, focus rings, severity dots) need 3:1.", "",
          "| Colour pair | Needs | Dark before | Dark now | Light before | Light now |", "|---|---|---|---|---|---|"]
    for d, l in zip(A["dark"], A["light"]):
        f = lambda r, k: f"{r[k]:.2f}{'' if r['pass' if k == 'ratio' else 'before_pass'] else ' FAIL'}"  # noqa: E731
        md.append(f"| {d['pair']} | {d['required']}:1 | {f(d, 'before')} | {f(d, 'ratio')} | {f(l, 'before')} | {f(l, 'ratio')} |")
    fails = sum(not r["before_pass"] for t in A.values() for r in t)
    md += ["", f"**{fails} pairs failed before the pass; 0 fail now.**", "", "## Other accessibility work", ""]
    md += [f"- {x}" for x in OTHER_FIXES]
    md += ["", "## Automated checks", "",
           "- `tests/test_accessibility.py::test_contrast_wcag_aa_both_themes` - every pair above, both themes.",
           "- `tests/test_accessibility.py::test_every_control_has_a_label` - renders every page and fails on any input/select/textarea without a label or aria-label, or any button without a name.",
           "- `tests/test_accessibility.py::test_tokens_match_stylesheet` - token file and CSS stay identical.", ""]
    (D / "ACCESSIBILITY.md").write_text("\n".join(md))
    cell = lambda x: str(x).replace("|", "\\|")  # noqa: E731
    rm = ["# Requirements and use cases → screens", "",
          "Source: *Project2_Final_Jayman_v5* (Sections 2-6). Use cases UC-01 to UC-11 replace the earlier UC-01 to UC-07 mapping; "
          "FR-01 to FR-10 are unchanged. Status: Implemented / Partially implemented / Not implemented.", "",
          "## Use cases (UC-01 to UC-11)", "",
          "| UC | Use case | Priority (report) | Screen journey | Flows covered | Status | Notes |", "|---|---|---|---|---|---|---|"]
    rm += ["| " + " | ".join(cell(x) for x in r) + " |" for r in USE_CASES]
    rm += ["", "## Functional requirements (FR-01 to FR-10)", "",
           "| FR | Requirement | Priority | Screen(s) | How the design supports it | Status |", "|---|---|---|---|---|---|"]
    rm += ["| " + " | ".join(cell(x) for x in r) + " |" for r in REQUIREMENTS]
    rm += ["", "## User flow steps by use case", "", "| UC | Path through the screens |", "|---|---|"]
    rm += [f"| {u} | {cell(f)} |" for u, f in FLOW_UC]
    rm += ["", "## Differences from the report (Sections 5 and 6)", "", "### Fixed in the prototype", "",
           "| Report item | Report says | Change made |", "|---|---|---|"]
    rm += ["| " + " | ".join(cell(x) for x in r) + " |" for r in CONFLICTS_FIXED]
    rm += ["", "### Not changed (needs a report update or larger work)", "",
           "| Report item | Report says | Prototype | Comment |", "|---|---|---|---|"]
    rm += ["| " + " | ".join(cell(x) for x in r) + " |" for r in CONFLICTS_OPEN]
    (D / "REQUIREMENTS_MAPPING.md").write_text("\n".join(rm) + "\n")
    return A, fails


def pdf_html(A, fails):
    uri = lambda p: p.as_uri()  # noqa: E731
    font = (ROOT / "app/static/vendor/inter/InterVariable.woff2").as_uri()
    wf_desc = {"01_login": "Centred card, brand, two-step indicator, labelled fields, one primary action, trust signals.",
               "02_mfa": "Same card as login so the step feels continuous; code field, helper text, recovery link; QR area for first sign-in.",
               "03_dashboard": "Sidebar grouped by task (Monitor / Intelligence / Administration), top bar with live status, KPI row, 3×2 chart grid, latest alerts.",
               "04_alerts_list": "Title + filter on one line, explanation of de-duplication, dense table, pager.",
               "05_alert_detail": "Breadcrumb, title + severity, key facts, explanation bars, then the incident report section.",
               "06_incident_report": "Generate button and AI label first; fixed report headings; unverified claims separated; notifications below.",
               "07_threat_map": "Full-width map with severity filter, popups and a text legend.",
               "08_models": "Results table first, then presets + slider with a live preview, activate / roll back, then failure cases.",
               "09_simulator": "UC-02: start form (dataset, speed, time window, attack filter), progress bar, Pause / Stop, run history.",
               "10_incidents": "UC-10: status tiles, severity / status / date filters, newest-first timeline with report labels.",
               "11_incident_detail": "UC-04 A3-A7: status + required note, alerts in the incident, merge, AI report with edit-as-version.",
               "12_users": "UC-07: add by email only, status (Active / Invited / Disabled), resend invitation, change email, disable.",
               "13_accept_invite": "UC-01 A3: set a password from the single-use link, then enrol the authenticator.",
               "14_data_sources": "UC-08: source status table, capture folder (A1), upload tabs with accepted / rejected summary."}
    wf = "".join(f'<figure class="half"><img src="{uri(WF / (n + ".png"))}"><figcaption><b>Figure W{i + 1}. {esc(t)}</b> - {esc(wf_desc[n])}</figcaption></figure>'
                 for i, (n, t, _f) in enumerate(SCREENS))
    mk = "".join(f'<figure class="{"half" if "mobile" not in n else "mobile"}"><img src="{uri(MO / (n + ".png"))}"><figcaption><b>Figure M{i + 1}. {esc(t)}</b> - {esc(c)}</figcaption></figure>'
                 for i, (n, t, c) in enumerate(MOCKUPS) if (MO / (n + ".png")).exists())
    pal = ""
    for theme in dt.THEMES:
        pal += f"<h3>{theme.capitalize()} theme</h3><div class='sw'>"
        for group, items in dt.palette(theme):
            for c in items:
                fg = "#fff" if c["white_on"] >= 4.5 else "#0d1430"
                pal += f'<div class="s"><div class="c" style="background:{c["hex"]};color:{fg}">{c["hex"]}</div><div class="m"><b>{esc(c["name"])}</b><br>{esc(group.split(" (")[0])}</div></div>'
        pal += "</div>"
    rows = ""
    for d, l in zip(A["dark"], A["light"]):
        cell = lambda r, k, ok: f'<td class="{"ok" if ok else "bad"}">{r[k]:.2f}</td>'  # noqa: E731
        rows += (f"<tr><td>{esc(d['pair'])}</td><td>{d['required']}:1</td>{cell(d, 'before', d['before_pass'])}{cell(d, 'ratio', d['pass'])}"
                 f"{cell(l, 'before', l['before_pass'])}{cell(l, 'ratio', l['pass'])}</tr>")
    req = "".join(f"<tr><td><b>{a}</b></td><td>{esc(b)}</td><td>{c}</td><td>{esc(s)}</td><td>{esc(h)}</td><td>{esc(st)}</td></tr>" for a, b, c, s, h, st in REQUIREMENTS)
    stc = {"Implemented": "ok", "Not implemented": "bad"}
    uc = "".join(f"<tr><td><b>{esc(u)}</b></td><td>{esc(n)}</td><td>{esc(pr)}</td><td>{esc(sc)}</td><td>{esc(fl)}</td>"
                 f"<td class='{stc.get(st, '')}'>{esc(st)}</td><td>{esc(no)}</td></tr>" for u, n, pr, sc, fl, st, no in USE_CASES)
    fuc = "".join(f"<tr><td><b>{esc(u)}</b></td><td>{esc(f)}</td></tr>" for u, f in FLOW_UC)
    cfx = "".join("<tr>" + "".join(f"<td>{esc(x)}</td>" for x in r) + "</tr>" for r in CONFLICTS_FIXED)
    cop = "".join("<tr>" + "".join(f"<td>{esc(x)}</td>" for x in r) + "</tr>" for r in CONFLICTS_OPEN)
    types = "".join(f"<tr><td>{esc(n)}</td><td>{s}</td><td>{w}</td><td style='font-size:{s};font-weight:{w}'>{esc(x)}</td></tr>" for n, s, w, x in dt.TYPE_SCALE)
    sgimgs = "".join(f'<figure><img src="{uri(SG / f)}" class="sg"><figcaption>{c}</figcaption></figure>' for f, c in
                     [("sg-buttons.png", "Buttons: primary, secondary, destructive, small, disabled, icon-only, link-as-button."),
                      ("sg-badges.png", "Severity badges, simulated / AI / template tags and trend chips."),
                      ("sg-forms.png", "Form elements - every field has a visible label."),
                      ("sg-cards.png", "Cards: KPI tiles, a plain card and a data table.")] if (SG / f).exists())
    checklist = [("Mockups included to show a complete design process", f"Sections 3 and 5: {len(SCREENS)} wireframes, then {sum((MO / (n + '.png')).exists() for n, *_ in MOCKUPS)} hi-fi mockups of the same screens"),
                 ("Consistent, professional design suited to target users", "One style guide (section 6) enforced in code and tests; SOC-style dark theme for IT admins at small businesses"),
                 ("Visual user flow for a key task", "Section 4: UC-01 Login → MFA → UC-03 Dashboard → UC-04 Alerts → Alert detail → Incident, with UC-02 / UC-10 branches, UC-09 email entry and recovery paths"),
                 ("Accessibility: colour contrast and clear labelling", f"Section 7: {fails} failing colour pairs fixed, all pages pass label checks"),
                 ("Designs map to functional requirements and use cases", "Section 8: UC-01 to UC-11 (report v5) and FR-01 to FR-10 mapped to screens with priority and status; section 9 lists differences from the report")]
    ck = "".join(f"<tr><td>☑ {esc(a)}</td><td>{esc(b)}</td></tr>" for a, b in checklist)
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>UI/UX Design - SentinelSMB</title><style>
@font-face{{font-family:Inter;src:url("{font}") format("woff2");font-weight:100 900}}
@page{{size:A4;margin:16mm 14mm 16mm 14mm}}
@page wide{{size:A4 landscape;margin:12mm}}
body{{font-family:Inter,Arial,sans-serif;font-size:10.5pt;line-height:1.45;color:#141a33;margin:0}}
h1{{font-size:24pt;margin:0 0 6px;letter-spacing:-.01em}}
h2{{font-size:15pt;margin:0 0 8px;padding-bottom:4px;border-bottom:3px solid #7c3aed;break-after:avoid}}
h3{{font-size:11.5pt;margin:12px 0 6px;break-after:avoid}}
section{{break-before:page}}
section.wide{{page:wide}}
.cover{{height:250mm;display:flex;flex-direction:column;justify-content:center;background:linear-gradient(135deg,#0b1022,#1b1446 60%,#3b0f4a);color:#fff;padding:0 18mm;margin:-16mm -14mm 0;border-radius:0}}
.cover .k{{font-size:11pt;letter-spacing:.18em;text-transform:uppercase;color:#a5f3fc}}
.cover h1{{font-size:32pt;color:#fff}} .cover p{{color:#cfd6f5;max-width:150mm}}
.cover img{{width:170mm;border-radius:8px;margin-top:10mm;box-shadow:0 10px 30px rgba(0,0,0,.5)}}
figure{{margin:0 0 10px;break-inside:avoid}} figure img{{width:100%;border:1px solid #c9cfe3;border-radius:4px;display:block}}
figure.half img{{width:100%}} figure.mobile img{{width:55mm}}
figcaption{{font-size:9pt;color:#444;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:9pt;margin:6px 0 10px}}
th{{background:#eef0fa;text-align:left;padding:5px 6px;border:1px solid #c9cfe3}} td{{padding:4px 6px;border:1px solid #d6dbeb;vertical-align:top}}
td.ok{{color:#047857;font-weight:700}} td.bad{{color:#be123c;font-weight:700}}
.sw{{display:grid;grid-template-columns:repeat(6,1fr);gap:6px}} .s{{border:1px solid #c9cfe3;border-radius:5px;overflow:hidden;break-inside:avoid}}
.s .c{{height:13mm;display:flex;align-items:flex-end;padding:3px 5px;font-weight:800;font-size:8.5pt}} .s .m{{font-size:7.5pt;padding:3px 5px;line-height:1.3}}
img.sg{{width:100%}} .flow img{{max-width:100%;max-height:150mm;display:block;margin:0 auto}}
ul{{margin:4px 0 8px 18px;padding:0}} li{{margin:2px 0}}
.muted{{color:#555}} .pill{{display:inline-block;background:#eef0fa;border:1px solid #c9cfe3;border-radius:999px;padding:0 8px;font-size:9pt}}
</style></head><body>
<div class="cover"><div class="k">Project 2 · UI/UX design specification</div><h1>SentinelSMB - AI-Driven Network Threat Detection and Visualization</h1>
<p>Wireframes, user flow, high-fidelity mockups, style guide, accessibility review and requirement mapping for the administrator web application.</p>
<p style="font-size:9.5pt">Jayman Shrestha · {date.today().strftime('%d %B %Y')}</p><img src="{uri(MO / '03_dashboard.png')}"></div>

<section><h2>1. Purpose of the UI/UX design</h2>
<p><b>Users.</b> The application is used by the IT administrator of a small or medium business (SMB) - usually one person who looks after the network part-time, not a full security operations team. They need to see quickly whether anything is wrong, understand why something was flagged, and know what to do next, without reading raw logs.</p>
<p><b>UI goal (the look).</b> A calm, professional "security operations centre" theme that makes risk stand out: neutral slate surfaces, opaque cards, a single indigo accent for actions and links, and four severity colours (blue Low, amber Medium, orange High, red Critical) used the same way on every screen, chart and map. A light theme is provided for bright offices and printing.</p>
<p><b>UX goal (the feel).</b> Every task starts at the dashboard and is at most three clicks deep. The sidebar groups pages by task - <i>Monitor</i> (Overview, Flagged events, Alerts, Incidents, Threat map), <i>Intelligence</i> (Models, Simulator, Data sources, Datasets) and <i>Administration</i> (Notifications, Users, Audit log, Style guide). Security steps (MFA, confirmations for destructive actions, an audit trail) are built into the flow instead of being extra screens.</p>
<h3>Design process followed</h3>
<ol><li><b>Wireframes</b> (section 3) - greyscale layouts that fix structure, content hierarchy and navigation.</li>
<li><b>User flow</b> (section 4) - the wireframes connected into the key task "investigate a threat".</li>
<li><b>High-fidelity mockups</b> (section 5) - the same screens in the final colours, type and icons, captured from the working prototype.</li>
<li><b>Style guide</b> (section 6) - palette, typography, buttons, badges, forms and cards; also available inside the app at <span class="pill">/style-guide</span>.</li>
<li><b>Accessibility review</b> (section 7), <b>use case and requirement mapping</b> (section 8) and <b>differences from the report</b> (section 9).</li></ol>
<h3>Checklist from the UI/UX guidance</h3><table><thead><tr><th>Guidance item</th><th>Where it is covered</th></tr></thead><tbody>{ck}</tbody></table></section>

<section><h2>2. Information architecture</h2>
<table><thead><tr><th>Area</th><th>Screen</th><th>Main content</th><th>Main actions</th></tr></thead><tbody>
<tr><th colspan="4" style="background:#fff">Use-case ids refer to Project2_Final_Jayman_v5.</th></tr>
<tr><td rowspan="3">Sign-in</td><td>Login (UC-01)</td><td>Email, password, MFA notice</td><td>Sign in; returns to the linked page (A1)</td></tr>
<tr><td>MFA verify / enrol (UC-01)</td><td>6-digit code; QR + manual key on first sign-in</td><td>Verify, Start again</td></tr>
<tr><td>Accept invitation (UC-01 A3)</td><td>Set password from a 24 h single-use link</td><td>Continue to authenticator enrolment</td></tr>
<tr><td rowspan="6">Monitor</td><td>Overview (UC-03)</td><td>KPI tiles, live charts, model panel, incident timeline, latest alerts</td><td>Time range incl. custom, customise / reset layout, open alert</td></tr>
<tr><td>Flagged events</td><td>Every flagged flow with detector and explanation</td><td>Filter by severity, open alert</td></tr>
<tr><td>Alerts (UC-04)</td><td>De-duplicated alerts with counters</td><td>Filter, open alert</td></tr>
<tr><td>Alert detail (UC-04)</td><td>Detector + model version, SHAP bars, incident, report, emails, grouped detections</td><td>Open incident, generate report</td></tr>
<tr><td>Incidents / Incident detail (UC-10, UC-04 A3-A7)</td><td>Timeline with filters; status, note, alerts, report versions</td><td>Change status, merge, request / edit report</td></tr>
<tr><td>Threat map (UC-03 A4)</td><td>Markers by severity; Internal network for private addresses</td><td>Filter by severity</td></tr>
<tr><td rowspan="4">Intelligence</td><td>Models (UC-06)</td><td>Metrics, confusion matrices, failure cases, model card</td><td>Preset / slider + preview, activate, roll back</td></tr>
<tr><td>Simulator (UC-02)</td><td>Replay form, progress, run summary, history</td><td>Start, pause, resume, stop replay</td></tr>
<tr><td>Data sources / Upload (UC-08)</td><td>Source status, capture folder, ingestion jobs</td><td>Upload a file per format, check sources, save as dataset</td></tr>
<tr><td>Datasets (UC-02 A1/A6)</td><td>Dataset origin, licence, size, replay runs</td><td>Register lab capture, delete lab data</td></tr>
<tr><td rowspan="4">Administration</td><td>Notifications (UC-05, UC-09)</td><td>Email policy, SMS alerts, notification log</td><td>Save, cancel, send test email / test SMS</td></tr>
<tr><td>Users (UC-07)</td><td>Administrators, status, MFA state</td><td>Invite, resend, change email, disable, reset MFA</td></tr>
<tr><td>Audit log (UC-11)</td><td>Append-only event list</td><td>Filter, clear filters, export CSV</td></tr>
<tr><td>Style guide</td><td>Design tokens and components</td><td>-</td></tr></tbody></table></section>

<section><h2>3. Wireframes (low fidelity)</h2>
<p class="muted">Greyscale boxes and placeholder lines only - colour is left out on purpose so the review is about layout, hierarchy and navigation. Numbered notes explain key decisions.</p>{wf}</section>

<section class="wide"><h2>4. User flow - investigate a threat</h2>
<p class="muted">Each step is named by its use case in the v5 report. The administrator signs in with password and MFA (UC-01), lands on the dashboard (UC-03), opens an alert from the dashboard or the alerts list and reads why it was flagged (UC-04), then works the incident: report, edit, merge and status (UC-04 A3-A7). Incidents can also be reached from the incident timeline (UC-10 A1), and replays started from the Simulator (UC-02) lead to the same alerts and incidents. A Critical alert email (UC-09) links straight to the alert page after sign-in (UC-01 A1). Dashed lines are optional branches and recovery paths.</p>
<figure class="flow"><img src="{uri(D / 'user_flow.png')}"></figure></section>
<section class="wide"><h2>4. User flow - high-fidelity version</h2><figure class="flow"><img src="{uri(D / 'user_flow_hifi.png')}"></figure></section>

<section><h2>5. High-fidelity mockups</h2>
<p class="muted">Captured from the working prototype at 1440 × 900 with the final v2 palette, the system font stack and the project's own inline-SVG icon set. Data shown is from the public CIC-IDS2017 dataset replayed through the system.</p>{mk}</section>

<section><h2>6. Style guide</h2>
<p>The style guide is a page inside the application (<span class="pill">Administration → Style guide</span>), generated from the same design tokens the stylesheet uses, so it cannot drift from the real UI.</p>
<h3>6.1 Colour palette</h3>{pal}
<h3>6.2 Typography</h3><p>One <b>system font stack</b> - system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif - so the app uses the operating system's own UI font (Segoe UI on Windows), loads nothing and stays fully offline. Tabular figures are switched on so live counters do not jump. Monospace (Cascadia Mono / Consolas) for IP addresses, code and raw values. Spacing follows a 4px scale (4, 8, 12, 16, 24, 32px).</p>
<table><thead><tr><th>Style</th><th>Size</th><th>Weight</th><th>Sample</th></tr></thead><tbody>{types}</tbody></table>
<h3>6.3 Components</h3>
<ul><li><b>Primary button</b> - flat indigo #3b5bdb, white semibold text, 6px radius, 36px tall; one per form.</li>
<li><b>Secondary button</b> - neutral with a 3:1 outline; filters and reversible actions. <b>Destructive</b> - solid red, always behind a confirm dialog.</li>
<li><b>Severity badge</b> - pill with a coloured dot and the severity word. <b>Cards</b> - opaque, 10px radius, 1px border. <b>Fields</b> - label above, 36px tall, visible border, 2px focus ring. <b>Tables</b> - shaded header row, 10-12px cell padding, row hover, empty and loading rows.</li></ul>
{sgimgs}</section>

<section><h2>7. Accessibility (WCAG 2.1 AA)</h2>
<p>Contrast was measured with the WCAG 2.1 relative-luminance formula for every text/background pair in both themes (cards are opaque, so each pair is measured on the exact surface colour). Text needs 4.5:1; large text and UI parts need 3:1. <b>{fails} pairs failed before this review; all pass now.</b></p>
<table><thead><tr><th>Colour pair</th><th>Needs</th><th>Dark before</th><th>Dark now</th><th>Light before</th><th>Light now</th></tr></thead><tbody>{rows}</tbody></table>
<h3>Labels, keyboard and other checks</h3><ul>{''.join(f'<li>{esc(x)}</li>' for x in OTHER_FIXES)}</ul>
<p class="muted">Automated tests (<code>tests/test_accessibility.py</code>) re-check contrast in both themes and fail the build if any page has a form field without a label or a button without a name.</p></section>

<section><h2>8. Use cases and requirements → screens</h2>
<p class="muted">Use cases UC-01 to UC-11 and priorities are taken from Project2_Final_Jayman_v5 (they replace the earlier seven use cases). FR-01 to FR-10 are unchanged.</p>
<h3>8.1 Use cases UC-01 to UC-11</h3>
<table style="font-size:8pt"><thead><tr><th>UC</th><th>Use case</th><th>Priority</th><th>Screen journey</th><th>Flows covered</th><th>Status</th><th>Notes</th></tr></thead><tbody>{uc}</tbody></table>
<h3>8.2 User flow steps by use case</h3><table><thead><tr><th>UC</th><th>Path through the screens</th></tr></thead><tbody>{fuc}</tbody></table>
<h3>8.3 Functional requirements FR-01 to FR-10</h3>
<table><thead><tr><th>FR</th><th>Requirement</th><th>Priority</th><th>Screen(s)</th><th>How the design supports it</th><th>Status</th></tr></thead><tbody>{req}</tbody></table></section>

<section><h2>9. Differences from the report (Sections 5 and 6)</h2>
<p class="muted">The sequence diagrams (Section 5) and resource plan (Section 6) were checked against the prototype. Small differences were fixed; the rest need either a wording update in the report or larger work.</p>
<h3>9.1 Fixed in the prototype</h3><table style="font-size:8.5pt"><thead><tr><th>Report item</th><th>Report says</th><th>Change made</th></tr></thead><tbody>{cfx}</tbody></table>
<h3>9.2 Not changed</h3><table style="font-size:8pt"><thead><tr><th>Report item</th><th>Report says</th><th>Prototype</th><th>Comment</th></tr></thead><tbody>{cop}</tbody></table></section>
</body></html>"""


def main():
    for d in (WF, MO, SG):
        d.mkdir(parents=True, exist_ok=True)
    missing = [n for n, *_ in MOCKUPS if not (MO / f"{n}.png").exists()]
    if missing:
        print("warning: mockups missing (run scripts/design_mockups.py):", missing)
    A, fails = write_markdown()
    if (MO / "15_style_guide_full.png").exists():
        shutil.copy(MO / "15_style_guide_full.png", D / "style_guide.png")
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page()
        render_wireframes(pg)
        render_flow(pg)
        f = SRC / "UI_UX_Design.html"
        f.write_text(pdf_html(A, fails))
        pg.goto(f.as_uri())
        pg.wait_for_timeout(800)
        pg.pdf(path=str(D / "UI_UX_Design.pdf"), format="A4", print_background=True, prefer_css_page_size=True)
        print("pdf", D / "UI_UX_Design.pdf")
        b.close()


if __name__ == "__main__":
    main()
