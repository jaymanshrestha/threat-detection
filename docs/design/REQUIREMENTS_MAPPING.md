# Requirements and use cases → screens

Source: *Project2_Final_Jayman_v5* (Sections 2-6). Use cases UC-01 to UC-11 replace the earlier UC-01 to UC-07 mapping; FR-01 to FR-10 are unchanged. Status: Implemented / Partially implemented / Not implemented.

## Use cases (UC-01 to UC-11)

| UC | Use case | Priority (report) | Screen journey | Flows covered | Status | Notes |
|---|---|---|---|---|---|---|
| UC-01 | Log In | Must | Login → MFA → Dashboard; Accept invitation | Main 1-7; A1 return to the linked alert; A2 log out; A3 invitation (set password + enrol); E1-E6 | Implemented |  |
| UC-02 | Replay a Dataset Simulation | Must (lab capture, incident report: Should) | Simulator, Datasets, run summary | Main 1-7; A1 lab capture + authorisation ref; A2 pause/resume; A3 stop; A4/A5 open alert/incident; A6 delete lab data; E1-E3 | Implemented |  |
| UC-03 | Monitor the Real-Time Dashboard | Must (threat map: Should) | Dashboard, Threat map | Main incl. last hour / 24 h / 7 days / custom; A1 open alert; A2 customise + save layout; A3 reset; A4 map 'Internal network'; E1 > 90 days; E2 paused banner; E3 invalid layout | Implemented |  |
| UC-04 | Investigate a Threat | Must (incident handling, AI report: Should) | Alerts → Alert detail → Incident detail | Main 1-6; A1 from email; A2 SHAP (≤ 5 features); A3 incident + report (auto for Critical/High); A4 source facts; A5 edit as new version; A6 merge; A7 status; E1-E4 | Implemented |  |
| UC-05 | Configure Alert Notifications | Must (SMS: Could) | Notifications | Main 1-7 incl. test email result; A1 change; A2 SMS numbers + test SMS; A3 cancel; A4 notification log with channel; E1-E3; E5 invalid mobile number; E6 SMS not delivered (recorded, email unaffected); E7 concurrent change | Implemented | Numbers are accepted in any E.164 format (Australian 04xx numbers are converted to +61); up to 10 numbers by default (report: three) - set SMS_MAX_RECIPIENTS=3 to match. |
| UC-06 | Review Model Performance and Tune Sensitivity | Must (RF, sensitivity tuning, model versions: Should) | Models | Main (rule baseline + IF metrics, confusion matrices, ≥ 5 failure cases); A1 RF; A2 presets + preview; A3 cancel; A4 activate / roll back; E1 invalid threshold; E2 not evaluated | Implemented |  |
| UC-07 | Manage Administrator Accounts | Must | Users | Main (email only, confirm, 24 h single-use invitation, audit); A1 change email; A2 disable; A3 cancel; A4 resend; E1-E4 | Implemented |  |
| UC-08 | Manage Data Sources and Upload Network Data | Must (interval pcap: Should) | Data sources, Upload | Main (status, events last hour, last event, accepted/rejected with reasons); A1 interval .pcap folder; A2 check sources; A3 save as replay dataset; E1-E5 | Implemented |  |
| UC-09 | Receive Threat Alert | Must (SMS: Could) | Alert email → Login → Alert detail; Notifications log; dashboard banner | Main 1-6 (Critical immediately, 30 min / 20 per hour limits, link, no raw logs); A1 hourly summary; A2 limit reached; A3 severity rises; A4 SMS (severity, category, time + link, no IPs); A5 open the alert; A6 below minimum; E1 retries + banner; E2 SMS not delivered (recorded, separate banner, email unaffected) | Implemented | SMS limits: one per alert per 60 min unless severity rises, 10 per hour (configurable). |
| UC-10 | Review Incidents | Should | Incidents, Incident detail, dashboard incident timeline | Main 1-6; A1 from the dashboard timeline; A2 request report for Medium/Low; E1 no matching incidents; E2 'Generated without AI' | Implemented |  |
| UC-11 | Review Audit Log | Must | Audit log | Main (filter by date, user, action); A1 CSV export of the filtered entries; E1 empty result | Implemented |  |

## Functional requirements (FR-01 to FR-10)

| FR | Requirement | Priority | Screen(s) | How the design supports it | Status |
|---|---|---|---|---|---|
| FR-01 | Administrator Login and MFA | Must | Login, MFA verify / enrol, Accept invitation | Two-step indicator; labelled fields; TOTP with autofill; lockout and expiry messages; single-use 24 h invitation links. | Implemented |
| FR-02 | Access Control and Audit Logging | Must | Users, Audit log (every page requires sign-in) | Invite by email, change email, disable, resend invitation with confirmations; filterable, exportable append-only audit table. | Implemented |
| FR-03 | Network Log Ingestion and Processing | Must | Data sources, Upload (per-format tabs) | Source status (Active/Paused/Error); format tabs; accepted/rejected counts with reasons; interval .pcap capture folder. | Implemented |
| FR-04 | AI Threat Detection and Model Evaluation | Must / Should | Models, Alert detail, Flagged events | Metrics, confusion matrices, failure cases (incl. analyst false positives), presets + preview, activate / roll back, SHAP bars. | Implemented |
| FR-05 | Isolated Attack Simulation, Replay and Log Generation | Must / Should | Simulator, Datasets, Dashboard replay tile | In-app replay at 1x/10x/100x with attack filter, progress, pause/stop, summary; lab captures with authorisation reference. | Implemented |
| FR-06 | Dashboard and Threat Visualisation | Must / Should | Dashboard, Threat map | KPI tiles, timelines, severity/category charts, top ports/sources, model panel, incident timeline, geo-map; custom range; saved layout. | Implemented |
| FR-07 | Threat Classification and Email Notifications | Must | Notifications, Alert detail (emails sent) | Recipients, minimum severity and grouping window form; test email result; notification log with channel, status and reason. | Implemented |
| FR-08 | Alert De-duplication and Throttling | Must | Alerts list, Notifications | Occurrence counter per alert, 'last email' column, suppressed emails shown with their reason. | Implemented |
| FR-09 | AI-Assisted Incident Reporting | Should | Incidents, Incident detail, Alert detail - report | Incidents with status/notes/merge; AI report labelled 'AI-generated: review before acting', template fallback 'Generated without AI', edits kept as versions. | Implemented |
| FR-10 | SMS Notifications | Could | Notifications (SMS card), notification log (channel SMS), dashboard banner | Twilio REST API (demo outbox without credentials); validated E.164 numbers; test SMS with result; Critical-only by default; same per-alert / hourly limits and log records as email; failures recorded, never affect email. | Implemented |

## User flow steps by use case

| UC | Path through the screens |
|---|---|
| UC-01 | Login → MFA → Dashboard; invitation link → set password → enrol → Login |
| UC-02 | Dashboard → Simulator → (progress, pause / stop) → run summary → Alert / Incident |
| UC-03 | Dashboard (time range, layout) → Threat map / Flagged events |
| UC-04 | Alerts → Alert detail → Incident detail (report, edit, merge, status) |
| UC-05 | Notifications → save / test / cancel → notification log |
| UC-06 | Models → preset or slider → preview → apply; activate / roll back |
| UC-07 | Users → add by email → invitation email → (UC-01 A3) |
| UC-08 | Data sources → Upload (format tab) → accepted / rejected summary; capture folder |
| UC-09 | Critical alert email → Login (+ MFA) → Alert detail |
| UC-10 | Incidents (filters) → Incident detail; or dashboard incident timeline → Incident detail |
| UC-11 | Audit log → filter → export CSV |

## Differences from the report (Sections 5 and 6)

### Fixed in the prototype

| Report item | Report says | Change made |
|---|---|---|
| SD-02 (UC-08 E2) | Rejected upload returns 400 Bad Request with the missing fields listed | The upload page now answers 400 with the missing fields (was a redirect). |
| SD-05 (UC-02) | Replay start returns 202 Accepted and runs in the background; E1 rejects a second replay | /api/v1/replay/start now returns 202; the Simulator page starts a background replay and refuses a second one (409 on the API). |
| SD-04 / UC-04 A3, E2 | Report labels 'AI-generated: review before acting' and 'Generated without AI' | Labels changed to the report's wording (older stored reports are shown with the new wording). |
| Table 13 :SimulatorPage | A Simulator page | Added (/simulator). |
| Section 6.2.3 tools | GitHub Actions and Gitleaks | Added .github/workflows/ci.yml (pytest + gitleaks). |
| UC-03 A4 | Private addresses shown as 'Internal network' | Map popups now say Internal network (site name kept separately). |
| Section 6.2.1 SMS / FR-10 | Twilio trial for SMS alerts | Built: Twilio REST API through requests (no extra dependency), demo outbox when not configured. |

### Not changed (needs a report update or larger work)

| Report item | Report says | Prototype | Comment |
|---|---|---|---|
| Section 6.2.1 back end | FastAPI (Python) | Flask 3 with Jinja templates (server-rendered). | Rewrite of every route; not trivial. Flask meets the same requirements; recommend updating Table 19. |
| Section 6.2.1 front end | React 19 + Vite + TypeScript SPA | Server-rendered Jinja pages + small vanilla JS files (strict CSP, no inline JS). | Full front-end rewrite; recommend updating Table 19 or describing the Jinja UI. |
| Section 6.2.1 database | PostgreSQL 17 | SQLite (WAL) by default; PostgreSQL works through DATABASE_URL (SQLAlchemy). | Deployment choice only; can run on PostgreSQL without code changes. |
| Section 6.2.1 background work | Celery 5 + Redis 8 workers | In-process threads (notifier, replay, capture folder, collectors). | Would add two services; behaviour (detection never blocked by email) is the same. |
| SD-02 messages 7-8 | Detection started asynchronously after upload | Uploads are scored synchronously before the summary is shown. | Needs a task queue (see Celery); the summary still lists accepted/rejected rows. |
| Section 6.2.1 charts / live updates | Apache ECharts, WebSockets | Chart.js and Server-Sent Events (one-way push, polling fallback). | Equivalent function; recommend updating Table 19. |
| Section 6.2.1 location data | MaxMind GeoLite2 + geoip2 | DB-IP Lite (CC BY 4.0) MMDB with a built-in reader; GeoLite2 .mmdb files also work. | GeoLite2 needs a MaxMind account/licence key; code accepts either file. |
| Section 6.2.1 email | Mailpit for development email | Any SMTP server (a local aiosmtpd sink was used) or a file outbox. | Mailpit works unchanged as the SMTP server. |
| Section 6.2.1 LLM | OpenAI API (Ollama as alternative) | Any OpenAI-compatible endpoint; demo used a local Qwen 2.5 1.5B model. | Configuration only (LLM_API_BASE / LLM_MODEL). |
| Section 6.1.3 deployment | Docker Compose + Nginx + Certbot (TLS) | Runs directly with Python (setup.bat / run_windows.ps1); Docker is used only for the attack lab. | Packaging work; no TLS proxy in the prototype. |
| Section 6.2.3 accessibility tooling | axe-core checks | Own automated checks (contrast tokens + label/name test on every page). | axe-core could be added to the Playwright scripts. |
| Section 3 / Table 13 data model and participants | Dashboard_Settings and Model_Versions tables; :AuthController, :AlertController, :SimulationController, :IngestionService, :ReplayService … | Settings table (key/value, incl. per-user layout); model versions = trained files + metrics.json; Flask blueprints auth, dash, admin, api, inc, sim. | Naming difference only; recommend a note mapping report participants to modules. |
| UC-05 step 4 vs UC-09 A1 | Minimum severity default Critical, yet High alerts go into the hourly summary | Default minimum severity is High so the UC-09 A1 summary works out of the box. | Internal inconsistency in the report; either default works (setting is editable). |
