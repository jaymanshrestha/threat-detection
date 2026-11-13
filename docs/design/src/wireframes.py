"""Low-fidelity, greyscale wireframes for the key SentinelSMB screens (HTML -> PNG via Playwright)."""

NAV = [("MONITOR", ["Overview", "Flagged events", "Alerts", "Incidents", "Threat map"]),
       ("INTELLIGENCE", ["Models", "Data sources", "Simulator", "Datasets"]),
       ("ADMINISTRATION", ["Notifications", "Users", "Audit log", "Style guide"])]


def frame(url, inner, title):
    return f"""<div class="screen"><div class="title-bar"><i></i><i></i><i></i><span class="url">{url}</span><span>{title}</span></div>
<div class="body">{inner}</div><div class="wf-tag">WIREFRAME · LOW FIDELITY</div></div>"""


def shell(active, main, url, title):
    nav = '<div class="row" style="align-items:center;gap:8px;margin-bottom:6px"><div class="box dark" style="width:30px;height:30px"></div><div><div class="h">SentinelSMB</div><div style="font-size:10px;color:#666">THREAT DETECTION SOC</div></div></div>'
    for sec, items in NAV:
        nav += f'<div class="sec">{sec}</div>' + "".join(
            f'<div class="nav {"on" if i == active else ""}"><b></b>{i}</div>' for i in items)
    top = ('<span class="pill">● Live · streaming</span><span style="flex:1"></span><div class="box" style="width:34px;height:30px"></div>'
           '<span class="pill">( A ) admin@example.com</span><div class="btn ghost" style="height:30px">Log out</div>')
    return frame(url, f'<div class="side">{nav}</div><div class="top">{top}</div><div class="main">{main}</div>', title)


def note(n, text, x, y, w=210):
    return f'<div class="note" style="left:{x}px;top:{y}px;max-width:{w}px"><b>{n}</b>{text}</div>'


def lines(*ws):
    return "".join(f'<div class="line {w}"></div>' for w in ws)


def table(cols, rows=6, badge_col=None):
    h = "".join(f"<th>{c}</th>" for c in cols)
    body = ""
    for r in range(rows):
        cells = ""
        for i, _ in enumerate(cols):
            if i == badge_col:
                cells += f'<td><span class="pill {"d" if r % 3 == 0 else ""}">{["Critical", "Medium", "High"][r % 3]}</span></td>'
            else:
                cells += '<td><div class="line" style="margin:2px 0;width:%d%%"></div></td>' % (55 + (r * 7 + i * 13) % 40)
        body += f"<tr>{cells}</tr>"
    return f"<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>"


def auth_card(step, inner):
    s1, s2 = ("d", "") if step == 1 else ("", "d")
    return f"""<div style="position:absolute;inset:0;background:#e9e9e9"></div>
<div class="box" style="position:absolute;left:440px;top:120px;width:400px;padding:26px">
<div style="text-align:center"><div class="box dark" style="width:54px;height:54px;margin:0 auto 8px;border-radius:14px"></div>
<div class="h" style="font-size:18px">SentinelSMB</div><div style="font-size:12px;color:#666">AI-driven network threat detection</div>
<div style="margin:12px 0"><span class="pill {s1}">1 · Password</span> <span class="pill {s2}">2 · Authenticator</span></div></div>
{inner}
<div class="row" style="justify-content:center;margin-top:16px;font-size:11px;color:#666;gap:14px"><span>▢ Encrypted session</span><span>▢ TOTP MFA</span><span>▢ Audited sign-ins</span></div></div>"""


def login():
    inner = """<div class="h" style="text-align:center;font-size:17px">Administrator sign in</div>
<div class="lbl">Email</div><div class="input">name@company.com</div>
<div class="lbl">Password</div><div class="input">••••••••••••</div>
<div class="btn" style="margin-top:18px">▢ Sign in</div>
<div style="font-size:12px;color:#666;margin-top:10px">Multi-factor authentication is required for all administrators.</div>"""
    body = auth_card(1, inner)
    body += note(1, "Labels above every field; email format hint appears under the field", 860, 300)
    body += note(2, "Button stays disabled until both fields are valid", 860, 395)
    body += note(3, "Wrong password: generic error under the button; 5 failures lock the account for 15 min", 860, 470)
    body += note(4, "Two-step indicator shows the user where they are in sign-in", 160, 240)
    return frame("/login", body, "Login")


def mfa():
    inner = """<div class="h" style="text-align:center;font-size:17px">Two-factor verification</div>
<div style="margin:8px 0">""" + lines("l", "m") + """</div>
<div class="lbl">Authenticator code</div>
<div class="row" style="gap:6px">""" + "".join('<div class="input" style="width:50px;height:46px"></div>' for _ in range(6)) + """</div>
<div style="font-size:11px;color:#666;margin-top:4px">6 digits, refreshes every 30 seconds</div>
<div class="btn" style="margin-top:18px">▢ Verify</div>
<div style="font-size:12px;margin-top:10px;text-decoration:underline">Start again</div>"""
    body = auth_card(2, inner)
    body += '<div class="box x" style="position:absolute;left:880px;top:200px;width:170px;height:170px"></div><div style="position:absolute;left:880px;top:375px;width:220px;font-size:12px;color:#555">First sign-in only: QR code + manual key to enrol an authenticator app</div>'
    body += note(1, "Large numeric field, one-time-code autofill", 150, 380)
    body += note(2, "Code is single-use; the step expires 2 minutes after the password", 150, 470)
    return frame("/mfa", body, "MFA")


def dashboard():
    tiles = "".join(f'<div class="box" style="height:110px;padding:10px"><div class="row" style="justify-content:space-between"><div style="font-size:10px;letter-spacing:.1em;color:#666">{t}</div><div class="box mid" style="width:26px;height:26px"></div></div><div class="h" style="font-size:26px;margin:6px 0">{v}</div>{lines("m")}</div>'
                    for t, v in [("INGEST STATUS", "Idle"), ("EVENTS", "000,000"), ("FLAGGED", "00,000"), ("ALERTS", "000"), ("OPEN CRITICAL", "00"), ("REPLAY", "#0 run")])
    def chart(t, kind):
        g = {"line": '<svg width="100%" height="120" viewBox="0 0 400 120"><polyline fill="none" stroke="#777" stroke-width="3" points="0,100 40,95 80,98 120,90 160,96 200,40 230,20 260,90 300,60 340,95 400,92"/></svg>',
             "donut": '<svg width="100%" height="120" viewBox="0 0 400 120"><circle cx="120" cy="60" r="45" fill="none" stroke="#999" stroke-width="22"/><circle cx="120" cy="60" r="45" fill="none" stroke="#555" stroke-width="22" stroke-dasharray="80 400"/><rect x="230" y="30" width="12" height="12" fill="#999"/><rect x="230" y="55" width="12" height="12" fill="#777"/><rect x="230" y="80" width="12" height="12" fill="#555"/></svg>',
             "bar": '<svg width="100%" height="120" viewBox="0 0 400 120">' + "".join(f'<rect x="40" y="{8 + i * 14}" width="{320 - i * 45}" height="9" fill="#888"/>' for i in range(7)) + "</svg>"}[kind]
        return f'<div class="box" style="padding:10px"><div class="h" style="font-size:13px">▌{t}</div>{g}</div>'
    charts = "".join(chart(t, k) for t, k in [("Traffic over time", "line"), ("Anomalies over time", "line"), ("Flagged by severity", "donut"),
                                             ("Alerts by category", "donut"), ("Top destination ports", "bar"), ("Top source IPs", "bar")])
    main = f"""<div class="row" style="justify-content:space-between;align-items:flex-end"><div><div class="h" style="font-size:22px">Network overview</div>{lines("l")}</div>
<div class="row" style="align-items:flex-end"><div><div class="lbl">Time range</div><div class="input" style="width:170px">Custom range… ▾</div></div><div><div class="lbl">From</div><div class="input" style="width:150px">dd/mm/yyyy --:--</div></div><div><div class="lbl">To</div><div class="input" style="width:150px">dd/mm/yyyy --:--</div></div><div class="btn ghost">Apply range</div></div></div>
<div class="grid" style="grid-template-columns:repeat(6,1fr);margin-top:12px">{tiles}</div>
<div class="grid" style="grid-template-columns:repeat(3,1fr);margin-top:12px">{charts}</div>
<div class="grid" style="grid-template-columns:1fr 1fr 1fr;margin-top:12px">
<div class="box" style="padding:10px"><div class="h" style="font-size:13px">▌Detection model</div>{lines("m","s","m")}</div>
<div class="box" style="padding:10px"><div class="h" style="font-size:13px">▌Incident timeline</div>{lines("l","m","l")}</div>
<div class="box" style="padding:10px"><div class="h" style="font-size:13px">▌Latest alerts</div>{table(["Severity", "Category", "Last seen"], 2, 0)}</div></div>
<div class="box" style="margin-top:12px;padding:8px;border-style:dashed"><b>▸ Customise layout</b> - show / hide / reorder widgets · Save layout · Reset to default</div>"""
    body = shell("Overview", main, "/", "Dashboard")
    body += note(1, "UC-03 E2: banner 'Live updates are paused' if the connection drops", 330, 36, 260)
    body += note(2, "UC-03 step 4: last hour / 24 h / 7 days / custom; over 90 days is rejected (E1)", 600, 92, 260)
    body += note(3, "Six charts update live (server push, polling fallback)", 1105, 330, 150)
    body += note(4, "Model panel + incident timeline (UC-10 A1)", 560, 640, 200)
    body += note(5, "UC-03 A2/A3: layout saved per administrator, audit-logged", 760, 745, 300)
    return frame_strip(body)


def frame_strip(html):
    return html


def alerts():
    main = f"""<div class="row" style="justify-content:space-between;align-items:flex-end"><div><div class="h" style="font-size:22px">Alerts (de-duplicated)</div>{lines("l")}</div>
<div class="row" style="align-items:flex-end"><div><div class="lbl">Severity</div><div class="input" style="width:160px">All severities ▾</div></div><div class="btn ghost">Filter</div></div></div>
<div style="font-size:12px;color:#666;margin:10px 0">Repeated detections are merged into one alert with a counter.</div>
<div class="box" style="padding:10px">{table(["#", "Severity", "Category", "Source → destination", "Occurrences", "First seen", "Last seen", "Max risk", "Top features", "Last email"], 12, 1)}
<div class="row" style="margin-top:10px;font-size:12px;color:#555;gap:14px"><span class="pill">← Prev</span><span>Page 1 / 7 · 348 rows</span><span class="pill">Next →</span></div></div>"""
    body = shell("Alerts", main, "/alerts", "Alerts list")
    body += note(1, "Filter by severity (labelled select)", 900, 40)
    body += note(2, "Severity always shown as a word, not only a colour", 330, 230)
    body += note(3, "Alert number links to the detail page", 230, 470)
    return body


def alert_detail(report_focus=False):
    kv = "".join(f'<tr><td style="width:180px;color:#333;font-weight:700">{k}</td><td>{v}</td></tr>' for k, v in [
        ("Category", '<div class="line m"></div>'), ("Source → destination", '<div class="line s"></div>'),
        ("Occurrences", '<div class="line m"></div>'), ("Max risk score", '<div class="line s"></div>'),
        ("Why was this flagged?", '<div class="bars"><div style="width:85%"></div><div style="width:55%"></div><div style="width:40%"></div><div style="width:28%"></div><div style="width:20%"></div></div>'),
        ("Detector · model version", '<div class="line m"></div>'),
        ("Status", '<div class="line s"></div>'), ("Incident", '<span class="pill">Incident #109 · Investigating</span>')])
    report = """<div class="box" style="padding:12px;margin-top:10px"><div class="row" style="align-items:center"><div class="btn">✦ Generate report</div><div style="flex:1">""" + lines("m") + """</div></div>
<span class="pill">AI-generated · verify before acting</span> <span style="font-size:11px;color:#666">v3 · versions v1 v2 v3</span>
<div class="h" style="margin-top:10px">What happened</div>""" + lines("l", "m") + """<div class="h">Likely impact</div>""" + lines("l") + """
<div class="h">Confidence: High</div>""" + lines("m") + """<div class="h">Recommended next steps</div>""" + lines("m", "s") + """
<div class="box" style="border-style:dashed;padding:8px;margin-top:8px"><div class="h">Unverified claims - check before acting</div>""" + lines("m") + """</div></div>"""
    crumbs = '<div style="font-size:12px;color:#666">Overview › Alerts › Alert #334</div>'
    head = f'{crumbs}<div class="row" style="align-items:center"><div class="h" style="font-size:22px">Alert #334</div><span class="pill d">Critical</span></div>'
    if report_focus:
        main = head + '<div class="h" style="margin-top:10px">▌Incident report</div>' + report + '<div class="h" style="margin-top:12px">▌Notifications</div><div class="box" style="padding:8px">' + table(["Time", "Kind", "Status", "Subject"], 2) + "</div>"
        body = shell("Alerts", main, "/alerts/334#report", "Incident report")
        body += note(1, "Report built from structured facts only (no raw log text); input sanitised against prompt injection", 900, 95, 240)
        body += note(2, "Label makes AI authorship explicit", 650, 180)
        body += note(3, "Every regeneration is a new version; old versions kept", 900, 205, 240)
        body += note(4, "Claims the model could not verify are boxed separately", 900, 520, 240)
        return body
    main = head + f'<div class="box" style="padding:10px;margin-top:10px"><table>{kv}</table></div><div class="h" style="margin-top:12px">▌Incident report</div>' + report
    body = shell("Alerts", main, "/alerts/334", "Alert detail")
    body += note(1, "Breadcrumb back to the list", 520, 55)
    body += note(2, "SHAP contribution bars: red pushes risk up, green down", 960, 300, 230)
    body += note(3, "Primary action on this page", 520, 560)
    body += note(4, "UC-04 A3: link to the incident (or Open incident for Medium/Low)", 960, 430, 230)
    return body


def threat_map():
    dots = "".join(f'<circle cx="{x}" cy="{y}" r="{r}" fill="#777" stroke="#333" stroke-width="2"/>' for x, y, r in
                   [(250, 150, 9), (420, 210, 6), (610, 120, 12), (760, 260, 7), (880, 180, 10), (520, 330, 5), (330, 300, 8)])
    lines_ = "".join(f'<line x1="{x}" y1="{y}" x2="610" y2="120" stroke="#999" stroke-width="2" stroke-dasharray="6 5"/>' for x, y, _ in
                     [(250, 150, 0), (420, 210, 0), (760, 260, 0), (880, 180, 0), (520, 330, 0), (330, 300, 0)])
    m = f'<svg width="100%" height="520" viewBox="0 0 1030 520"><rect width="1030" height="520" fill="#e2e2e2"/><path d="M60 120 Q200 60 330 110 T560 90 T820 120 T1000 100 L1000 420 Q800 460 600 430 T200 440 T60 400Z" fill="#cfcfcf"/>{lines_}{dots}</svg>'
    main = f"""<div class="row" style="justify-content:space-between;align-items:flex-end"><div><div class="h" style="font-size:22px">Threat map</div>{lines("l")}</div>
<div><div class="lbl">Severity</div><div class="input" style="width:150px">All ▾</div></div></div>
<div class="box" style="margin-top:10px;overflow:hidden;position:relative">{m}<div class="box" style="position:absolute;left:640px;top:70px;width:200px;padding:8px;font-size:11px">Popup: IP, country, alerts, top severity{lines("m","s")}</div></div>
<div style="font-size:12px;color:#555;margin-top:8px">Legend: ● Low ● Medium ● High ● Critical · lines join source and destination · approximate locations</div>"""
    body = shell("Threat map", main, "/map", "Threat map")
    body += note(1, "Marker size = number of alerts; internal IPs placed at the site location", 230, 650, 260)
    body += note(2, "Filter by severity", 1050, 40)
    return body


def models():
    cards = f"""<div class="grid" style="grid-template-columns:1fr 1fr 1fr;margin-top:12px">
<div class="box" style="padding:10px"><div class="h">▌Active model</div><div class="lbl">ML detector for new traffic</div><div class="input">Random Forest + rules ▾</div><div class="btn" style="margin-top:10px;width:150px">Activate model</div><div class="btn ghost" style="margin-top:6px;width:190px">Roll back to previous</div>{lines("l","m")}</div>
<div class="box" style="padding:10px"><div class="h">▌Sensitivity control</div><div class="lbl">Threshold (0-1, step 0.05)</div><div class="row" style="align-items:center"><div style="flex:1;height:6px;background:#999;border-radius:3px;position:relative"><span style="position:absolute;left:68%;top:-6px;width:18px;height:18px;border-radius:50%;background:#444"></span></div><div class="input" style="width:70px">0.70</div></div><div class="row" style="margin-top:6px"><span class="pill">Low</span><span class="pill d">Medium</span><span class="pill">High</span></div><div style="font-size:11px;margin-top:6px">Preview: precision · recall · false positives / hour</div><div class="row"><div class="btn" style="margin-top:10px;width:170px">Apply to new traffic</div><div class="btn ghost" style="margin-top:10px">Cancel</div></div>{table(["Thr", "P", "R", "F1"], 3)}</div>
<div class="box" style="padding:10px"><div class="h">▌Per-category detection</div>{table(["Label", "Flows", "IF", "RF"], 5)}</div></div>"""
    plots = '<div class="grid" style="grid-template-columns:repeat(4,1fr);margin-top:12px">' + "".join(
        f'<div class="box x" style="height:120px"><span style="position:absolute;left:8px;bottom:6px;font-size:11px">{t}</span></div>' for t in ["PR curves", "Confusion matrix IF", "Confusion matrix RF", "Threshold sweep"]) + "</div>"
    main = f"""<div class="h" style="font-size:22px">Model evaluation</div>{lines("l")}
<div class="box" style="padding:10px;margin-top:8px"><div class="h">▌Test-set results (held-out days)</div>{table(["Detector", "Precision", "Recall", "F1", "FPR", "FP / hour", "ROC-AUC", "TP/FP/TN/FN"], 4)}</div>{cards}{plots}"""
    body = shell("Models", main, "/models", "Models")
    body += note(1, "Precision / recall / F1 / FPR / FP per hour for every detector", 900, 75, 240)
    body += note(2, "UC-06 A2: presets + preview before applying; confirm, audit-logged; E1 rejects values off the 0.05 steps", 560, 520, 260)
    body += note(4, "UC-06 A4: activate / roll back with confirmation; E2 not-evaluated versions refused", 230, 520, 260)
    body += note(3, "Confusion matrices and curves as images with descriptive alt text", 900, 690, 260)
    return body


def simulator():
    facts = "".join(f'<div class="box" style="padding:8px"><div style="font-size:10px;color:#666">{k}</div><div class="h">{v}</div></div>' for k, v in
                    [("Run", "#5"), ("Speed", "10x"), ("Status", "Running"), ("Events sent", "2,969 / 154,667"), ("Alerts raised", "3")])
    main = f"""<div class="h" style="font-size:22px">Simulator</div>{lines("l")}
<div class="h" style="margin-top:10px">▌Replay in progress</div><div class="box" style="padding:10px"><div class="grid" style="grid-template-columns:repeat(5,1fr)">{facts}</div>
<div style="height:10px;background:#ccc;border-radius:6px;margin:10px 0"><div style="width:22%;height:10px;background:#666;border-radius:6px"></div></div>
<div class="row"><div class="btn ghost">Pause</div><div class="btn" style="background:#555">Stop replay</div><div class="btn ghost">Watch the dashboard</div></div></div>
<div class="h" style="margin-top:12px">▌Start a replay</div><div class="box" style="padding:10px"><div class="lbl">Dataset</div><div class="input">CIC-IDS2017 · Friday PortScan (held-out test day) · 77 MB ▾</div>
<div class="row" style="align-items:flex-end"><div><div class="lbl">Speed</div><span class="pill">○ 1x</span> <span class="pill d">● 10x</span> <span class="pill">○ 100x</span></div><div><div class="lbl">Attack type (optional)</div><div class="input" style="width:200px">PortScan + benign ▾</div></div><div><div class="lbl">From</div><div class="input" style="width:90px">14:49</div></div><div><div class="lbl">To</div><div class="input" style="width:90px">15:05</div></div><div class="btn">▶ Start replay</div></div></div>
<div class="h" style="margin-top:12px">▌Stored datasets</div><div class="box" style="padding:8px">{table(["Name", "Type", "Origin", "Licence", "Size"], 2)}</div>"""
    body = shell("Simulator", main, "/simulator", "Simulator")
    body += note(1, "UC-02 step 6: progress (events sent, alerts raised) refreshes every 2 s", 960, 120, 240)
    body += note(2, "UC-02 A2/A3: pause, resume, stop early (confirmed)", 620, 300, 220)
    body += note(3, "UC-02 E1: Start is disabled while a replay runs", 960, 445, 230)
    body += note(4, "Only held-out test days or registered lab captures can be replayed; output labelled SIMULATED", 960, 620, 250)
    return body


def incidents():
    items = "".join(f'<div style="border-left:3px solid #888;padding:8px 12px;margin-left:8px;border-bottom:1px solid #ddd"><div class="row" style="align-items:center"><b>Incident #{n} · {t}</b><span class="pill {"d" if s == "Critical" else ""}">{s}</span><span class="pill">{st}</span></div><div style="font-size:11px;color:#666">2026-11-12 22:50 · 1 alert · 172.16.0.1 → 192.168.10.50 · <span class="pill">AI-generated: review before acting</span></div></div>'
                    for n, t, s, st in [(112, "Port Scan", "Critical", "New"), (111, "DoS / Flood", "Critical", "Investigating"), (109, "Attack - supervised", "High", "Resolved"), (104, "Port Scan", "High", "False Positive")])
    tiles = "".join(f'<div class="box" style="padding:10px"><div style="font-size:10px;color:#666">{k}</div><div class="h" style="font-size:22px">{v}</div></div>' for k, v in [("NEW", "108"), ("INVESTIGATING", "1"), ("RESOLVED", "0"), ("FALSE POSITIVE", "0")])
    main = f"""<div class="h" style="font-size:22px">Incidents</div>{lines("l")}
<div class="grid" style="grid-template-columns:repeat(4,1fr);margin-top:10px">{tiles}</div>
<div class="box row" style="padding:10px;margin-top:10px;align-items:flex-end"><div><div class="lbl">Severity</div><div class="input" style="width:150px">All ▾</div></div><div><div class="lbl">Status</div><div class="input" style="width:150px">All ▾</div></div><div><div class="lbl">From date</div><div class="input" style="width:130px">dd/mm/yyyy</div></div><div><div class="lbl">To date</div><div class="input" style="width:130px">dd/mm/yyyy</div></div><div class="btn ghost">Apply filters</div></div>
<div class="box" style="padding:10px;margin-top:10px">{items}</div>"""
    body = shell("Incidents", main, "/incidents", "Incidents")
    body += note(1, "UC-10 step 2: timeline, newest first, severity + status + date", 980, 380, 230)
    body += note(2, "UC-10 step 3: filter by severity, status or date; E1 'No incidents match these filters'", 980, 230, 250)
    body += note(3, "Report label on every item (AI or 'Generated without AI')", 620, 620, 240)
    return body


def incident_detail():
    main = f"""<div style="font-size:12px;color:#666">Overview › Incidents › Incident #109</div><div class="row" style="align-items:center"><div class="h" style="font-size:22px">Incident #109 · Port Scan</div><span class="pill d">Critical</span></div>
<div class="box" style="padding:10px;margin-top:8px"><div class="h">▌Change status</div><div class="row" style="align-items:flex-end"><div><div class="lbl">Status</div><div class="input" style="width:170px">Investigating ▾</div></div><div style="flex:1"><div class="lbl">Note (required to close)</div><div class="input" style="height:40px"></div></div><div class="btn">Save status</div></div></div>
<div class="box" style="padding:10px;margin-top:8px"><div class="h">▌Alerts in this incident</div>{table(["#", "Severity", "Category", "Source → destination", "Occurrences"], 2, 1)}<div class="btn ghost" style="width:180px">Merge related alerts</div></div>
<div class="box" style="padding:10px;margin-top:8px"><div class="h">▌Incident report</div><div class="row"><div class="btn">✦ Regenerate report</div><div class="btn ghost">Edit report</div></div><span class="pill">AI-generated: review before acting</span> <span style="font-size:11px">v1 v2 · Show source facts ▸</span>{lines("l","m","l")}</div>"""
    body = shell("Incidents", main, "/incidents/109", "Incident detail")
    body += note(1, "UC-04 A7: New / Investigating / Resolved / False Positive; E3 note required to close", 960, 95, 250)
    body += note(2, "UC-04 E4: hidden revision - a concurrent edit is refused and the latest version shown", 960, 200, 250)
    body += note(3, "UC-04 A6: merge related alerts", 620, 420, 200)
    body += note(4, "UC-04 A4/A5: source-facts toggle; edits saved as a new version, AI original kept", 960, 560, 250)
    return body


def users():
    main = f"""<div class="h" style="font-size:22px">Administrators</div>{lines("l")}
<div class="box" style="padding:10px;margin-top:10px">{table(["Email", "Role", "Status", "MFA", "Last login", "Actions"], 4)}</div>
<div class="h" style="margin-top:12px">▌Add administrator</div><div class="box row" style="padding:10px;align-items:flex-end"><div><div class="lbl">Email address</div><div class="input" style="width:300px">name@company.com</div></div><div class="btn">Send invitation</div><div class="btn ghost">Cancel</div></div>"""
    body = shell("Users", main, "/users", "Users")
    body += note(1, "UC-07: email only; confirm, then a single-use 24-hour invitation is emailed", 760, 560, 260)
    body += note(2, "Status: Active / Invited / Invitation expired / Disabled; Resend invitation (A4), Change email (A1), Disable (A2)", 900, 160, 260)
    body += note(3, "E1 invalid email · E2 duplicate · E3 own account / last admin · E4 not delivered", 380, 660, 300)
    return body


def accept_invite():
    inner = """<div class="h" style="text-align:center;font-size:17px">Welcome - set up your account</div>
<div style="font-size:12px;color:#555;margin:6px 0">You were invited as name@company.com</div>
<div class="lbl">New password (min 12 characters)</div><div class="input">••••••••••••</div>
<div class="lbl">Confirm password</div><div class="input">••••••••••••</div>
<div class="btn" style="margin-top:18px">Continue to authenticator setup</div>"""
    body = auth_card(1, inner).replace("1 · Password", "1 · Set password").replace("2 · Authenticator", "2 · Enrol authenticator")
    body += note(1, "UC-01 A3: first sign-in from the invitation link; step 2 is the QR enrolment", 860, 300)
    body += note(2, "UC-01 E6: an expired or used link shows 'This invitation has expired or has already been used'", 860, 420)
    return frame("/invite/&lt;token&gt;", body, "Accept invitation")


def data_sources():
    main = f"""<div class="h" style="font-size:22px">Data sources</div>{lines("l")}
<div class="box" style="padding:10px;margin-top:10px">{table(["Source", "Formats", "Status", "Events (last hour)", "Last event"], 5)}</div>
<div class="h" style="margin-top:12px">▌Upload logs</div><div class="box" style="padding:10px"><div class="row"><span class="pill d">cicids2017</span><span class="pill">netflow_v5</span><span class="pill">nfdump_csv</span><span class="pill">pcap</span><span class="pill">syslog</span></div>
<div class="box" style="border-style:dashed;padding:8px;margin:8px 0">Unsupported file: this is not a readable CSV file. Nothing was stored.</div>
<div class="lbl">File</div><div class="input" style="width:320px">Choose file…</div><div style="font-size:12px;margin:6px 0">▸ Also save this file as a replay dataset (origin, licence)</div><div class="row"><div class="btn">Upload and analyse</div><div class="btn ghost">Cancel</div></div></div>
<div class="h" style="margin-top:12px">▌Interval capture (.pcap)</div><div class="box" style="padding:10px">{lines("m","s")}<div class="btn ghost" style="width:230px">Check capture folder now</div></div>"""
    body = shell("Data sources", main, "/sources", "Data sources and upload")
    body += note(1, "UC-08 step 2: Active / Paused / Error, events in the last hour, last event", 960, 110, 250)
    body += note(2, "UC-08 E1/E2/E3/E5: one clear message; missing fields listed; invalid rows counted", 960, 380, 250)
    body += note(3, "UC-08 A3: save as replay dataset; A1 interval .pcap source", 960, 560, 250)
    return body


SCREENS = [("01_login", "Login", login), ("02_mfa", "MFA verification", mfa), ("03_dashboard", "Dashboard (overview)", dashboard),
           ("04_alerts_list", "Alerts list", alerts), ("05_alert_detail", "Alert detail", alert_detail),
           ("06_incident_report", "Incident report", lambda: alert_detail(True)), ("07_threat_map", "Threat map", threat_map),
           ("08_models", "Models and sensitivity", models), ("09_simulator", "Simulator", simulator),
           ("10_incidents", "Incidents timeline", incidents), ("11_incident_detail", "Incident detail", incident_detail),
           ("12_users", "Users and invitations", users), ("13_accept_invite", "Accept invitation", accept_invite),
           ("14_data_sources", "Data sources and upload", data_sources)]
