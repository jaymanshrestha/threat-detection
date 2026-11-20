"""Dashboard pages (all require an authenticated, MFA-verified administrator)."""
import json
from datetime import datetime, timedelta
from pathlib import Path

import time

from flask import (Blueprint, Response, abort, current_app, flash, jsonify, redirect, render_template, request,
                   send_from_directory, stream_with_context, url_for)
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from sqlalchemy import func

from alerts.severity import SEVERITIES

from . import settings
from .extensions import db
from ingest import ADAPTERS

from . import reports as incident_reports
from .geo import ATTRIBUTION, locate
from .models import Incident
from .models import (Dataset, DetectionResult, IncidentReport, IngestionJob, NetworkEvent, Notification,
                     SecurityAlert, SimulationRun)
from .pipeline import MODEL_CHOICES, available_models, ingest_bytes
from .privacy import display
from .security import audit

bp = Blueprint("dash", __name__)
RANGES = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "24h": timedelta(hours=24),
          "7d": timedelta(days=7), "all": None}


def _metrics():
    p = Path(current_app.config["METRICS_PATH"])
    return json.loads(p.read_text()) if p.exists() else None


@bp.app_context_processor
def inject_globals():
    failed = sms_failed = 0
    if current_user.is_authenticated:
        since = datetime.now() - timedelta(hours=24)
        recent = Notification.query.filter(Notification.status.in_(("Failed", "Partial")), Notification.created_at >= since)
        sms_failed = recent.filter(Notification.channel == "SMS").count()  # FR-10: kept apart from email (UC-09 E1/E2)
        failed = recent.filter(Notification.status == "Failed").count() - recent.filter(
            Notification.channel == "SMS", Notification.status == "Failed").count()
    return {"email_failures": failed, "sms_failures": sms_failed, "SEVERITIES": SEVERITIES}


WIDGETS = {"tiles": "Summary tiles", "map": "Threat map", "incidents": "Incident timeline",
           "latest": "Latest alerts", "traffic": "Traffic over time", "anomalies": "Anomalies over time",
           "severity": "Flagged events by severity", "categories": "Alerts by category",
           "ports": "Top destination ports", "sources": "Top source IPs", "model": "Detection model"}
MAX_RANGE_DAYS = 90


def _layout_key():
    return f"layout:{current_user.id}"


def get_layout():
    """UC-03 A2: per-administrator dashboard layout -> [(widget_id, title, visible)]."""
    saved = settings.get_raw(_layout_key()) or {}
    order = [w for w in saved.get("order", []) if w in WIDGETS] + [w for w in WIDGETS if w not in saved.get("order", [])]
    hidden = set(saved.get("hidden", []))
    return [(w, WIDGETS[w], w not in hidden) for w in order]


def _model_panel():
    m = _metrics() or {}
    key = settings.get("active_model")
    t = ((m.get("results") or {}).get(key) or {}).get("test") or {}
    return {"name": MODEL_CHOICES.get(key, key), "key": key, "threshold": settings.get("sensitivity_threshold"),
            "precision": t.get("precision"), "recall": t.get("recall"), "f1": t.get("f1"),
            "fp_per_hour": t.get("fp_alerts_per_hour"), "generated": m.get("generated_at")}


@bp.route("/")
@login_required
def overview():
    from .incidents import backfill
    backfill()
    return render_template("overview.html", threshold=settings.get("sensitivity_threshold"), layout=get_layout(),
                           widgets=WIDGETS, model=_model_panel(), max_days=MAX_RANGE_DAYS)


@bp.route("/dashboard/layout", methods=["POST"])
@login_required
def save_layout():
    """UC-03 A2 (show / hide / rearrange, saved per administrator) and E3 (invalid layout rejected)."""
    # CSRF is enforced globally by CSRFProtect
    ids = request.form.getlist("widget")
    try:
        pos = {w: int(request.form.get(f"pos_{w}", "")) for w in ids}
    except ValueError:
        pos = None
    shown = set(request.form.getlist("show"))
    if (not ids or pos is None or set(ids) != set(WIDGETS) or len(ids) != len(WIDGETS)
            or sorted(pos.values()) != list(range(1, len(WIDGETS) + 1)) or not shown or not shown <= set(WIDGETS)):
        flash("That layout is not valid (each widget needs a different position from 1 to "
              f"{len(WIDGETS)} and at least one widget must be shown). Your previous layout was kept.", "danger")
        return redirect(url_for("dash.overview"))
    order = sorted(ids, key=lambda w: pos[w])
    value = {"order": order, "hidden": [w for w in WIDGETS if w not in shown]}
    settings.put(_layout_key(), value)
    audit("Dashboard layout saved", user=current_user, **value)
    flash("Dashboard layout saved.", "info")
    return redirect(url_for("dash.overview"))


@bp.route("/dashboard/layout/reset", methods=["POST"])
@login_required
def reset_layout():
    """UC-03 A3."""
    # CSRF is enforced globally by CSRFProtect
    from .models import Setting
    row = db.session.get(Setting, _layout_key())
    if row:
        db.session.delete(row)
        db.session.commit()
    audit("Dashboard layout reset", user=current_user)
    flash("Dashboard layout reset to the default.", "info")
    return redirect(url_for("dash.overview"))


def _custom_range():
    """Returns (start, end, error) for range=custom (UC-03 step 4 + E1)."""
    try:
        start = datetime.fromisoformat(request.args.get("from", ""))
        end = datetime.fromisoformat(request.args.get("to", ""))
    except ValueError:
        return None, None, "Enter both a start and an end date and time for a custom range."
    if end <= start:
        return None, None, "The end of the time range must be after the start."
    if end - start > timedelta(days=MAX_RANGE_DAYS):
        return None, None, f"The time range cannot be longer than {MAX_RANGE_DAYS} days."
    return start, end, None


def live_alert_ids(ids):
    """Alerts raised from the live capture sensor (source kali-live) - tagged on the dashboard."""
    from .sensor import SOURCE
    if not ids:
        return set()
    rows = db.session.query(DetectionResult.alert_id).join(NetworkEvent, DetectionResult.event_id == NetworkEvent.id) \
        .join(IngestionJob, NetworkEvent.job_id == IngestionJob.id) \
        .filter(DetectionResult.alert_id.in_(ids), IngestionJob.source == SOURCE).distinct().all()
    return {r[0] for r in rows}


@bp.route("/api/summary")
@login_required
def summary():
    rng = request.args.get("range", "all")
    if rng not in RANGES and rng != "custom":
        return jsonify({"error": "invalid range"}), 400
    latest = db.session.query(func.max(NetworkEvent.observed_at)).scalar()
    q = NetworkEvent.query
    start = end = None
    if rng == "custom":
        start, end, err = _custom_range()
        if err:
            return jsonify({"error": err}), 400
        q = q.filter(NetworkEvent.observed_at >= start, NetworkEvent.observed_at < end)
    elif latest and RANGES[rng]:
        start = latest - RANGES[rng]
        q = q.filter(NetworkEvent.observed_at >= start)
    base = q.subquery()
    total = db.session.query(func.count()).select_from(base).scalar()
    flagged = db.session.query(func.count()).select_from(base).filter(base.c.flagged.is_(True)).scalar()
    minute = func.strftime("%Y-%m-%d %H:%M", base.c.observed_at)
    series = db.session.query(minute, func.count(), func.sum(db.case((base.c.flagged.is_(True), 1), else_=0))) \
        .group_by(minute).order_by(minute).all()
    sev = dict(db.session.query(base.c.severity, func.count()).filter(base.c.flagged.is_(True))
               .group_by(base.c.severity).all())
    ports = db.session.query(base.c.dst_port, func.count()).filter(base.c.flagged.is_(True)) \
        .group_by(base.c.dst_port).order_by(func.count().desc()).limit(10).all()
    srcs = db.session.query(base.c.src_ip, func.count()).filter(base.c.flagged.is_(True)) \
        .group_by(base.c.src_ip).order_by(func.count().desc()).limit(10).all()
    proto = dict(db.session.query(base.c.protocol, func.count()).group_by(base.c.protocol).all())
    aq = SecurityAlert.query
    if start:
        aq = aq.filter(SecurityAlert.last_seen >= start)
    if end:
        aq = aq.filter(SecurityAlert.first_seen < end)
    cats = dict(db.session.query(SecurityAlert.category, func.count()).filter(SecurityAlert.id.in_(
        aq.with_entities(SecurityAlert.id))).group_by(SecurityAlert.category).all())
    n_alerts = aq.count()
    grouped = db.session.query(func.coalesce(func.sum(SecurityAlert.occurrence_count), 0)).filter(
        SecurityAlert.id.in_(aq.with_entities(SecurityAlert.id))).scalar()
    recent = aq.order_by(SecurityAlert.last_seen.desc(), SecurityAlert.id.desc()).limit(8).all()
    last_recv = db.session.query(func.max(NetworkEvent.received_at)).scalar()
    run = SimulationRun.query.order_by(SimulationRun.id.desc()).first()
    health = "No data"
    if last_recv:
        age = (datetime.now() - last_recv).total_seconds()
        health = "Receiving" if age < 60 else "Idle"
    mode = settings.get("ip_display_mode")
    live = live_alert_ids([a.id for a in recent])
    return jsonify({
        "range": rng, "latest_event": str(latest) if latest else None,
        "tiles": {"events": total, "flagged": flagged, "alerts": n_alerts, "grouped_detections": int(grouped or 0),
                  "flag_rate": round(100 * flagged / total, 2) if total else 0,
                  "critical_open": SecurityAlert.query.filter_by(severity="Critical", status="Open").count(),
                  "ingest_status": health, "last_received": str(last_recv)[:19] if last_recv else None,
                  "threshold": settings.get("sensitivity_threshold")},
        "series": {"labels": [s[0] for s in series], "events": [s[1] for s in series],
                   "flagged": [int(s[2] or 0) for s in series]},
        "severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "categories": cats, "protocols": proto,
        "top_ports": [[str(p), c] for p, c in ports], "top_sources": [[display(s, mode), c] for s, c in srcs],
        "recent_alerts": [{"id": a.id, "severity": a.severity, "category": a.category, "src": display(a.src_ip, mode),
                           "dst": display(a.dst_ip, mode), "count": a.occurrence_count, "last_seen": str(a.last_seen),
                           "simulated": a.is_simulated, "live": a.id in live} for a in recent],
        "replay": {"id": run.id, "status": run.status, "events": run.events_sent,
                   "alerts": run.alerts_raised} if run else None,
        "incidents": [{"id": i.id, "title": i.title, "severity": i.severity, "status": i.status,
                       "created": i.created_at.strftime("%Y-%m-%d %H:%M"), "simulated": i.is_simulated}
                      for i in Incident.query.order_by(Incident.created_at.desc(), Incident.id.desc()).limit(6)],
    })


@bp.route("/events")
@login_required
def events():
    sev = request.args.get("severity")
    page = max(int(request.args.get("page", 1)), 1)
    q = NetworkEvent.query.filter(NetworkEvent.flagged.is_(True))
    if sev in SEVERITIES:
        q = q.filter(NetworkEvent.severity == sev)
    q = q.order_by(NetworkEvent.observed_at.desc(), NetworkEvent.id.desc())
    pg = q.paginate(page=page, per_page=50, error_out=False)
    ids = [e.id for e in pg.items]
    dets = {}
    for d in DetectionResult.query.filter(DetectionResult.event_id.in_(ids)).all():
        dets.setdefault(d.event_id, []).append(d)
    return render_template("events.html", page=pg, dets=dets, sev=sev)


@bp.route("/alerts")
@login_required
def alerts():
    sev = request.args.get("severity")
    q = SecurityAlert.query
    if sev in SEVERITIES:
        q = q.filter(SecurityAlert.severity == sev)
    page = max(int(request.args.get("page", 1)), 1)
    order = ((SecurityAlert.occurrence_count.desc(),) if request.args.get("sort") == "occurrences"
             else (SecurityAlert.last_seen.desc(), SecurityAlert.id.desc()))
    pg = q.order_by(*order).paginate(
        page=page, per_page=50, error_out=False)
    return render_template("alerts.html", page=pg, sev=sev)


@bp.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    a = db.session.get(SecurityAlert, alert_id) or abort(404)
    dets = (DetectionResult.query.filter_by(alert_id=a.id).order_by(DetectionResult.id.desc()).limit(200).all())
    notes = Notification.query.filter_by(alert_id=a.id).order_by(Notification.id.desc()).all()
    reps = IncidentReport.query.filter_by(alert_id=a.id).order_by(IncidentReport.version.desc()).all()
    show = reps[0] if reps else None
    if request.args.get("report") and reps:
        show = next((r for r in reps if str(r.version) == request.args["report"]), show)
    from .incidents import for_alert
    detectors = sorted({(d.detector or "", d.model_version or "", d.detector_type or "") for d in dets})
    return render_template("alert_detail.html", a=a, dets=dets, notes=notes, reports=reps, report=show,
                           detectors=detectors, incident=for_alert(a.id),
                           llm_configured=bool(current_app.config.get("LLM_API_KEY")))


@bp.route("/alerts/<int:alert_id>/report", methods=["POST"])
@login_required
def generate_report(alert_id):
    from flask_wtf.csrf import validate_csrf
    from wtforms import ValidationError
    try:
        validate_csrf(request.form.get("csrf_token"))
    except ValidationError:
        abort(400)
    a = db.session.get(SecurityAlert, alert_id) or abort(404)
    rep = incident_reports.generate(a, user=current_user)
    flash(f"Incident report v{rep.version} generated ({rep.label}).", "info" if not rep.error else "warning")
    return redirect(url_for("dash.alert_detail", alert_id=a.id, report=rep.version) + "#report")


@bp.route("/models")
@login_required
def models():
    from .incidents import false_positive_cases
    return render_template("models.html", m=_metrics(), threshold=settings.get("sensitivity_threshold"),
                           active_model=settings.get("active_model"), choices=MODEL_CHOICES,
                           previous_model=settings.get("previous_active_model"), analyst_fps=false_positive_cases(),
                           available=available_models(), explain_method=_explain_method(),
                           plots={p.name for p in Path(current_app.config["METRICS_PATH"]).parent.glob("*.png")})


def _explain_method():
    from ml.explain import SAABAS_METHOD, SHAP_METHOD, shap_available
    return SHAP_METHOD if shap_available() else SAABAS_METHOD


# ------------------------------------------------------------------ live push (SSE)
def _latest_ids():
    return {"event_id": db.session.query(func.max(NetworkEvent.id)).scalar() or 0,
            "alert_id": db.session.query(func.max(SecurityAlert.id)).scalar() or 0,
            "alert_updated": str(db.session.query(func.max(SecurityAlert.updated_at)).scalar() or "")}


@bp.route("/api/stream")
@login_required
def stream():
    """Server-Sent Events: emits a 'tick' whenever new events/alerts are stored (from uploads, replay or the
    streaming collectors - even in another process, since it watches the database). The connection closes
    after STREAM_SECONDS so authentication is re-checked on the browser's automatic reconnect."""
    max_s = float(current_app.config.get("STREAM_SECONDS", 60))
    interval = float(current_app.config.get("STREAM_POLL_SECONDS", 1.0))

    @stream_with_context
    def gen():
        last, started, keep = None, time.time(), time.time()
        yield "retry: 3000\n\n"
        while time.time() - started < max_s:
            cur = _latest_ids()
            db.session.remove()  # don't hold a connection/snapshot open between polls
            if cur != last:
                yield f"event: tick\ndata: {json.dumps(cur)}\n\n"
                last, keep = cur, time.time()
            elif time.time() - keep > 15:
                yield ": keep-alive\n\n"
                keep = time.time()
            time.sleep(interval)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ geo-map
@bp.route("/map")
@login_required
def geo_map():
    c = current_app.config
    return render_template("map.html", attribution=ATTRIBUTION, has_db=Path(c["GEOIP_DB"]).exists(),
                           site={"name": c["SITE_NAME"], "lat": c["SITE_LAT"], "lon": c["SITE_LON"]})


@bp.route("/api/geo")
@login_required
def geo_data():
    """Flagged source/destination pairs (from alerts) with locations for the map."""
    c = current_app.config
    site = {"name": c["SITE_NAME"], "lat": c["SITE_LAT"], "lon": c["SITE_LON"]}
    mode = settings.get("ip_display_mode")
    limit = min(int(request.args.get("limit", 500)), 2000)
    q = SecurityAlert.query
    sev = request.args.get("severity")
    if sev in SEVERITIES:
        q = q.filter(SecurityAlert.severity == sev)
    alerts = q.order_by(SecurityAlert.last_seen.desc(), SecurityAlert.id.desc()).limit(limit).all()
    points, lines, unknown = {}, [], 0
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    for a in alerts:
        ends = []
        for role, ip in (("source", a.src_ip), ("destination", a.dst_ip)):
            g = locate(ip, c["GEOIP_DB"], site)
            if not g:
                unknown += 1
                ends.append(None)
                continue
            key = display(ip, mode)
            p = points.setdefault(key, {"ip": key, "lat": g["lat"], "lon": g["lon"], "internal": g["internal"],
                                        "place": ", ".join(x for x in (g.get("city"), g.get("country")) if x),
                                        "roles": [], "alerts": 0, "severity": a.severity})
            if role not in p["roles"]:
                p["roles"].append(role)
            p["alerts"] += 1
            if rank.get(a.severity, 0) > rank.get(p["severity"], 0):
                p["severity"] = a.severity
            ends.append(g)
        if all(ends):
            lines.append({"from": [ends[0]["lat"], ends[0]["lon"]], "to": [ends[1]["lat"], ends[1]["lon"]],
                          "severity": a.severity, "id": a.id, "category": a.category,
                          "label": f"{display(a.src_ip, mode)} → {display(a.dst_ip, mode)}",
                          "count": a.occurrence_count})
    return jsonify({"points": list(points.values()), "lines": lines, "unknown_locations": unknown,
                    "site": site, "geoip_db": Path(c["GEOIP_DB"]).exists()})


@bp.route("/reports/<path:name>")
@login_required
def report_file(name):
    if not name.endswith(".png"):
        abort(404)
    return send_from_directory(Path(current_app.config["METRICS_PATH"]).parent, name)


@bp.route("/datasets")
@login_required
def datasets():
    return render_template("datasets.html", datasets=Dataset.query.all(),
                           runs=SimulationRun.query.order_by(SimulationRun.id.desc()).limit(20).all())


class UploadForm(FlaskForm):
    file = FileField("Log file", validators=[FileRequired()])


UPLOAD_HELP = {
    "cicids2017": "CIC-IDS2017 / CICFlowMeter CSV. Required columns: Timestamp, Source/Destination IP, "
                  "Source/Destination Port, Protocol and the mapped flow statistics.",
    "syslog": "Plain-text syslog, one message per line (RFC 3164 or RFC 5424). Network events are extracted from "
              "iptables / UFW / netfilter key=value lines (SRC=, DST=, PROTO=, SPT=, DPT=, LEN=, WINDOW=); each "
              "logged packet becomes one event. Lines without network fields are counted and skipped.",
    "netflow_v5": "Raw NetFlow v5 export datagrams concatenated (e.g. a capture of UDP payloads). Live export: "
                  "point the exporter at the collector on UDP 2055.",
    "nfdump_csv": "nfdump CSV: nfdump -r nfcapd.xxx -o csv > flows.csv (columns ts, td, sa, da, sp, dp, pr, flg, "
                  "ipkt, ibyt, opkt, obyt). The summary block at the end is ignored.",
    "pcap": "Packet capture (.pcap or .pcapng, Ethernet / loopback / raw IP / Linux cooked). Packets are aggregated "
            "into bidirectional flows; payloads are discarded and never stored.",
}


CSV_PROFILES = ("cicids2017", "nfdump_csv")


def _missing_text(cols):
    shown = ", ".join(cols[:8])
    return shown + (f" and {len(cols) - 8} more" if len(cols) > 8 else "")


def _looks_binary(data: bytes) -> bool:
    head = data[:4096]
    return not head.strip() or b"\x00" in head or b"," not in head.split(b"\n", 1)[0]


def _upload_error(profile, form, msg, name=None):
    audit("File upload rejected", user=current_user, profile=profile, filename=name, reason=msg[:200])
    jobs = IngestionJob.query.filter_by(profile=profile).order_by(IngestionJob.id.desc()).limit(20).all()
    return render_template("upload.html", form=form, profile=profile, adapters=ADAPTERS, jobs=jobs,
                           help=UPLOAD_HELP.get(profile, ADAPTERS[profile].description), error=msg), 400


def _do_upload(profile, form):
    """UC-08 main flow + E1 (unsupported file), E2 (missing fields), E3 (invalid rows), E5 (capture rejected), A3."""
    f = form.file.data
    name = Path(f.filename or "upload").name
    exts = ADAPTERS[profile].extensions
    if exts and not name.lower().endswith(tuple(exts)):
        return _upload_error(profile, form, f"Unsupported file type: {profile} uploads must end in "
                                            f"{', '.join(exts)}. Nothing was stored.", name)
    data = f.read()
    if profile in CSV_PROFILES and _looks_binary(data):
        return _upload_error(profile, form, "Unsupported file: this is not a readable CSV file. Nothing was stored.",
                             name)
    try:
        job, stats = ingest_bytes(data, name, source="upload", profile=profile, user=current_user)
    except Exception as e:  # noqa: BLE001 - a malformed file must never crash the page
        db.session.rollback()
        current_app.logger.warning("upload failed: %s", e)
        return _upload_error(profile, form, "Unsupported file: it could not be read. Nothing was stored.", name)
    audit("File uploaded", user=current_user, profile=profile, filename=name, job_id=job.id,
          accepted=job.accepted, rejected=job.rejected, status=job.status)
    if job.status == "Rejected":
        missing = (job.reasons or {}).get("missing_required_columns", [])
        if profile == "pcap":
            return _upload_error(profile, form, "Capture file rejected: it is not a readable .pcap or .pcapng "
                                                f"capture ({', '.join(missing)}). Nothing was stored.", name)
        return _upload_error(profile, form, f"Rejected - missing required fields: {_missing_text(missing)}. "
                                            "Nothing was stored.", name)
    reasons = "; ".join(f"{k.replace('_', ' ')}: {v}" for k, v in (job.reasons or {}).items())
    flash(f"{name}: {job.accepted:,} records accepted, {job.rejected:,} rejected"
          + (f" ({reasons})" if reasons else "") + f". Flagged {stats['flagged']:,}, new alerts {stats['alerts_new']:,}.",
          "info" if not job.rejected else "warning")
    if request.form.get("save_dataset") and profile == "cicids2017":  # UC-08 A3
        from .simulator import store_dataset
        ds, err = store_dataset((request.form.get("ds_name") or name).strip()[:128],
                                (request.form.get("ds_origin") or "").strip()[:500] or f"Uploaded by {current_user.email}",
                                (request.form.get("ds_licence") or "").strip()[:500] or "Not stated",
                                data, name, kind="upload")
        flash(err if err else f"Saved as replay dataset {ds.name!r} - choose it in the Simulator.",
              "danger" if err else "info")
    return redirect(url_for("dash.upload", profile=profile))


@bp.route("/sources/upload/<profile>", methods=["GET", "POST"])
@login_required
def upload(profile):
    if profile not in ADAPTERS:
        abort(404)
    form = UploadForm()
    if form.validate_on_submit():
        return _do_upload(profile, form)
    jobs = IngestionJob.query.filter_by(profile=profile).order_by(IngestionJob.id.desc()).limit(20).all()
    return render_template("upload.html", form=form, profile=profile, adapters=ADAPTERS, jobs=jobs,
                           help=UPLOAD_HELP.get(profile, ADAPTERS[profile].description), error=None)


@bp.route("/sources", methods=["GET", "POST"])
@login_required
def sources():
    form = UploadForm()
    if form.validate_on_submit():  # legacy single-form upload = CIC-IDS2017 CSV
        return _do_upload(request.form.get("profile", "cicids2017") if request.form.get("profile") in ADAPTERS
                          else "cicids2017", form)
    jobs = IngestionJob.query.order_by(IngestionJob.id.desc()).limit(50).all()
    from . import pcap_watch
    svc = current_app.extensions.get("collectors")
    watch = pcap_watch.status()
    rows = [_source_row("File upload", "upload", ", ".join(ADAPTERS)),
            _source_row("Ingest API (log shippers)", "api", "cicids2017, syslog, nfdump_csv, netflow_v5, pcap"),
            _source_row("Replay simulator", "replay", "CIC-IDS2017 test days, lab captures"),
            _source_row("Streaming collectors", "stream:%", f"syslog UDP/TCP {current_app.config['SYSLOG_UDP_PORT']}, "
                        f"NetFlow v5 UDP {current_app.config['NETFLOW_UDP_PORT']}", running=bool(svc)),
            _source_row("Live capture sensor (Kali)", "kali-live",
                        "pcap chunks to /sensor/v1/pcap" + (f" on {current_app.config['SENSOR_BIND']}:{current_app.config['SENSOR_PORT']}"
                                                              if current_app.extensions.get("sensor_server") else " (port 5000 only)")),
            _source_row("Interval capture (.pcap)", pcap_watch.SOURCE,
                        f"pcap every {watch['interval'] // 60} min from the capture folder", running=watch["running"])]
    return render_template("sources.html", form=form, jobs=jobs, rows=rows, adapters=ADAPTERS,
                           collectors=svc.stats() if svc else None, watch=watch, cfg=current_app.config)


def _source_row(name, source, formats, running=False):
    """UC-08 step 2: status (Active / Paused / Error), events in the last hour and the last event per source."""
    match = IngestionJob.source.like(source) if "%" in source else IngestionJob.source == source
    job_ids = db.session.query(IngestionJob.id).filter(match)
    hour_ago = datetime.now() - timedelta(hours=1)
    last_hour = NetworkEvent.query.filter(NetworkEvent.job_id.in_(job_ids), NetworkEvent.received_at >= hour_ago).count()
    last = db.session.query(func.max(NetworkEvent.received_at)).filter(NetworkEvent.job_id.in_(job_ids)).scalar()
    last_job = IngestionJob.query.filter(match).order_by(IngestionJob.id.desc()).first()
    error = None
    if last_job and last_job.status in ("Rejected", "Failed") and last_job.created_at >= datetime.now() - timedelta(hours=24):
        status, error = "Error", f"last file {last_job.filename} was {last_job.status.lower()}"
    elif running or (last and (datetime.now() - last).total_seconds() < 300):
        status = "Active"
    else:
        status = "Paused"
    return {"name": name, "formats": formats, "status": status, "last_hour": last_hour, "last": last, "error": error}


@bp.route("/sources/pcap/scan", methods=["POST"])
@login_required
def pcap_scan():
    # CSRF is enforced globally by CSRFProtect
    from . import pcap_watch
    done = pcap_watch.scan_once()
    audit("Capture folder checked", user=current_user, files=len(done))
    if not done:
        flash("No finished capture files are waiting in the capture folder.", "info")
    for name, st, acc, rej in done:
        flash(f"{name}: {st}." + (f" {acc:,} flows accepted, {rej:,} rejected; the raw capture was deleted."
                                   if st != "Rejected" else " Capture file rejected - moved to the rejected folder."),
              "info" if st != "Rejected" else "danger")
    return redirect(url_for("dash.sources"))
