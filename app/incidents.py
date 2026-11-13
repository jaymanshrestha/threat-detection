"""Incidents (FR-09; v5 report UC-04 A3-A7 and UC-10 "Review Incident Timeline and Reports").

An incident groups one or more related alerts. High and Critical alerts open an incident automatically
and get an AI report when the incident is first opened; Medium and Low alerts can be added by hand
(UC-10 A2). Status changes, notes, report edits and merges are audit-logged and never delete history."""
from datetime import datetime, timedelta

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from alerts.severity import RANK, SEVERITIES

from . import reports as incident_reports
from .extensions import db
from .models import INCIDENT_STATUSES, Incident, IncidentAlert, IncidentReport, SecurityAlert
from .security import audit

bp = Blueprint("inc", __name__)
AUTO_SEVERITIES = ("High", "Critical")
CLOSED = ("Resolved", "False Positive")
CONFLICT = ("This incident was changed by another administrator while you were editing. "
            "Your change was not saved - the latest version is shown below.")


# ---------------------------------------------------------------- service ----
def for_alert(alert_id):
    link = IncidentAlert.query.filter_by(alert_id=alert_id).first()
    return db.session.get(Incident, link.incident_id) if link else None


def alerts_of(inc):
    ids = [x.alert_id for x in IncidentAlert.query.filter_by(incident_id=inc.id)]
    return SecurityAlert.query.filter(SecurityAlert.id.in_(ids)).order_by(SecurityAlert.max_risk.desc()).all() if ids else []


def _recompute(inc):
    al = alerts_of(inc)
    if al:
        inc.severity = max((a.severity for a in al), key=lambda s: RANK.get(s, -1))
        inc.is_simulated = all(a.is_simulated for a in al)


def open_for(alert, user=None, auto=False):
    inc = for_alert(alert.id)
    if inc:
        return inc, False
    inc = Incident(title=alert.category, severity=alert.severity, status="New", primary_alert_id=alert.id,
                   is_simulated=bool(alert.is_simulated), created_by=getattr(user, "id", None))
    db.session.add(inc)
    db.session.flush()
    db.session.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id))
    audit("Incident opened" + (" automatically" if auto else ""), user=user, commit=False,
          incident_id=inc.id, alert_id=alert.id, severity=alert.severity)
    return inc, True


def auto_open(alerts):
    """Called by the pipeline after alert grouping; also used to back-fill older alerts."""
    n = 0
    for a in alerts:
        if a is not None and a.severity in AUTO_SEVERITIES:
            n += open_for(a, auto=True)[1]
        elif a is not None and (inc := for_alert(a.id)):
            _recompute(inc)
    if n:
        db.session.commit()
    return n


def backfill(limit=2000):
    linked = db.session.query(IncidentAlert.alert_id)
    todo = (SecurityAlert.query.filter(SecurityAlert.severity.in_(AUTO_SEVERITIES), ~SecurityAlert.id.in_(linked))
            .order_by(SecurityAlert.id).limit(limit).all())
    return auto_open(todo)


def latest_report(inc):
    return (IncidentReport.query.filter_by(alert_id=inc.primary_alert_id)
            .order_by(IncidentReport.version.desc()).first())


def _stale(inc):
    try:
        return int(request.form.get("revision", "0")) != inc.revision
    except ValueError:
        return True


def _bump(inc):
    inc.revision = (inc.revision or 1) + 1
    inc.updated_at = datetime.now()


def false_positive_cases(limit=20):
    """UC-04 A7: alerts in incidents marked False Positive feed the model's failure-case list (UC-06)."""
    rows = []
    for inc in Incident.query.filter_by(status="False Positive").order_by(Incident.updated_at.desc()).limit(limit):
        for a in alerts_of(inc):
            rows.append((inc, a))
    return rows


# ----------------------------------------------------------------- routes ----
def _parse_day(v, end=False):
    try:
        d = datetime.strptime(v, "%Y-%m-%d")
        return d + timedelta(days=1) if end else d
    except (TypeError, ValueError):
        return None


@bp.route("/incidents")
@login_required
def incidents():
    """UC-10 main flow: timeline newest first, filter by severity, status and date."""
    backfill()
    sev, status = request.args.get("severity", ""), request.args.get("status", "")
    d_from, d_to = request.args.get("from", ""), request.args.get("to", "")
    q = Incident.query
    if sev in SEVERITIES:
        q = q.filter(Incident.severity == sev)
    if status in INCIDENT_STATUSES:
        q = q.filter(Incident.status == status)
    if _parse_day(d_from):
        q = q.filter(Incident.created_at >= _parse_day(d_from))
    if _parse_day(d_to, end=True):
        q = q.filter(Incident.created_at < _parse_day(d_to, end=True))
    page = max(request.args.get("page", 1, type=int), 1)
    pg = q.order_by(Incident.created_at.desc(), Incident.id.desc()).paginate(page=page, per_page=30, error_out=False)
    info = {}
    for inc in pg.items:
        al = alerts_of(inc)
        info[inc.id] = {"alerts": al, "primary": next((a for a in al if a.id == inc.primary_alert_id), al[0] if al else None),
                        "report": latest_report(inc)}
    counts = {s: Incident.query.filter_by(status=s).count() for s in INCIDENT_STATUSES}
    return render_template("incidents.html", page=pg, info=info, sev=sev, status=status, d_from=d_from, d_to=d_to,
                           statuses=INCIDENT_STATUSES, counts=counts,
                           filtered=bool(sev or status or d_from or d_to))


@bp.route("/incidents/<int:iid>")
@login_required
def incident_detail(iid):
    inc = db.session.get(Incident, iid) or abort(404)
    al = alerts_of(inc)
    primary = db.session.get(SecurityAlert, inc.primary_alert_id)
    reps = (IncidentReport.query.filter_by(alert_id=inc.primary_alert_id)
            .order_by(IncidentReport.version.desc()).all())
    if not reps and inc.severity in AUTO_SEVERITIES and primary is not None:
        # UC-04 A3: Critical/High incidents get a report automatically when first opened
        reps = [incident_reports.generate(primary, user=None, incident=inc)]
    show = reps[0] if reps else None
    if request.args.get("report") and reps:
        show = next((r for r in reps if str(r.version) == request.args["report"]), show)
    linked = db.session.query(IncidentAlert.alert_id)
    candidates = (SecurityAlert.query.filter(~SecurityAlert.id.in_(linked))
                  .order_by(SecurityAlert.last_seen.desc()).limit(50).all())
    from .models import AuditLog
    history = [e for e in AuditLog.query.filter(AuditLog.action.like("Incident%")).order_by(AuditLog.id.desc()).limit(400)
               if (e.details or {}).get("incident_id") == inc.id][:30]
    return render_template("incident_detail.html", inc=inc, alerts=al, primary=primary, reports=reps, report=show,
                           statuses=INCIDENT_STATUSES, candidates=candidates, history=history,
                           llm_configured=bool(current_app.config.get("LLM_API_KEY")),
                           edit=request.args.get("edit") == "1")


@bp.route("/alerts/<int:alert_id>/incident", methods=["POST"])
@login_required
def open_incident(alert_id):
    """UC-10 A2 / UC-04 A3: open an incident for an alert of any severity."""
    a = db.session.get(SecurityAlert, alert_id) or abort(404)
    inc, created = open_for(a, user=current_user)
    db.session.commit()
    flash(f"Incident #{inc.id} opened for alert #{a.id}." if created else f"Alert #{a.id} is already in incident #{inc.id}.",
          "info")
    return redirect(url_for("inc.incident_detail", iid=inc.id))


@bp.route("/incidents/<int:iid>/status", methods=["POST"])
@login_required
def set_status(iid):
    """UC-04 A7 + E3 + E4."""
    inc = db.session.get(Incident, iid) or abort(404)
    if _stale(inc):
        flash(CONFLICT, "warning")
        return redirect(url_for("inc.incident_detail", iid=iid))
    new, note = request.form.get("status", ""), (request.form.get("note") or "").strip()[:2000]
    if new not in INCIDENT_STATUSES:
        flash("Choose a valid status.", "danger")
        return redirect(url_for("inc.incident_detail", iid=iid))
    if new in CLOSED and not note:
        flash(f"Add a note explaining why the incident is {new.lower()} before closing it.", "danger")
        return redirect(url_for("inc.incident_detail", iid=iid))
    old = inc.status
    inc.status = new
    if note:
        inc.resolution_note = note
    for a in alerts_of(inc):
        a.status = "Closed" if new in CLOSED else ("Open" if new == "New" else new)
    _bump(inc)
    audit("Incident status changed", user=current_user, commit=False, incident_id=inc.id, old=old, new=new,
          note=note or None)
    db.session.commit()
    flash(f"Incident #{inc.id} is now {new}." + (" Its alerts were added to the model's failure cases."
                                                   if new == "False Positive" else ""), "info")
    return redirect(url_for("inc.incident_detail", iid=iid))


@bp.route("/incidents/<int:iid>/merge", methods=["POST"])
@login_required
def merge(iid):
    """UC-04 A6: merge related alerts into this incident (their own incidents are folded in)."""
    inc = db.session.get(Incident, iid) or abort(404)
    if _stale(inc):
        flash(CONFLICT, "warning")
        return redirect(url_for("inc.incident_detail", iid=iid))
    ids = [int(x) for x in request.form.getlist("alert_ids") if x.isdigit()]
    added = []
    for aid in ids:
        a = db.session.get(SecurityAlert, aid)
        if not a:
            continue
        link = IncidentAlert.query.filter_by(alert_id=aid).first()
        if link and link.incident_id == inc.id:
            continue
        if link:
            old = db.session.get(Incident, link.incident_id)
            link.incident_id = inc.id
            if old and not IncidentAlert.query.filter(IncidentAlert.incident_id == old.id,
                                                      IncidentAlert.alert_id != aid).first():
                old.status, old.resolution_note = "Resolved", f"Merged into incident #{inc.id}"
                _bump(old)
        else:
            db.session.add(IncidentAlert(incident_id=inc.id, alert_id=aid))
        added.append(aid)
    if not added:
        flash("Select at least one alert to merge.", "danger")
        return redirect(url_for("inc.incident_detail", iid=iid))
    db.session.flush()
    _recompute(inc)
    _bump(inc)
    audit("Incident alerts merged", user=current_user, commit=False, incident_id=inc.id, alert_ids=added)
    db.session.commit()
    flash(f"Merged {len(added)} alert(s) into incident #{inc.id}.", "info")
    return redirect(url_for("inc.incident_detail", iid=iid))


@bp.route("/incidents/<int:iid>/report", methods=["POST"])
@login_required
def request_report(iid):
    """UC-10 A2: request (or regenerate) the report for any incident."""
    inc = db.session.get(Incident, iid) or abort(404)
    primary = db.session.get(SecurityAlert, inc.primary_alert_id) or abort(404)
    rep = incident_reports.generate(primary, user=current_user, incident=inc)
    flash(f"Incident report v{rep.version} created - {rep.label}.", "info" if not rep.error else "warning")
    return redirect(url_for("inc.incident_detail", iid=iid, report=rep.version) + "#report")


def _lines(v, n=8, ln=400):
    return [x.strip()[:ln] for x in (v or "").splitlines() if x.strip()][:n]


@bp.route("/incidents/<int:iid>/report/edit", methods=["POST"])
@login_required
def edit_report(iid):
    """UC-04 A5: save an edited copy as a new version; the AI original is kept unchanged."""
    inc = db.session.get(Incident, iid) or abort(404)
    if _stale(inc):
        flash(CONFLICT, "warning")
        return redirect(url_for("inc.incident_detail", iid=iid) + "#report")
    base = latest_report(inc) or abort(400)
    f = request.form
    content = {
        "what_happened": (f.get("what_happened") or "").strip()[:2000],
        "likely_impact": (f.get("likely_impact") or "").strip()[:2000],
        "confidence": f.get("confidence") if f.get("confidence") in incident_reports.CONFIDENCE else base.content.get("confidence"),
        "confidence_rationale": (f.get("confidence_rationale") or "").strip()[:2000],
        "recommended_next_steps": _lines(f.get("recommended_next_steps")),
        "unverified_claims": _lines(f.get("unverified_claims")),
    }
    if not content["what_happened"]:
        flash("The report needs a 'What happened' section.", "danger")
        return redirect(url_for("inc.incident_detail", iid=iid, edit=1) + "#report")
    version = IncidentReport.query.filter_by(alert_id=inc.primary_alert_id).count() + 1
    rep = IncidentReport(alert_id=inc.primary_alert_id, incident_id=inc.id, version=version,
                         generator=f"Edited by {current_user.email}",
                         label=f"Edited by an administrator from v{base.version} - original kept",
                         facts=base.facts, content=content, administrator_id=current_user.id)
    db.session.add(rep)
    _bump(inc)
    db.session.flush()
    audit("Incident report edited", user=current_user, commit=False, incident_id=inc.id, report_id=rep.id,
          version=version, based_on=base.version)
    db.session.commit()
    flash(f"Saved your edits as report v{version}. v{base.version} is unchanged.", "info")
    return redirect(url_for("inc.incident_detail", iid=iid, report=version) + "#report")
