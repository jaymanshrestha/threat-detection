"""Replay simulator screen (v5 report UC-02 "Replay a Dataset Simulation", FR-05).

Streams a stored dataset through the same ingestion pipeline as live sources, one dataset-minute per
batch, at 1x / 10x / 100x speed. Everything it produces is stored with is_simulated=True and labelled
SIMULATED. Only held-out CIC-IDS2017 test-day files, or lab captures / uploads that an administrator
registered with their origin, may be replayed. One replay runs at a time (UC-02 E1).

The command-line replayer (scripts/replay.py) is still available and uses the ingestion API."""
import csv
import io
import threading
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
from flask import (Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ingest.validate import parse_timestamps
from ml.data import FILES, RAW_DIR, SPLIT

from .extensions import db
from .models import Dataset, DetectionResult, IngestionJob, NetworkEvent, SecurityAlert, SimulationRun
from .security import audit

bp = Blueprint("sim", __name__)
TEST_FILES = [f for d in SPLIT["test"] for f in FILES[d]]
SPEEDS = (1, 10, 100)
ATTACK_FILTERS = ["DoS Hulk", "DoS GoldenEye", "DoS slowloris", "DoS Slowhttptest", "DDoS", "PortScan", "Bot",
                  "Infiltration", "Web Attack \x96 Brute Force", "Web Attack \x96 XSS", "Web Attack \x96 Sql Injection",
                  "FTP-Patator", "SSH-Patator", "Heartbleed"]
ACTIVE = ("Running", "Paused", "Stopping")
_threads = {}


def _label(f):
    return f.replace("\x96", "-")


def dataset_dir():
    d = Path(current_app.config["DATASET_DIR"])
    d.mkdir(parents=True, exist_ok=True)
    return d


def is_public(ds):
    return bool(ds.is_public) or (ds.kind or "public") == "public"


def sources():
    """Replayable (dataset, file) pairs that exist on disk."""
    out = []
    for ds in Dataset.query.order_by(Dataset.id).all():
        if is_public(ds) and ds.profile == "cicids2017":
            for f in TEST_FILES:
                p = RAW_DIR / f
                if p.exists():
                    out.append({"key": f"{ds.id}:{f}", "dataset": ds, "file": f, "path": p,
                                "size": p.stat().st_size, "label": f"{ds.name} · {f} (held-out test day)"})
        elif ds.file_path and Path(ds.file_path).exists():
            p = Path(ds.file_path)
            out.append({"key": f"{ds.id}:", "dataset": ds, "file": p.name, "path": p, "size": p.stat().st_size,
                        "label": f"{ds.name} · {(ds.kind or 'lab').capitalize()} dataset"})
    return out


def _fmt_size(n):
    return f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{n / 1e3:.0f} KB"


def prepare(path, start="", end="", attack_filter=""):
    """Returns (header, [(minute_label, [lines])]) in timestamp order, like scripts/replay.py."""
    text = Path(path).read_text(encoding="latin-1")
    lines = text.splitlines()
    if not lines:
        return "", []
    header, body = lines[0], [ln for ln in lines[1:] if ln.strip(", ")]
    cols = [c.strip().lower() for c in next(csv.reader(io.StringIO(header)))]
    if "timestamp" not in cols:  # not a flow CSV with timestamps -> fixed-size batches
        return header, [(f"batch {i // 500 + 1}", body[i:i + 500]) for i in range(0, len(body), 500)]
    ti = cols.index("timestamp")
    li = cols.index("label") if "label" in cols else None
    rows = list(csv.reader(io.StringIO("\n".join(body))))
    ts = parse_timestamps(pd.Series([r[ti] if len(r) > ti else "" for r in rows]), twelve_hour_fix=True)
    df = pd.DataFrame({"line": body, "ts": ts,
                       "label": [(r[li].strip() if li is not None and len(r) > li else "") for r in rows]}).dropna(
        subset=["ts"])
    if df.empty:
        return header, []
    day = df.ts.dt.normalize().iloc[0]
    if start:
        df = df[df.ts >= day + pd.Timedelta(start + ":00")]
    if end:
        df = df[df.ts < day + pd.Timedelta(end + ":00") + pd.Timedelta(minutes=1)]
    if attack_filter:
        df = df[df.label.isin(["BENIGN", attack_filter])]
    df = df.sort_values("ts", kind="stable")
    return header, [(f"{m:%H:%M}", list(g.line)) for m, g in df.groupby(df.ts.dt.floor("min"), sort=True)]


def _run_status(run_id):
    db.session.expire_all()
    r = db.session.get(SimulationRun, run_id)
    return r.status if r else "Stopping"


def _worker(app, run_id, header, batches, filename, profile, speed, sync=False):
    from .pipeline import ingest_bytes
    with app.app_context():
        status, err = "Completed", None
        try:
            for _minute, lines in batches:
                st = _run_status(run_id)
                while st == "Paused":  # UC-02 A2
                    time.sleep(0.5)
                    st = _run_status(run_id)
                if st != "Running":  # UC-02 A3 stop early (or superseded by the command-line replayer)
                    status = "Stopped"
                    break
                t0 = time.time()
                run = db.session.get(SimulationRun, run_id)
                payload = (header + "\n" + "\n".join(lines) + "\n").encode("latin-1", "replace")
                ingest_bytes(payload, filename, source="replay", profile=profile, run=run, simulated=True)
                if not sync:
                    wait = max(0.0, 60.0 / speed - (time.time() - t0))
                    while wait > 0 and _run_status(run_id) == "Running":
                        time.sleep(min(0.5, wait))
                        wait -= 0.5
        except Exception as e:  # noqa: BLE001 - record and finish the run cleanly
            status, err = "Failed", f"{type(e).__name__}: {str(e)[:300]}"
            app.logger.exception("replay failed")
            db.session.rollback()
        run = db.session.get(SimulationRun, run_id)
        if run:
            run.status, run.ended_at, run.error = status, datetime.now(), err
            db.session.commit()
            audit("Replay finished", actor=run.started_by or "replay-simulator", run_id=run.id,
                  events=run.events_sent, alerts=run.alerts_raised, status=status)
        _threads.pop(run_id, None)


def active_run():
    return SimulationRun.query.filter(SimulationRun.status.in_(ACTIVE)).order_by(SimulationRun.id.desc()).first()


def run_alerts(run):
    jobs = db.session.query(IngestionJob.id).filter(IngestionJob.run_id == run.id)
    ev = db.session.query(NetworkEvent.id).filter(NetworkEvent.job_id.in_(jobs))
    ids = db.session.query(DetectionResult.alert_id).filter(DetectionResult.event_id.in_(ev),
                                                            DetectionResult.alert_id.isnot(None)).distinct()
    return SecurityAlert.query.filter(SecurityAlert.id.in_(ids)).order_by(SecurityAlert.max_risk.desc())


def recover_orphans():
    """Runs started from this screen cannot survive an app restart; mark them stopped."""
    for r in SimulationRun.query.filter(SimulationRun.status.in_(ACTIVE), SimulationRun.started_by.isnot(None)):
        if r.id not in _threads:
            r.status, r.ended_at, r.error = "Stopped", r.ended_at or datetime.now(), "application restarted"
    db.session.commit()


# ----------------------------------------------------------------- routes ----
@bp.route("/simulator")
@login_required
def simulator():
    recover_orphans()
    srcs = sources()
    run = active_run()
    last = SimulationRun.query.order_by(SimulationRun.id.desc()).first()
    summary = last if last and last.status not in ACTIVE else None
    return render_template("simulator.html", sources=srcs, fmt_size=_fmt_size, speeds=SPEEDS,
                           attack_filters=ATTACK_FILTERS, label=_label, run=run, summary=summary,
                           summary_alerts=run_alerts(summary).limit(10).all() if summary else [],
                           runs=SimulationRun.query.order_by(SimulationRun.id.desc()).limit(10).all(),
                           datasets=Dataset.query.order_by(Dataset.id).all(), is_public=is_public)


@bp.route("/simulator/start", methods=["POST"])
@login_required
def start():
    if active_run():  # UC-02 E1
        flash("A replay is already in progress. Pause or stop it, or wait for it to finish, before starting another.",
              "danger")
        return redirect(url_for("sim.simulator"))
    key = request.form.get("source", "")
    src = next((s for s in sources() if s["key"] == key), None)
    try:
        speed = int(request.form.get("speed", "10"))
    except ValueError:
        speed = 0
    if not src or speed not in SPEEDS:
        flash("Choose a dataset and a speed of 1x, 10x or 100x.", "danger")
        return redirect(url_for("sim.simulator"))
    flt = request.form.get("attack_filter", "")
    flt = flt if flt in ATTACK_FILTERS else ""
    t_start, t_end = request.form.get("start", "").strip(), request.form.get("end", "").strip()
    for t in (t_start, t_end):
        if t and not (len(t) == 5 and t[2] == ":" and t[:2].isdigit() and t[3:].isdigit()):
            flash("Times must be HH:MM (dataset time), or left blank for the whole file.", "danger")
            return redirect(url_for("sim.simulator"))
    header, batches = prepare(src["path"], t_start, t_end, flt)
    if not batches:
        flash("No rows in the selected window - widen the time range or remove the attack filter.", "danger")
        return redirect(url_for("sim.simulator"))
    ds = src["dataset"]
    run = SimulationRun(dataset=ds.name, dataset_id=ds.id, file=src["file"], speed=speed, attack_filter=flt or None,
                        status="Running", started_by=current_user.email,
                        events_planned=sum(len(b[1]) for b in batches))
    db.session.add(run)
    db.session.commit()
    from .pipeline import reset_window
    reset_window()
    audit("Replay started", user=current_user, run_id=run.id, dataset=ds.name, file=src["file"], speed=speed,
          attack_filter=flt or None, window=f"{t_start or 'start'}-{t_end or 'end'}", minutes=len(batches))
    app = current_app._get_current_object()
    args = (app, run.id, header, batches, src["file"], ds.profile or "cicids2017", speed)
    if app.config.get("SIMULATOR_SYNC"):
        _worker(*args, sync=True)
    else:
        t = threading.Thread(target=_worker, args=args, name=f"replay-{run.id}", daemon=True)
        _threads[run.id] = t
        t.start()
    flash(f"Replay #{run.id} started at {speed}x: {len(batches)} dataset-minute(s), "
          f"{run.events_planned:,} events. Everything it produces is labelled SIMULATED.", "info")
    return redirect(url_for("sim.simulator"))


def _set(run_id, allowed, new, verb):
    run = db.session.get(SimulationRun, run_id) or abort(404)
    if run.status not in allowed:
        flash(f"Replay #{run.id} is {run.status.lower()} and cannot be {verb}.", "danger")
        return redirect(url_for("sim.simulator"))
    run.status = new
    db.session.commit()
    audit(f"Replay {verb}", user=current_user, run_id=run.id)
    if new == "Stopping" and run.id not in _threads:  # started elsewhere or orphaned -> finish now
        run.status, run.ended_at = "Stopped", datetime.now()
        db.session.commit()
    flash(f"Replay #{run.id} {verb}.", "info")
    return redirect(url_for("sim.simulator"))


@bp.route("/simulator/runs/<int:run_id>/pause", methods=["POST"])
@login_required
def pause(run_id):
    return _set(run_id, ("Running",), "Paused", "paused")


@bp.route("/simulator/runs/<int:run_id>/resume", methods=["POST"])
@login_required
def resume(run_id):
    return _set(run_id, ("Paused",), "Running", "resumed")


@bp.route("/simulator/runs/<int:run_id>/stop", methods=["POST"])
@login_required
def stop(run_id):
    return _set(run_id, ("Running", "Paused"), "Stopping", "stopped")


@bp.route("/simulator/runs/<int:run_id>/status")
@login_required
def status(run_id):
    run = db.session.get(SimulationRun, run_id) or abort(404)
    return jsonify({"id": run.id, "status": run.status, "events_sent": run.events_sent or 0,
                    "events_planned": run.events_planned or 0, "alerts_raised": run.alerts_raised or 0})


@bp.route("/simulator/runs/<int:run_id>")
@login_required
def run_detail(run_id):
    run = db.session.get(SimulationRun, run_id) or abort(404)
    return render_template("simulator_run.html", run=run, alerts=run_alerts(run).limit(200).all())


# ---------------------------------------------- lab datasets (UC-02 A1 / A6) ----
@bp.route("/datasets/lab", methods=["POST"])
@login_required
def register_lab():
    """UC-02 A1: register a lab capture; E2 an authorisation reference is required."""
    name = (request.form.get("name") or "").strip()[:128]
    auth_ref = (request.form.get("authorisation_ref") or "").strip()[:255]
    origin = (request.form.get("origin") or "").strip()[:500]
    licence = (request.form.get("licence") or "").strip()[:500] or "Internal lab capture - not for redistribution"
    f = request.files.get("file")
    if not auth_ref:
        flash("A written authorisation reference is required before a lab capture can be stored.", "danger")
        return redirect(url_for("dash.datasets") + "#lab")
    if not name or not origin or not f or not f.filename:
        flash("Enter a name, origin and choose a CSV file for the lab capture.", "danger")
        return redirect(url_for("dash.datasets") + "#lab")
    return save_dataset(name, origin, licence, f.read(), Path(f.filename).name, kind="lab", auth_ref=auth_ref,
                        back=url_for("dash.datasets"))


def save_dataset(name, origin, licence, data, filename, kind, auth_ref=None, back=None, profile="cicids2017"):
    ds, err = store_dataset(name, origin, licence, data, filename, kind, auth_ref, profile)
    if err:
        flash(err, "danger")
    else:
        flash(f"Saved {name!r} as a replay dataset ({ds.row_count:,} valid rows). It now appears in the Simulator.",
              "info")
    return redirect(back or url_for("dash.datasets"))


def store_dataset(name, origin, licence, data, filename, kind, auth_ref=None, profile="cicids2017"):
    """Validate and keep a CSV as a replay dataset (UC-02 A1, UC-08 A3). Returns (dataset, error)."""
    from ingest import get_adapter
    if not name:
        return None, "Enter a name for the dataset."
    if Dataset.query.filter_by(name=name).first():
        return None, f"A dataset called {name!r} already exists - choose another name."
    try:
        _df, rep = get_adapter(profile).load(data)
    except Exception:  # noqa: BLE001
        return None, "Unsupported file: this is not a readable CSV flow file. Nothing was stored."
    if rep.missing_columns:
        return None, "Rejected - missing required fields: " + ", ".join(rep.missing_columns[:8]) + (
            f" and {len(rep.missing_columns) - 8} more" if len(rep.missing_columns) > 8 else "") + ". Nothing was stored."
    ds = Dataset(name=name[:128], origin=origin, licence=licence, profile=profile, is_public=False, kind=kind,
                 authorisation_ref=auth_ref, row_count=rep.accepted,
                 size_info=f"{rep.accepted:,} valid rows ({rep.rejected:,} invalid), {_fmt_size(len(data))}")
    db.session.add(ds)
    db.session.flush()
    path = dataset_dir() / f"dataset-{ds.id}.csv"
    path.write_bytes(data)
    ds.file_path = str(path)
    db.session.commit()
    audit("Dataset registered", user=current_user, dataset_id=ds.id, name=name, kind=kind,
          authorisation_ref=auth_ref, filename=filename, rows=rep.accepted)
    return ds, None


@bp.route("/datasets/<int:ds_id>/delete", methods=["POST"])
@login_required
def delete_dataset(ds_id):
    """UC-02 A6 (confirmed in the browser); E3 public datasets cannot be deleted."""
    ds = db.session.get(Dataset, ds_id) or abort(404)
    if is_public(ds):
        flash(f"{ds.name} is a public dataset and cannot be deleted.", "danger")
        return redirect(url_for("dash.datasets"))
    if active_run() and active_run().dataset_id == ds.id:
        flash("This dataset is being replayed. Stop the replay first.", "danger")
        return redirect(url_for("dash.datasets"))
    if ds.file_path:
        Path(ds.file_path).unlink(missing_ok=True)
    name = ds.name
    db.session.delete(ds)
    db.session.commit()
    audit("Dataset deleted", user=current_user, dataset_id=ds_id, name=name)
    flash(f"Deleted dataset {name!r} and its stored file. Earlier replay results are kept.", "info")
    return redirect(url_for("dash.datasets"))
