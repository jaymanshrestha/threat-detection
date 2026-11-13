"""Machine-to-machine ingestion API used by the replay simulator / log shippers.
Authenticated with an API key header (X-API-Key), CSRF-exempt."""
import hmac
from datetime import datetime

from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, request

from ingest import ADAPTERS

from .extensions import csrf, db
from .models import SimulationRun
from .pipeline import ingest_bytes, reset_window
from .security import audit

bp = Blueprint("api", __name__, url_prefix="/api/v1")
csrf.exempt(bp)


@bp.before_request
def check_key():
    key = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(key, current_app.config["INGEST_API_KEY"]):
        abort(401)


@bp.post("/ingest")
def ingest():
    run = None
    if request.args.get("run_id"):
        run = db.session.get(SimulationRun, int(request.args["run_id"]))
    profile = request.args.get("profile", "cicids2017")
    if profile not in ADAPTERS:
        return jsonify({"error": f"unknown profile; available: {sorted(ADAPTERS)}"}), 400
    data = request.get_data(cache=False)
    if not data:
        return jsonify({"error": "empty body"}), 400
    name = Path(request.args.get("filename", f"api-{profile}")).name[:200]
    job, stats = ingest_bytes(data, name, source="replay" if run else "api", profile=profile, run=run,
                              simulated=bool(run))
    return jsonify({"job_id": job.id, "status": job.status, "accepted": job.accepted, "rejected": job.rejected,
                    "reasons": job.reasons, **stats})


@bp.post("/replay/start")
def replay_start():
    body = request.get_json(force=True, silent=True) or {}
    active = SimulationRun.query.filter(SimulationRun.status.in_(("Running", "Paused", "Stopping")))
    if active.first() and not body.get("force"):
        return jsonify({"error": "a replay is already in progress"}), 409  # UC-02 E1
    for r in active.all():
        r.status = "Stopped"
    run = SimulationRun(dataset=body.get("dataset", "CIC-IDS2017"), file=body.get("file"),
                        speed=body.get("speed"), attack_filter=body.get("attack_filter"))
    db.session.add(run)
    db.session.commit()
    reset_window()
    audit("Replay started", actor="replay-simulator", run_id=run.id, file=run.file, speed=run.speed)
    return jsonify({"run_id": run.id}), 202  # report SD-05: replay accepted, runs in the background


@bp.post("/replay/<int:run_id>/finish")
def replay_finish(run_id):
    run = db.session.get(SimulationRun, run_id) or abort(404)
    run.status = (request.get_json(silent=True) or {}).get("status", "Completed")
    run.ended_at = datetime.now()
    db.session.commit()
    audit("Replay finished", actor="replay-simulator", run_id=run.id, events=run.events_sent,
          alerts=run.alerts_raised, status=run.status)
    return jsonify({"run_id": run.id, "status": run.status, "events": run.events_sent, "alerts": run.alerts_raised})
