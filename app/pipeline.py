"""Ingestion -> detection -> de-duplication -> notification pipeline.

Used by CSV upload, the ingest API and the replay simulator, so replayed data
goes through exactly the same path as live data (FR-05)."""
import threading
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from flask import current_app

from alerts import notifier
from alerts.severity import RANK, classify
from ingest import get_adapter
from ingest.schema import FLOW_FEATURES
from ingest.windows import WINDOW_FEATURES, WindowState
from ml.detectors import UNCLASSIFIED, IsolationForestDetector, RandomForestDetector, RuleDetector

from . import settings
from .extensions import db
from .models import DetectionResult, IngestionJob, NetworkEvent, SecurityAlert, SimulationRun

_lock = threading.Lock()
_window = WindowState()
_models = {}


MODEL_CHOICES = {"isolation_forest": "Isolation Forest (unsupervised)", "random_forest": "Random Forest (supervised)"}


def _load_models():
    cfg = current_app.config
    key = (cfg["MODEL_PATH"], cfg["RF_MODEL_PATH"], cfg["RULES_PATH"])
    if _models.get("key") != key:
        _models["isolation_forest"] = (IsolationForestDetector.load(cfg["MODEL_PATH"])
                                       if Path(cfg["MODEL_PATH"]).exists() else None)
        _models["random_forest"] = (RandomForestDetector.load(cfg["RF_MODEL_PATH"])
                                    if Path(cfg["RF_MODEL_PATH"]).exists() else None)
        _models["rules"] = RuleDetector.load(cfg["RULES_PATH"]) if Path(cfg["RULES_PATH"]).exists() else RuleDetector()
        _models["key"] = key
    return _models


def available_models():
    m = _load_models()
    return {k: v for k, v in MODEL_CHOICES.items() if m.get(k) is not None}


def detectors():
    """Return (active ML detector or None, rule detector). Pluggable: add models to MODEL_CHOICES."""
    m = _load_models()
    active = settings.get("active_model")
    model = m.get(active) or m.get("isolation_forest") or m.get("random_forest")
    return model, m["rules"]


def reset_window():
    global _window
    _window = WindowState()


def ingest_bytes(data: bytes, filename: str, source: str, profile="cicids2017", user=None,
                 run: SimulationRun = None, simulated=False):
    adapter = get_adapter(profile)
    job = IngestionJob(source=source, filename=filename, profile=profile,
                       administrator_id=getattr(user, "id", None), run_id=getattr(run, "id", None))
    db.session.add(job)
    db.session.flush()
    df, rep = adapter.load(data)
    job.total_rows, job.accepted, job.rejected = rep.total_rows, rep.accepted, rep.rejected
    job.reasons = rep.reasons or None
    if rep.missing_columns:
        job.status = "Rejected"
        job.reasons = {"missing_required_columns": rep.missing_columns}
        db.session.commit()
        return job, {"events": 0, "flagged": 0, "alerts_new": 0}
    stats = process_events(df, job, simulated=simulated)
    job.status = "Completed"
    if run:
        run.events_sent = (run.events_sent or 0) + stats["events"]
        run.alerts_raised = (run.alerts_raised or 0) + stats["alerts_new"]
    db.session.commit()
    return job, stats


def process_events(df: pd.DataFrame, job: IngestionJob = None, simulated=False):
    if df.empty:
        return {"events": 0, "flagged": 0, "alerts_new": 0}
    model, rules = detectors()
    threshold = float(settings.get("sensitivity_threshold"))
    with _lock:
        df = df.sort_values("observed_at", kind="stable").reset_index(drop=True)
        df = pd.concat([df, _window.update(df)], axis=1)
    if model is not None:
        if_out = model.detect(df, threshold=threshold)
    else:  # no trained model yet -> rules only
        if_out = pd.DataFrame({"risk": 0.0, "flagged": False, "category": UNCLASSIFIED, "explanation": None},
                              index=df.index)
    rule_out = rules.detect(df)
    feat_cols = FLOW_FEATURES + WINDOW_FEATURES
    feats = df[feat_cols].round(3).to_dict(orient="records")
    labels = df["label"].tolist() if "label" in df.columns else [None] * len(df)
    messages = df["message"].tolist() if "message" in df.columns else [None] * len(df)

    events, flagged_rows = [], []
    for i in range(len(df)):
        risk = float(if_out["risk"].iat[i])
        rcat = rule_out["category"].iat[i] if rule_out["flagged"].iat[i] else ""
        sev = classify(risk, threshold, rcat)
        ev = NetworkEvent(
            observed_at=df["observed_at"].iat[i].to_pydatetime(), src_ip=df["src_ip"].iat[i],
            src_port=int(df["src_port"].iat[i]), dst_ip=df["dst_ip"].iat[i], dst_port=int(df["dst_port"].iat[i]),
            protocol=df["protocol"].iat[i], features=feats[i], dataset_label=labels[i],
            is_simulated=simulated, risk=round(risk, 4), flagged=bool(sev), severity=sev or None,
            job_id=getattr(job, "id", None), message=messages[i] if isinstance(messages[i], str) else None,
        )
        events.append(ev)
        if sev:
            flagged_rows.append((i, ev, risk, rcat, sev))
    db.session.add_all(events)
    db.session.flush()

    model_version = model.model_version if model else "none"
    model_key = "random_forest" if isinstance(model, RandomForestDetector) else "isolation_forest"
    results = []
    for i, ev, risk, rcat, sev in flagged_rows:
        if bool(if_out["flagged"].iat[i]):
            results.append(DetectionResult(
                event_id=ev.id, detector=model_key, model_version=model_version,
                detector_type=model.detector_type, anomaly_score=round(risk, 4), flagged=True,
                predicted_label=if_out["category"].iat[i],
                label_source="Supervised (binary)" if model_key == "random_forest" else "Unclassified", severity=sev,
                top_features=if_out["explanation"].iat[i]))
        if rcat:
            results.append(DetectionResult(
                event_id=ev.id, detector="rule_baseline", model_version=rules.model_version,
                detector_type="Rule-based", anomaly_score=1.0, flagged=True, predicted_label=rcat,
                label_source="Rule", severity=sev, top_features=rule_out["explanation"].iat[i]))
    db.session.add_all(results)
    db.session.flush()
    new_alerts = _group_into_alerts(results, simulated)
    db.session.commit()
    return {"events": len(events), "flagged": len(flagged_rows), "alerts_new": new_alerts}


def _group_into_alerts(results, simulated):
    """De-duplicate detections into alerts keyed by (source, destination, category)
    within the grouping window (event time). No detection is discarded."""
    window = timedelta(minutes=int(settings.get("grouping_minutes")))
    # one detection per event: prefer the rule's category (more specific)
    by_event, all_by_event = {}, {}
    for r in results:
        all_by_event.setdefault(r.event_id, []).append(r)
        if r.event_id not in by_event or r.detector == "rule_baseline":
            by_event[r.event_id] = r
    cache, touched, created = {}, {}, 0
    for r in sorted(by_event.values(), key=lambda r: r.event.observed_at):
        ev = r.event
        cat = r.predicted_label or UNCLASSIFIED
        key = (ev.src_ip, ev.dst_ip, cat)
        alert = cache.get(key)
        if alert is None or ev.observed_at - alert.last_seen > window:
            alert = (SecurityAlert.query.filter_by(src_ip=ev.src_ip, dst_ip=ev.dst_ip, category=cat, status="Open")
                     .filter(SecurityAlert.last_seen >= ev.observed_at - window)
                     .order_by(SecurityAlert.last_seen.desc()).first())
        is_new = alert is None
        if is_new:
            alert = SecurityAlert(src_ip=ev.src_ip, dst_ip=ev.dst_ip, category=cat, severity=r.severity,
                                  max_risk=ev.risk or 0, occurrence_count=0, first_seen=ev.observed_at,
                                  last_seen=ev.observed_at, is_simulated=simulated,
                                  top_features=r.top_features)
            db.session.add(alert)
            db.session.flush()
            created += 1
        prev = touched.get(alert.id, (is_new, alert.severity))
        alert.occurrence_count += 1
        alert.last_seen = max(alert.last_seen, ev.observed_at)
        ml_feats = next((x.top_features for x in all_by_event[ev.id]
                         if x.detector != "rule_baseline" and x.top_features), None)
        if (ev.risk or 0) > (alert.max_risk or 0):
            alert.max_risk = ev.risk
            if ml_feats:
                alert.top_features = ml_feats
        elif ml_feats and (not alert.top_features or alert.top_features[0].get("method", "").startswith("rule")):
            alert.top_features = ml_feats
        if RANK[r.severity] > RANK[alert.severity]:
            alert.severity = r.severity
        cache[key] = alert
        touched[alert.id] = prev
        for res in all_by_event[ev.id]:
            res.alert_id = alert.id
    for aid, (is_new, old_sev) in touched.items():
        a = db.session.get(SecurityAlert, aid)
        try:
            notifier.on_alert(a, is_new, RANK[a.severity] > RANK[old_sev])
        except Exception as e:  # notification problems never interrupt detection
            current_app.logger.exception("notifier failed: %s", e)
    try:  # FR-09 / UC-04 A3: High and Critical alerts open an incident automatically
        from .incidents import auto_open
        auto_open([db.session.get(SecurityAlert, aid) for aid in touched])
    except Exception as e:  # noqa: BLE001
        current_app.logger.exception("incident linking failed: %s", e)
    return created


def purge_old_events(days: int):
    """Delete raw (unflagged) events older than the retention period."""
    cutoff = datetime.now() - timedelta(days=days)
    n = NetworkEvent.query.filter(NetworkEvent.received_at < cutoff, NetworkEvent.flagged.is_(False)).delete()
    db.session.commit()
    return n
