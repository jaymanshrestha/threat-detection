"""Flask application factory."""
import getpass
import threading
import time
from datetime import timedelta

import click
from flask import Flask, flash, redirect, request, session, url_for
from flask_login import current_user, logout_user

from config import Config

from .extensions import csrf, db, login_manager


def create_app(config_object=Config, **overrides):
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)
    app.config.update(overrides)
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=app.config["SESSION_IDLE_MINUTES"])

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.session_protection = "strong"

    from . import admin, api, auth, incidents, simulator, views
    from .models import Administrator

    @login_manager.user_loader
    def load_user(uid):
        u = db.session.get(Administrator, int(uid))
        return u if u and u.active else None

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return {"error": "authentication required"}, 401
        from .auth import safe_next
        nxt = safe_next(request.full_path if request.query_string else request.path)
        return redirect(url_for("auth.login", next=nxt) if nxt else url_for("auth.login"))

    app.register_blueprint(auth.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(api.bp)
    app.register_blueprint(incidents.bp)
    app.register_blueprint(simulator.bp)

    @app.before_request
    def idle_timeout():
        """Server-side 30-minute inactivity timeout (FR-01)."""
        if current_user.is_authenticated:
            last = session.get("last_activity", 0)
            if time.time() - last > app.config["SESSION_IDLE_MINUTES"] * 60:
                logout_user()
                session.clear()
                if request.path.startswith("/api/"):
                    return {"error": "session expired"}, 401
                flash("Your session expired after 30 minutes of inactivity. Please sign in again.", "warning")
                return redirect(url_for("auth.login"))
            # don't let the dashboard's auto-refresh keep an unattended session alive
            if request.endpoint not in ("dash.summary", "dash.stream", "dash.geo_data"):
                session["last_activity"] = time.time()

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; frame-ancestors 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.endpoint and not request.endpoint.startswith("static"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    with app.app_context():
        if db.engine.url.get_backend_name() == "sqlite" and db.engine.url.database not in (None, "", ":memory:"):
            from sqlalchemy import event as sa_event

            @sa_event.listens_for(db.engine, "connect")
            def _wal(dbapi_conn, _):
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=30000")
                cur.close()
            db.engine.dispose()
        db.create_all()
        _auto_migrate()
        _seed_datasets()

    from . import settings as _settings
    from .privacy import display as _display

    @app.template_filter("report_label")
    def report_label(rep):
        from .reports import display_label
        return display_label(rep)

    @app.template_filter("ip")
    def ip_filter(value):
        """Render an IP according to the admin-selected display mode (full/truncate/hash)."""
        from flask import g
        if "ip_mode" not in g:
            try:
                g.ip_mode = _settings.get("ip_display_mode")
            except Exception:  # noqa: BLE001
                g.ip_mode = app.config["IP_DISPLAY_MODE"]
        return _display(value, g.ip_mode)

    _register_cli(app)
    if app.config.get("START_SCHEDULER"):
        _start_scheduler(app)
    if app.config.get("ENABLE_COLLECTORS") and not app.config.get("TESTING"):
        from ingest.collectors import start_for_app
        start_for_app(app)
    if app.config.get("PCAP_WATCH_ENABLED") and not app.config.get("TESTING"):
        from .pcap_watch import start_for_app as start_pcap_watch
        start_pcap_watch(app)
    return app


# columns added after v1 - (table, column, DDL type). Lets an existing instance/threats.db keep working.
_MIGRATIONS = [("network_events", "message", "TEXT"),
               ("administrators", "invite_pending", "BOOLEAN DEFAULT 0"),
               ("datasets", "kind", "VARCHAR(16)"), ("datasets", "file_path", "TEXT"),
               ("datasets", "authorisation_ref", "TEXT"), ("datasets", "row_count", "INTEGER"),
               ("datasets", "created_at", "DATETIME"), ("simulation_runs", "dataset_id", "INTEGER"),
               ("simulation_runs", "started_by", "VARCHAR(255)"), ("simulation_runs", "events_planned", "INTEGER"), ("simulation_runs", "error", "TEXT"),
               ("incident_reports", "incident_id", "INTEGER"),
               ("security_alerts", "last_sms_at", "DATETIME"), ("security_alerts", "last_sms_severity", "VARCHAR(16)")]


def _auto_migrate():
    from sqlalchemy import inspect, text
    insp = inspect(db.engine)
    for table, col, ddl in _MIGRATIONS:
        if table in insp.get_table_names() and col not in {c["name"] for c in insp.get_columns(table)}:
            with db.engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))


def _seed_datasets():
    from .models import Dataset
    if not Dataset.query.filter_by(name="CIC-IDS2017").first():
        db.session.add(Dataset(
            name="CIC-IDS2017", profile="cicids2017", is_public=True, kind="public",
            origin="Canadian Institute for Cybersecurity, UNB - https://www.unb.ca/cic/datasets/ids-2017.html "
                   "(GeneratedLabelledFlows.zip, downloaded from the Hugging Face mirror bencorn/CICIDS2017)",
            licence="Publicly available for research; users must cite the dataset paper (see citation).",
            citation="I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, 'Toward Generating a New Intrusion Detection "
                     "Dataset and Intrusion Traffic Characterization', ICISSP 2018.",
            size_info="8 CSV files, ~2.8M labelled flows, 5 capture days (3-7 July 2017)"))
        db.session.commit()


def _start_scheduler(app):
    """Background worker: deliver queued emails every 5 s and build the digest."""
    from alerts import notifier

    def loop():
        while True:
            try:
                with app.app_context():
                    notifier.build_digest()
                    notifier.process_queue()
            except Exception:  # noqa: BLE001
                app.logger.exception("scheduler iteration failed")
            time.sleep(5)

    t = threading.Thread(target=loop, name="notifier", daemon=True)
    t.start()


def _register_cli(app):
    from .models import Administrator
    from .security import audit, hash_password

    @app.cli.command("create-admin")
    @click.option("--email", prompt=True)
    @click.option("--password", default=None, help="omit to be prompted (recommended)")
    def create_admin(email, password):
        """Create an administrator (MFA is enrolled at first sign-in)."""
        email = email.strip().lower()
        if Administrator.query.filter_by(email=email).first():
            raise click.ClickException("user already exists")
        if not password:
            password = getpass.getpass("Password (min 12 chars): ")
        if len(password) < 12:
            raise click.ClickException("password must be at least 12 characters")
        u = Administrator(email=email, password_hash=hash_password(password))
        db.session.add(u)
        db.session.commit()
        audit("User created", actor="cli", target=email)
        click.echo(f"Created administrator {email}. Sign in and scan the QR code to enrol MFA.")

    @app.cli.command("reset-mfa")
    @click.option("--email", prompt=True)
    def reset_mfa(email):
        u = Administrator.query.filter_by(email=email.strip().lower()).first()
        if not u:
            raise click.ClickException("no such user")
        u.mfa_enabled, u.totp_secret_enc, u.last_totp_step, u.locked_until = False, None, 0, None
        db.session.commit()
        audit("MFA reset", actor="cli", target=u.email)
        click.echo("MFA reset; user will re-enrol at next sign-in.")

    @app.cli.command("flush-digest")
    def flush_digest():
        """Send the High-severity summary email now."""
        from alerts import notifier
        n = notifier.build_digest(force=True)
        notifier.process_queue()
        click.echo(f"digest: {n.status if n else 'nothing pending'}")

    @app.cli.command("reset-demo-data")
    @click.option("--yes", is_flag=True, help="skip the confirmation prompt")
    def reset_demo_data(yes):
        """Clear events, alerts, incidents, reports, emails and replay runs (keeps admins, audit log, settings, datasets)."""
        if not yes:
            click.confirm("Delete all events, alerts, incidents, reports, notifications and simulation runs?", abort=True)
        from sqlalchemy import text
        from . import pipeline
        tables = ["incident_alerts", "incident_reports", "incidents", "notifications", "detection_results",
                  "security_alerts", "network_events", "ingestion_jobs", "simulation_runs"]
        counts = {}
        with db.engine.begin() as conn:
            existing = set(db.inspect(db.engine).get_table_names())
            for t in tables:
                if t in existing:
                    counts[t] = conn.execute(text(f"DELETE FROM {t}")).rowcount
        try:
            pipeline.reset_window()
        except Exception:  # noqa: BLE001
            pass
        audit("Demo data reset", actor="cli", **{k: v for k, v in counts.items() if v})
        click.echo("Reset done: " + ", ".join(f"{k}={v}" for k, v in counts.items()))

    @app.cli.command("purge-events")
    def purge_events():
        """Delete unflagged raw events older than RAW_EVENT_RETENTION_DAYS."""
        from .pipeline import purge_old_events
        n = purge_old_events(app.config["RAW_EVENT_RETENTION_DAYS"])
        audit("Raw events purged", actor="cli", count=n)
        click.echo(f"purged {n} events")
