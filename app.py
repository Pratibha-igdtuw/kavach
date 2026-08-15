"""
KAVACH — Detect Module ("The Sentinel Eye")
Flask + SocketIO backend serving a real-time cross-sector anomaly detection
dashboard, with ensemble/classified detection, weighted-graph propagation,
containment actions, persisted history, incident reports, an executive
summary, an audit trail, and role-based auth (analyst / executive / admin).
"""
import os
import threading
import time

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, Response
from werkzeug.security import generate_password_hash

from flask_socketio import SocketIO

from simulator import TelemetrySimulator, ATTACK_SIGNATURES, MITRE_MAPPING
from detector import SectorDetector
from propagation import PropagationEngine, CRITICAL_THRESHOLD
import storage
import auth
from report import generate_incident_report
from report_pdf import generate_incident_report_pdf
import notifier

app = Flask(__name__)
app.config["SECRET_KEY"] = "kavach-dev-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

SECTORS = ["hospital", "power_grid", "bank"]

# Business-criticality weights for the executive org-risk rollup. Hospital
# carries the most weight (life-safety), then power (cascades to everything),
# then bank. Purely for the exec summary — detection/propagation logic below
# doesn't use these.
SECTOR_WEIGHTS = {"hospital": 0.40, "power_grid": 0.35, "bank": 0.25}
SECTOR_LABEL = {"hospital": "Hospital", "power_grid": "Power Grid", "bank": "Bank"}

INCIDENT_WINDOW_SECONDS = 24 * 60 * 60  # 24h, for the exec summary

# ---- replay mode: drive a sector from a real (or real-shaped) CSV instead
# of pure synthetic generation. Resolution order per sector:
#   1. explicit env var override, e.g. KAVACH_REPLAY_HOSPITAL=/path/to.csv
#   2. auto-detected default at data/<sector>_replay.csv, if present
# A sector with no file either way just falls back to synthetic simulation,
# so this is fully backward compatible — nothing breaks if you ignore it.
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
REPLAY_FILES = {}
for _sector in SECTORS:
    _env_key = f"KAVACH_REPLAY_{_sector.upper()}"
    _path = os.environ.get(_env_key) or os.path.join(DATA_DIR, f"{_sector}_replay.csv")
    if os.path.isfile(_path):
        REPLAY_FILES[_sector] = _path

simulator = TelemetrySimulator(SECTORS, replay_files=REPLAY_FILES)
detectors = {s: SectorDetector() for s in SECTORS}
propagation_engine = PropagationEngine(SECTORS)

storage.init_db()
auth.seed_default_users_if_needed()

# Per-sector configurable detection thresholds (risk-score cutoffs), seeded
# with sane defaults and reloaded from the DB on every boot. Hospital and
# power grid alert a little sooner than bank given the life-safety /
# cascading-failure stakes (see SECTOR_WEIGHTS above for the same idea
# applied to the exec-summary rollup).
DEFAULT_THRESHOLDS = {
    "hospital": (35.0, 70.0),
    "power_grid": (35.0, 70.0),
    "bank": (40.0, 75.0),
}
storage.seed_default_thresholds([(s, a, c) for s, (a, c) in DEFAULT_THRESHOLDS.items()])
sector_thresholds = storage.get_all_thresholds()

# ticks remaining that a sector's risk is being actively suppressed by a
# manual containment action
contained = {s: 0 for s in SECTORS}
# whether a sector has been contained at least once in its current incident
# (used for the incident report)
was_contained = {s: False for s in SECTORS}


def log_audit_and_emit(action, sector=None, detail=""):
    """Record an audit entry (who did what, when) and push it to every
    connected client so the audit panel updates live for both analyst and
    executive viewers."""
    actor = session.get("display_name", "Unknown")
    role = session.get("role", "unknown")
    storage.insert_audit(actor, role, action, sector=sector, detail=detail)
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "actor": actor,
        "role": role,
        "action": action,
        "sector": sector,
        "detail": detail,
    }
    socketio.emit("audit_log", {"entries": [entry]})


def compute_exec_summary(sectors_payload):
    """Weighted org risk score + top risk sector + trailing-24h incident
    count, phrased for a non-technical, business-impact audience."""
    weighted_total = 0.0
    weight_sum = 0.0
    top_sector, top_score = None, -1.0

    for sector, weight in SECTOR_WEIGHTS.items():
        score = sectors_payload.get(sector, {}).get("risk_score", 0)
        weighted_total += score * weight
        weight_sum += weight
        if score > top_score:
            top_sector, top_score = sector, score

    org_risk = round(weighted_total / weight_sum, 1) if weight_sum else 0.0

    if org_risk >= CRITICAL_THRESHOLD:
        status_label = "Critical — immediate action needed"
    elif org_risk >= 45:
        status_label = "Elevated — monitor closely"
    else:
        status_label = "Normal — no action required"

    return {
        "org_risk": org_risk,
        "status_label": status_label,
        "top_sector": top_sector,
        "top_sector_label": SECTOR_LABEL.get(top_sector, top_sector),
        "top_sector_score": round(top_score, 1) if top_score >= 0 else 0.0,
        "incidents_24h": storage.incident_count_since(INCIDENT_WINDOW_SECONDS),
    }


def background_loop():
    """Continuously generate telemetry, score it, propagate, persist, and push to clients."""
    while True:
        payload = {"sectors": {}, "propagation": [], "timestamp": time.time()}
        base_scores = {}
        anomaly_flags = {}
        raw_results = {}

        for sector in SECTORS:
            thresholds = sector_thresholds.get(sector, {"alert_threshold": 40.0, "critical_threshold": 75.0})

            reading, injected_attack_type = simulator.next_reading(sector)
            result = detectors[sector].score(reading, alert_threshold=thresholds["alert_threshold"])
            raw_results[sector] = result

            risk_score = result["risk_score"]
            sector_contained = contained[sector] > 0
            if sector_contained:
                risk_score *= 0.35
                contained[sector] -= 1
                was_contained[sector] = True

            base_scores[sector] = risk_score
            anomaly_flags[sector] = result["is_anomaly"] and not sector_contained

            payload["sectors"][sector] = {
                "risk_score": risk_score,
                "is_anomaly": result["is_anomaly"],
                "metrics": reading,
                "top_factor": result["top_factor"],
                "forest_risk": result["forest_risk"],
                "trend_risk": result["trend_risk"],
                "injected_attack_type": injected_attack_type,
                "predicted_attack_type": result["predicted_attack_type"],
                "attack_confidence": result["attack_confidence"],
                "contained": sector_contained,
                "critical_threshold": thresholds["critical_threshold"],
                "data_source": "replay" if simulator.is_replaying(sector) else "synthetic",
            }

            if result["is_anomaly"] and not sector_contained:
                atype = result["predicted_attack_type"]
                atype_label = ATTACK_SIGNATURES[atype]["label"] if atype else "Unclassified"
                mitre = MITRE_MAPPING.get(atype)
                entry = {
                    "time": time.strftime("%H:%M:%S"),
                    "sector": sector,
                    "message": f"Anomaly detected in {sector.replace('_',' ').title()} — "
                               f"{atype_label} (deviation in {result['top_factor']})",
                    "severity": "high" if risk_score > thresholds["critical_threshold"] else "medium",
                    "attack_type": atype,
                    "status": "new",
                    "mitre_id": mitre["technique_id"] if mitre else None,
                    "mitre_label": mitre["technique_name"] if mitre else None,
                }
                entry["id"] = storage.insert_log(entry)
                payload.setdefault("new_log", []).append(entry)
                notifier.notify_critical(entry)

        # ---- cross-sector propagation over the weighted dependency graph ----
        adjusted_scores, prop_events = propagation_engine.propagate(base_scores, anomaly_flags)
        for target, events in _group_by_target(prop_events).items():
            payload["sectors"][target]["risk_score"] = round(adjusted_scores[target], 1)
            was_anomaly = payload["sectors"][target]["is_anomaly"]
            if adjusted_scores[target] >= 60 and not was_anomaly:
                sources = ", ".join(e["from"].replace("_", " ").title() for e in events)
                entry = {
                    "time": time.strftime("%H:%M:%S"),
                    "sector": target,
                    "message": f"Dependency risk rising in {target.replace('_',' ').title()} "
                               f"— propagated from {sources}",
                    "severity": "medium",
                    "attack_type": None,
                }
                storage.insert_log(entry)
                payload.setdefault("new_log", []).append(entry)
        payload["propagation"] = prop_events

        # ---- persist + blast-radius forecast ----
        for sector in SECTORS:
            score = payload["sectors"][sector]["risk_score"]
            propagation_engine.record(sector, score)
            storage.insert_risk_point(sector, score, payload["sectors"][sector]["is_anomaly"])

            forecast = propagation_engine.blast_radius(
                sector, critical_threshold=sector_thresholds.get(sector, {}).get("critical_threshold")
            )
            if forecast:
                payload["sectors"][sector]["blast_radius"] = forecast

        # ---- executive summary rollup ----
        payload["exec_summary"] = compute_exec_summary(payload["sectors"])
        payload["thresholds"] = sector_thresholds

        socketio.emit("telemetry_update", payload)
        time.sleep(2)


def _group_by_target(events):
    grouped = {}
    for e in events:
        grouped.setdefault(e["to"], []).append(e)
    return grouped


# ---------------- auth routes ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = auth.check_credentials(username, password)
        if user:
            session["role"] = user["role"]
            session["display_name"] = user["display_name"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- main dashboard ----------------

@app.route("/")
@auth.login_required
def index():
    return render_template(
        "index.html",
        role=auth.current_role(),
        display_name=auth.current_name(),
    )


@app.route("/api/history/<sector>")
@auth.login_required
def api_history(sector):
    if sector not in SECTORS:
        return jsonify({"error": "unknown sector"}), 404
    return jsonify(storage.sector_history(sector, limit=120))


@app.route("/api/audit")
@auth.login_required
def api_audit():
    return jsonify(storage.recent_audit(50))


@app.route("/report/<sector>")
@auth.login_required
def report(sector):
    if sector not in SECTORS:
        return jsonify({"error": "unknown sector"}), 404
    md = generate_incident_report(sector, contained=was_contained.get(sector, False))
    filename = f"kavach_incident_{sector}_{int(time.time())}.md"
    return Response(
        md,
        mimetype="text/markdown",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/report/<sector>/pdf")
@auth.login_required
def report_pdf(sector):
    if sector not in SECTORS:
        return jsonify({"error": "unknown sector"}), 404
    pdf_bytes = generate_incident_report_pdf(sector, contained=was_contained.get(sector, False))
    filename = f"kavach_incident_{sector}_{int(time.time())}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------- admin routes (user management) ----------------

@app.route("/admin")
@auth.admin_required
def admin_panel():
    return render_template(
        "admin.html",
        role=auth.current_role(),
        display_name=auth.current_name(),
        users=storage.list_users(),
        roles=auth.ROLES,
        error=request.args.get("error"),
        success=request.args.get("success"),
        sectors=SECTORS,
        sector_labels=SECTOR_LABEL,
        thresholds=sector_thresholds,
    )


@app.route("/admin/thresholds/update", methods=["POST"])
@auth.admin_required
def admin_update_thresholds():
    sector = request.form.get("sector", "")
    if sector not in SECTORS:
        return redirect(url_for("admin_panel", error="Unknown sector."))

    try:
        alert_threshold = float(request.form.get("alert_threshold", ""))
        critical_threshold = float(request.form.get("critical_threshold", ""))
    except ValueError:
        return redirect(url_for("admin_panel", error="Thresholds must be numbers."))

    if not (0 <= alert_threshold <= 100 and 0 <= critical_threshold <= 100):
        return redirect(url_for("admin_panel", error="Thresholds must be between 0 and 100."))
    if critical_threshold <= alert_threshold:
        return redirect(url_for("admin_panel", error="Critical threshold must be higher than the alert threshold."))

    actor = session.get("display_name", "Unknown")
    storage.update_threshold(sector, alert_threshold, critical_threshold, actor)
    sector_thresholds[sector] = {"alert_threshold": alert_threshold, "critical_threshold": critical_threshold}

    log_audit_and_emit(
        "Updated detection thresholds", sector=sector,
        detail=f"alert>{alert_threshold}, critical>{critical_threshold}",
    )
    socketio.emit("thresholds_updated", {"sector": sector, **sector_thresholds[sector]})
    return redirect(url_for("admin_panel", success=f"Thresholds updated for {SECTOR_LABEL.get(sector, sector)}."))


@app.route("/admin/users/add", methods=["POST"])
@auth.admin_required
def admin_add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    display_name = request.form.get("display_name", "").strip() or username

    if not username or not password or role not in auth.ROLES:
        return redirect(url_for("admin_panel", error="All fields are required and role must be valid."))
    if storage.get_user(username):
        return redirect(url_for("admin_panel", error=f"Username '{username}' already exists."))

    storage.add_user(username, generate_password_hash(password), role, display_name)
    log_audit_and_emit("Created user", detail=f"{username} ({role})")
    return redirect(url_for("admin_panel", success=f"User '{username}' created."))


@app.route("/admin/users/<username>/delete", methods=["POST"])
@auth.admin_required
def admin_delete_user(username):
    target = storage.get_user(username)
    if not target:
        return redirect(url_for("admin_panel", error="User not found."))
    if username == session.get("username"):
        return redirect(url_for("admin_panel", error="You can't delete your own account."))
    if target["role"] == "admin" and storage.count_users_by_role("admin") <= 1:
        return redirect(url_for("admin_panel", error="Can't delete the last remaining admin."))

    storage.delete_user(username)
    log_audit_and_emit("Deleted user", detail=username)
    return redirect(url_for("admin_panel", success=f"User '{username}' deleted."))


@app.route("/admin/users/<username>/reset-password", methods=["POST"])
@auth.admin_required
def admin_reset_password(username):
    new_password = request.form.get("new_password", "")
    if not storage.get_user(username):
        return redirect(url_for("admin_panel", error="User not found."))
    if not new_password:
        return redirect(url_for("admin_panel", error="New password can't be empty."))

    storage.update_password(username, generate_password_hash(new_password))
    log_audit_and_emit("Reset password", detail=username)
    return redirect(url_for("admin_panel", success=f"Password reset for '{username}'."))


# ---------------- socket events ----------------

@socketio.on("connect")
def on_connect():
    if "role" not in session:
        return False  # reject unauthenticated socket connections
    socketio.emit(
        "log_history",
        {"log": storage.recent_logs(30)},
        to=request.sid,
    )
    socketio.emit(
        "audit_log",
        {"entries": storage.recent_audit(50)},
        to=request.sid,
    )
    socketio.emit(
        "session_info",
        {"role": session.get("role"), "name": session.get("display_name")},
        to=request.sid,
    )
    socketio.emit(
        "thresholds_bulk",
        {"thresholds": sector_thresholds},
        to=request.sid,
    )


@socketio.on("trigger_attack")
def on_trigger_attack(data):
    if session.get("role") not in ("analyst", "admin"):
        return
    sector = (data or {}).get("sector")
    attack_type = (data or {}).get("attack_type")
    if sector in SECTORS:
        simulator.trigger_attack(sector, ticks=3, attack_type=attack_type)
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "sector": sector,
            "message": f"Manual attack simulation triggered on {sector.replace('_',' ').title()}",
            "severity": "medium",
            "attack_type": attack_type,
        }
        storage.insert_log(entry)
        socketio.emit("log_history", {"log": [entry]})
        log_audit_and_emit("Triggered attack simulation", sector=sector, detail=attack_type or "unclassified")


@socketio.on("contain_sector")
def on_contain_sector(data):
    if session.get("role") not in ("analyst", "admin"):
        return
    sector = (data or {}).get("sector")
    if sector in SECTORS:
        contained[sector] = 6
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "sector": sector,
            "message": f"Containment protocol engaged on {sector.replace('_',' ').title()} "
                       f"— risk actively suppressed while isolation holds",
            "severity": "medium",
            "attack_type": None,
        }
        storage.insert_log(entry)
        socketio.emit("log_history", {"log": [entry]})
        log_audit_and_emit("Contained sector", sector=sector)


@socketio.on("mark_false_positive")
def on_mark_false_positive(data):
    if session.get("role") not in ("analyst", "admin"):
        return
    sector = (data or {}).get("sector")
    if sector in SECTORS:
        detectors[sector].mark_false_positive()
        entry = {
            "time": time.strftime("%H:%M:%S"),
            "sector": sector,
            "message": f"Analyst marked last alert on {sector.replace('_',' ').title()} as a "
                       f"false positive — detector sensitivity adjusted",
            "severity": "medium",
            "attack_type": None,
        }
        storage.insert_log(entry)
        socketio.emit("log_history", {"log": [entry]})
        log_audit_and_emit("Marked false positive", sector=sector)


@socketio.on("update_alert_status")
def on_update_alert_status(data):
    if session.get("role") not in ("analyst", "admin"):
        return
    log_id = (data or {}).get("id")
    status = (data or {}).get("status")
    if log_id is None or status not in ("new", "acknowledged", "resolved"):
        return

    actor = session.get("display_name", "Unknown")
    updated = storage.update_alert_status(log_id, status, actor)
    if not updated:
        return

    socketio.emit("alert_status_updated", updated)
    action_label = {"acknowledged": "Acknowledged alert", "resolved": "Resolved alert", "new": "Reopened alert"}[status]
    log_audit_and_emit(action_label, sector=updated["sector"], detail=f"log #{log_id}")


if __name__ == "__main__":
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    socketio.run(app, host="0.0.0.0", port=5001, debug=True, use_reloader=False, allow_unsafe_werkzeug=True)