"""
KAVACH — Detect Module ("The Sentinel Eye")
Flask + SocketIO backend serving a real-time cross-sector anomaly detection
dashboard, with ensemble/classified detection, weighted-graph propagation,
containment actions, persisted history, incident reports, an executive
summary, an audit trail, and role-based auth (analyst / executive / admin).
"""
import csv
import io
import os
import secrets
import threading
import time

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, Response
from werkzeug.security import generate_password_hash

from flask_socketio import SocketIO
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from simulator import TelemetrySimulator, ATTACK_SIGNATURES, MITRE_MAPPING
from detector import SectorDetector
from propagation import PropagationEngine, CRITICAL_THRESHOLD
import storage
from case_management_routes import register_case_management_routes, register_case_management_sockets
import auth
from report import generate_incident_report
from report_pdf import generate_incident_report_pdf
import notifier

app = Flask(__name__)
# SECRET_KEY comes from the environment in real deployments (set it before
# running, e.g. `export SECRET_KEY=...`). Falling back to a freshly
# generated random key means the app never silently ships with a known,
# hardcoded secret — the trade-off is that sessions won't survive a
# restart unless SECRET_KEY is set explicitly.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

csrf = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

SECTORS = ["hospital", "power_grid", "bank"]

# Business-criticality weights for the executive org-risk rollup. Hospital
# carries the most weight (life-safety), then power (cascades to everything),
# then bank. Purely for the exec summary — detection/propagation logic below
# doesn't use these.
SECTOR_WEIGHTS = {"hospital": 0.40, "power_grid": 0.35, "bank": 0.25}
SECTOR_LABEL = {"hospital": "Hospital", "power_grid": "Power Grid", "bank": "Bank"}

INCIDENT_WINDOW_SECONDS = 24 * 60 * 60  # 24h, for the exec summary

# ---- telemetry ingestion / continuous learning ----
# Shared secret for the /api/ingest endpoint.  Rotate via env var in prod.
# If unset a random key is generated at startup (printed to stdout so the
# operator can copy it); it resets on every restart until a real secret is set.
_generated_ingest_key = secrets.token_hex(24)
INGEST_API_KEY = os.environ.get("KAVACH_INGEST_KEY") or _generated_ingest_key
if not os.environ.get("KAVACH_INGEST_KEY"):
    print(
        f"[KAVACH] No KAVACH_INGEST_KEY env var set — "
        f"using ephemeral key for /api/ingest: {INGEST_API_KEY}",
        flush=True,
    )

# How often (seconds) the background thread checks whether each sector's
# detector should be retrained on accumulated real telemetry.
# Operators can tune via env var (e.g. KAVACH_RETRAIN_INTERVAL=1800).
RETRAIN_INTERVAL = int(os.environ.get("KAVACH_RETRAIN_INTERVAL", "300"))

# Rolling window of real telemetry to train on (seconds).
# 3600 = last 1 hour of ingested readings.
RETRAIN_WINDOW_SECONDS = int(os.environ.get("KAVACH_RETRAIN_WINDOW", "3600"))

# Analyst response playbook: recommended actions per attack type
RESPONSE_PLAYBOOK = {
    "ddos": [
        "Verify traffic source IPs (legitimate vs. spoofed)",
        "Check rate-limiting rules on edge firewalls",
        "Escalate to network ops if traffic exceeds 50% capacity",
        "Preserve pcap logs for forensics",
    ],
    "sql_injection": [
        "Review recent database query logs for malicious syntax",
        "Check for unauthorized data export or modification",
        "Rotate database credentials if compromise suspected",
        "Patch vulnerable endpoints immediately",
    ],
    "malware": [
        "Isolate affected host from network (if applicable)",
        "Scan with updated antivirus/EDR across infrastructure",
        "Review process execution logs and network connections",
        "Check for lateral movement indicators",
    ],
    "brute_force": [
        "Enforce account lockout after N failed attempts",
        "Review access logs for source IPs (block if hostile)",
        "Require password reset for affected accounts",
        "Enable MFA if not already active",
    ],
    "privilege_escalation": [
        "Review sudo/admin access logs for unauthorized use",
        "Check for unexpected permission changes",
        "Audit service accounts and their access",
        "Implement least-privilege access controls",
    ],
    "data_exfiltration": [
        "Check firewall egress logs for suspicious data transfers",
        "Review user/process data access patterns (DLP)",
        "Implement encryption for sensitive data in transit",
        "Contact legal/compliance if PII involved",
    ],
}

# MITRE ATT&CK technique → generic response framework
MITRE_RESPONSE = {
    # T1110: Brute Force
    "T1110": "Enforce rate-limiting, MFA, and account lockout policies",
    # T1005: Data from Local System
    "T1005": "Review file access logs; restrict to least-privilege users",
    # T1041: Exfiltration Over C2 Channel
    "T1041": "Block suspicious outbound connections; inspect egress traffic",
    # T1098: Account Manipulation
    "T1098": "Audit user accounts; enforce password policies",
    # T1053: Scheduled Task/Job
    "T1053": "Review scheduled tasks/cron jobs; remove unauthorized entries",
    # T1071: Application Layer Protocol (C2)
    "T1071": "Monitor for anomalous protocol patterns; block known C2 domains",
}

# Business-impact templates: risk_score -> plain-language statement per sector
IMPACT_TEMPLATES = {
    "hospital": {
        "normal": "Patient record systems operational",
        "elevated": "Potential impact to patient data access and clinical workflows",
        "critical": "Critical threat to patient safety systems and data integrity",
    },
    "power_grid": {
        "normal": "Power distribution operating normally",
        "elevated": "Risk to grid stability and service continuity in affected regions",
        "critical": "Critical infrastructure failure imminent — cascading outage risk",
    },
    "bank": {
        "normal": "Financial systems secure and operational",
        "elevated": "Risk to transaction processing and customer data",
        "critical": "Critical threat to financial integrity and customer trust",
    },
}

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
storage.init_case_management_db()
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


def _risk_to_severity_level(risk_score):
    """Map risk score to severity level for impact statements."""
    if risk_score >= CRITICAL_THRESHOLD:
        return "critical"
    elif risk_score >= 45:
        return "elevated"
    return "normal"


def _impact_statement(sector, risk_score):
    """Generate a plain-language business impact statement for a sector."""
    severity = _risk_to_severity_level(risk_score)
    template = IMPACT_TEMPLATES.get(sector, {}).get(severity, "Status uncertain")
    sector_label = SECTOR_LABEL.get(sector, sector)
    return f"{sector_label}: {template}"


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
    """Continuously generate telemetry, score it, propagate, persist, and push to clients.

    Also runs a periodic retraining check every RETRAIN_INTERVAL seconds:
    if a sector has accumulated enough real ingested telemetry, its detector
    is quietly re-fitted on that rolling window without disrupting the live
    scoring loop.
    """
    _last_retrain_check = time.time()

    while True:
        # ---- periodic baseline retraining on real ingested data ----
        now = time.time()
        if now - _last_retrain_check >= RETRAIN_INTERVAL:
            _last_retrain_check = now
            for sector in SECTORS:
                rows = storage.get_ingest_baseline_window(
                    sector, window_seconds=RETRAIN_WINDOW_SECONDS
                )
                if rows:
                    ok = detectors[sector].retrain_on_real_data(rows)
                    if ok:
                        storage.prune_ingest_telemetry(sector)
                        socketio.emit(
                            "detector_retrained",
                            {
                                "sector": sector,
                                "auto": True,
                                "real_rows": len(rows),
                                "detail": f"auto-retrain on {len(rows)} real rows",
                            },
                        )

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
                # FIXED: Added defensive check to prevent KeyError if unexpected attack type
                if atype and atype in ATTACK_SIGNATURES:
                    atype_label = ATTACK_SIGNATURES[atype]["label"]
                else:
                    atype_label = "Unclassified"
                mitre = MITRE_MAPPING.get(atype)
                
                # Recommended actions from playbook
                playbook_actions = RESPONSE_PLAYBOOK.get(atype, [])
                mitre_response = MITRE_RESPONSE.get(mitre["technique_id"], "") if mitre else ""
                
                entry = {
                    "time": time.strftime("%H:%M:%S"),
                    "ts": time.time(),  # For SLA calculation
                    "sector": sector,
                    "message": f"Anomaly detected in {sector.replace('_',' ').title()} — "
                               f"{atype_label} (deviation in {result['top_factor']})",
                    "severity": "high" if risk_score > thresholds["critical_threshold"] else "medium",
                    "attack_type": atype,
                    "status": "new",
                    "mitre_id": mitre["technique_id"] if mitre else None,
                    "mitre_label": mitre["technique_name"] if mitre else None,
                    # Analyst drill-down data
                    "forest_risk": result["forest_risk"],
                    "trend_risk": result["trend_risk"],
                    "metric_scores": result.get("metric_scores", {}),
                    "playbook_actions": playbook_actions,
                    "mitre_response": mitre_response,
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
@limiter.limit("10 per minute")
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


# ---- /api/ingest — real telemetry ingestion ----

def _check_ingest_auth():
    """Return True if the request carries a valid ingest API key.

    Accepted in either the Authorization header (Bearer <key>) or the
    X-Kavach-Key header, to accommodate a wide range of webhook senders
    and syslog forwarders without requiring a browser session.
    """
    bearer = request.headers.get("Authorization", "")
    if bearer.startswith("Bearer "):
        return bearer[7:] == INGEST_API_KEY
    return request.headers.get("X-Kavach-Key", "") == INGEST_API_KEY


@app.route("/api/ingest", methods=["POST"])
@csrf.exempt  # machine-to-machine endpoint — CSRF protection via API key
@limiter.limit("600 per minute")  # generous; a SIEM can be chatty
def api_ingest():
    """Accept real telemetry and feed it into the per-sector baseline store.

    Authentication: Bearer token or X-Kavach-Key header (value = KAVACH_INGEST_KEY).

    Payload (JSON):

        Single reading for one sector:
        {
            "sector": "hospital",
            "source": "cloudwatch",          // optional free-text label
            "readings": [
                {
                    "network_traffic_mbps": 118.4,
                    "failed_logins": 1,
                    "cpu_usage_pct": 33.7,
                    "data_egress_mb": 4.9,
                    "active_connections": 148
                }
            ]
        }

        Batch for multiple sectors in one call:
        {
            "batch": [
                { "sector": "hospital",   "source": "syslog",  "readings": [...] },
                { "sector": "power_grid", "source": "siem",    "readings": [...] }
            ]
        }

    Response:
        { "accepted": <total rows written>, "skipped": <malformed rows>, "sectors": { ... } }
    """
    if not _check_ingest_auth():
        return jsonify({"error": "Unauthorized — provide a valid KAVACH_INGEST_KEY"}), 401

    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON"}), 400

    # Normalise both single-sector and multi-sector payloads into a list.
    if "batch" in body:
        items = body["batch"]
        if not isinstance(items, list):
            return jsonify({"error": "'batch' must be a list"}), 400
    elif "sector" in body:
        items = [body]
    else:
        return jsonify({"error": "Payload must contain 'sector' or 'batch'"}), 400

    total_accepted = 0
    total_skipped = 0
    per_sector = {}

    for item in items:
        sector = item.get("sector", "")
        if sector not in SECTORS:
            total_skipped += len(item.get("readings", []))
            continue
        source = str(item.get("source", "api"))[:64]
        readings = item.get("readings", [])
        if not isinstance(readings, list):
            total_skipped += 1
            continue

        written = storage.insert_ingest_readings(sector, readings, source_label=source)
        skipped = len(readings) - written
        total_accepted += written
        total_skipped += skipped
        per_sector[sector] = {"accepted": written, "skipped": skipped}

    return jsonify({
        "accepted": total_accepted,
        "skipped": total_skipped,
        "sectors": per_sector,
    }), 202


@app.route("/api/ingest/status")
@auth.admin_required
def api_ingest_status():
    """Admin-only: how many ingested rows exist per sector, and whether each
    detector has been trained on real data yet."""
    result = {}
    for sector in SECTORS:
        det = detectors[sector]
        result[sector] = {
            "ingest_row_count": storage.count_ingest_rows(sector),
            "trained_on_real_data": det.trained_on_real_data,
            "real_row_count_last_fit": det.real_row_count,
            "trained_at": det.trained_at,
            "trained_at_label": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(det.trained_at)
            ),
        }
    return jsonify(result)


@app.route("/api/analyst/queue")
@auth.login_required
def api_analyst_queue():
    """Triage queue for analyst: unresolved/new alerts, sorted by age/severity.
    Query params: sort (age|severity), status (new|acknowledged|unresolved|all)"""
    if session.get("role") not in ("analyst", "admin"):
        return {"error": "Analyst access required"}, 403
    
    sort_by = request.args.get("sort", "age")  # age or severity
    status_filter = request.args.get("status", "unresolved")  # new, acknowledged, unresolved, all
    
    # Get recent alerts with triage status
    all_logs = storage.recent_logs(limit=500)
    
    # Filter by status
    if status_filter == "all":
        filtered = [l for l in all_logs if l.get("status")]  # Only triage-eligible
    elif status_filter == "unresolved":
        filtered = [l for l in all_logs if l.get("status") in ("new", "acknowledged")]
    elif status_filter == "new":
        filtered = [l for l in all_logs if l.get("status") == "new"]
    elif status_filter == "acknowledged":
        filtered = [l for l in all_logs if l.get("status") == "acknowledged"]
    else:
        filtered = [l for l in all_logs if l.get("status")]
    
    # Calculate SLA (time since creation) for each alert, and attach the
    # recommended-action playbook / MITRE response framework. These are
    # recomputed here (rather than only trusted from storage) keyed off
    # attack_type/mitre_id, which are always persisted — so drill-down works
    # even for rows written before the playbook columns existed.
    now = time.time()
    for alert in filtered:
        ts = alert.get("ts") or now
        alert["sla_seconds"] = max(0, int(now - ts))
        alert["sla_minutes"] = alert["sla_seconds"] // 60

        alert["playbook_actions"] = RESPONSE_PLAYBOOK.get(alert.get("attack_type"), [])
        alert["mitre_response"] = MITRE_RESPONSE.get(alert.get("mitre_id"), "")
    
    # Sort
    if sort_by == "severity":
        severity_order = {"high": 0, "medium": 1, "low": 2}
        filtered.sort(key=lambda x: (severity_order.get(x.get("severity", "low"), 3), x.get("id", 0)), reverse=True)
    else:  # age (default)
        filtered.sort(key=lambda x: x.get("id", 0), reverse=True)  # Newest first
    
    return jsonify({
        "queue": filtered,
        "count": len(filtered),
        "total_triageable": len([l for l in all_logs if l.get("status")]),
    })


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


# ----------- executive view (business stakeholder) -----------

@app.route("/executive")
@auth.login_required
def executive_view():
    """Executive dashboard: trends, impact statements, SOC performance,
    board report export. Role-agnostic (both executive and admin can see it),
    but the UI is tailored toward business review rather than live ops."""
    if session.get("role") not in ("executive", "admin"):
        return {"error": "Executive access required"}, 403
    
    # Current sector risk scores for impact statements
    payload = {"sectors": {}}
    for sector in SECTORS:
        thresholds = sector_thresholds.get(sector, {"alert_threshold": 40.0, "critical_threshold": 75.0})
        reading, _ = simulator.next_reading(sector)
        result = detectors[sector].score(reading, alert_threshold=thresholds["alert_threshold"])
        risk_score = result["risk_score"]
        if contained[sector] > 0:
            risk_score *= 0.35
        payload["sectors"][sector] = {"risk_score": risk_score}
    
    # Impact statements for each sector
    impact_statements = {
        sector: _impact_statement(sector, payload["sectors"][sector]["risk_score"])
        for sector in SECTORS
    }
    
    # SOC performance metrics (7-day trailing)
    perf = storage.soc_performance_metrics()
    perf["avg_time_to_ack_label"] = f"{perf['avg_time_to_ack_seconds'] // 60} min"
    perf["avg_time_to_resolve_label"] = f"{perf['avg_time_to_resolve_seconds'] // 60} min"
    
    return render_template(
        "executive.html",
        role=auth.current_role(),
        display_name=auth.current_name(),
        sectors=SECTORS,
        sector_labels=SECTOR_LABEL,
        impact_statements=impact_statements,
        performance=perf,
        exec_summary=compute_exec_summary(payload),
    )


@app.route("/api/executive/trends")
@auth.login_required
def api_executive_trends():
    """Time-series risk data per sector over the last 7 days, for trend
    charting. Response: {sector: [{ts, risk_score}, ...], ...}"""
    if session.get("role") not in ("executive", "admin"):
        return {"error": "Executive access required"}, 403
    
    trends = {}
    for sector in SECTORS:
        points = storage.risk_history_range(sector, lookback_seconds=604800)
        trends[sector] = points
    return jsonify(trends)


@app.route("/api/executive/performance")
@auth.login_required
def api_executive_performance():
    """SOC team performance metrics: avg ack time, resolve time, containment %,
    incident count over 7 days."""
    if session.get("role") not in ("executive", "admin"):
        return {"error": "Executive access required"}, 403
    
    return jsonify(storage.soc_performance_metrics())


@app.route("/report/board-report")
@auth.login_required
def board_report_pdf():
    """High-level executive board report: org risk summary + top incidents
    of the week, formatted for C-suite review."""
    if session.get("role") not in ("executive", "admin"):
        return {"error": "Executive access required"}, 403
    
    from report_pdf import generate_board_report_pdf
    pdf_bytes = generate_board_report_pdf()
    filename = f"kavach_board_report_{int(time.time())}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------- admin routes (user management) ----------------

@app.route("/admin/reset-demo", methods=["POST"])
@auth.admin_required
def admin_reset_demo():
    """Wipes the anomaly log, risk history, and audit trail, and clears any
    active containment/detector state — so the dashboard can be handed to
    the next judge looking clean, without restarting the server (which
    would drop user accounts and threshold config). Users/thresholds are
    intentionally left untouched."""
    global detectors
    storage.reset_demo_data()
    for sector in SECTORS:
        contained[sector] = 0
        was_contained[sector] = False
    detectors = {s: SectorDetector() for s in SECTORS}
    log_audit_and_emit("Reset demo data")
    socketio.emit("demo_reset", {})
    return redirect(url_for("admin_panel", success="Demo data cleared — log, risk history, and audit trail reset."))


@app.route("/admin/detector/<sector>/retrain", methods=["POST"])
@auth.admin_required
def admin_retrain_detector(sector):
    """Granular retrain for a single sector.

    Prefers real ingested telemetry when enough rows exist (>= MIN_REAL_ROWS);
    falls back to a fresh synthetic-bootstrap detector otherwise.  Either way
    the containment/feedback-bias state for this sector is reset so the freshly
    fitted model starts clean.
    """
    if sector not in SECTORS:
        return redirect(url_for("admin_panel", error="Unknown sector."))

    rows = storage.get_ingest_baseline_window(
        sector, window_seconds=RETRAIN_WINDOW_SECONDS
    )
    if rows:
        ok = detectors[sector].retrain_on_real_data(rows)
        if ok:
            detail = f"{len(rows)} real telemetry rows (window={RETRAIN_WINDOW_SECONDS}s)"
        else:
            # rows were present but retrain returned False (shouldn't happen normally)
            detectors[sector] = SectorDetector()
            detail = "synthetic (real-data retrain failed)"
    else:
        detectors[sector] = SectorDetector()
        detail = "synthetic (no ingested data yet)"

    contained[sector] = 0
    was_contained[sector] = False
    log_audit_and_emit("Retrained detector", sector=sector, detail=detail)
    socketio.emit("detector_retrained", {"sector": sector, "detail": detail})
    storage.prune_ingest_telemetry(sector)

    label = SECTOR_LABEL.get(sector, sector)
    return redirect(url_for("admin_panel", success=f"Detector retrained for {label} — {detail}."))


@app.route("/api/admin/health")
@auth.admin_required
def api_admin_health():
    """Per-sector system health snapshot for the admin panel: data source
    (replay vs synthetic), when each detector was last (re)trained, and
    whether outbound webhook notifications are configured."""
    sectors_health = {}
    for sector in SECTORS:
        det = detectors[sector]
        sectors_health[sector] = {
            "data_source": "replay" if simulator.is_replaying(sector) else "synthetic",
            "detector_trained_at": det.trained_at,
            "contained": contained[sector] > 0,
            "trained_on_real_data": det.trained_on_real_data,
            "real_row_count": det.real_row_count,
            "ingest_row_count": storage.count_ingest_rows(sector),
        }
    return jsonify({
        "sectors": sectors_health,
        "webhook": notifier.current_config(),
        "ingest_key_configured": bool(os.environ.get("KAVACH_INGEST_KEY")),
        "retrain_interval_seconds": RETRAIN_INTERVAL,
        "retrain_window_seconds": RETRAIN_WINDOW_SECONDS,
    })


@app.route("/admin/notifier/test", methods=["POST"])
@auth.admin_required
def admin_notifier_test():
    ok, message = notifier.send_test_alert()
    log_audit_and_emit("Sent test webhook alert", detail=message)
    if ok:
        return redirect(url_for("admin_panel", success=message))
    return redirect(url_for("admin_panel", error=message))


@app.route("/admin/notifier/config", methods=["POST"])
@auth.admin_required
def admin_notifier_config():
    webhook_url = request.form.get("webhook_url", "")
    webhook_kind = request.form.get("webhook_kind", "slack")
    if webhook_url and not (webhook_url.startswith("http://") or webhook_url.startswith("https://")):
        return redirect(url_for("admin_panel", error="Webhook URL must start with http:// or https://"))

    actor = session.get("display_name", "Unknown")
    notifier.set_webhook_config(webhook_url, webhook_kind, actor)
    log_audit_and_emit(
        "Updated notification config",
        detail=f"kind={webhook_kind}, url={'set' if webhook_url else 'cleared'}",
    )
    return redirect(url_for("admin_panel", success="Notification config updated."))


@app.route("/admin/audit/export")
@auth.admin_required
def admin_audit_export():
    """CSV export of the (optionally filtered) audit trail — compliance-
    grade access that the analyst's live-scroll panel doesn't offer."""
    actor = request.args.get("actor") or None
    sector = request.args.get("sector") or None
    date_from = request.args.get("date_from") or None
    date_to = request.args.get("date_to") or None
    entries = storage.audit_log_filtered(
        actor=actor, sector=sector, date_from=date_from, date_to=date_to, limit=5000
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["time", "actor", "role", "action", "sector", "detail"])
    for e in entries:
        writer.writerow([e["time"], e["actor"], e["role"], e["action"], e["sector"] or "", e["detail"] or ""])

    filename = f"kavach_audit_{int(time.time())}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/admin/summary")
@auth.admin_required
def api_admin_summary():
    """Lightweight, dashboard-friendly snapshot for the Admin quick-panel —
    keeps admins from having to open /admin just to see user/threshold state."""
    users = storage.list_users()
    role_counts = {r: 0 for r in auth.ROLES}
    for u in users:
        role_counts[u["role"]] = role_counts.get(u["role"], 0) + 1
    return jsonify({
        "total_users": len(users),
        "role_counts": role_counts,
        "thresholds": sector_thresholds,
    })


@app.route("/admin")
@auth.admin_required
def admin_panel():
    audit_filters = {
        "actor": request.args.get("actor", ""),
        "sector": request.args.get("sector", ""),
        "date_from": request.args.get("date_from", ""),
        "date_to": request.args.get("date_to", ""),
    }
    audit_entries = storage.audit_log_filtered(
        actor=audit_filters["actor"] or None,
        sector=audit_filters["sector"] or None,
        date_from=audit_filters["date_from"] or None,
        date_to=audit_filters["date_to"] or None,
        limit=200,
    )
    sectors_health = {
        s: {
            "data_source": "replay" if simulator.is_replaying(s) else "synthetic",
            "detector_trained_at": detectors[s].trained_at,
            "detector_trained_label": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(detectors[s].trained_at)
            ),
            "contained": contained[s] > 0,
            "trained_on_real_data": detectors[s].trained_on_real_data,
            "real_row_count": detectors[s].real_row_count,
            "ingest_row_count": storage.count_ingest_rows(s),
        }
        for s in SECTORS
    }
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
        audit_entries=audit_entries,
        audit_filters=audit_filters,
        sectors_health=sectors_health,
        webhook_config=notifier.current_config(),
        retrain_interval_s=RETRAIN_INTERVAL,
        ingest_key_from_env=bool(os.environ.get("KAVACH_INGEST_KEY")),
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


# Register case management routes and socket events
register_case_management_routes(app, socketio, storage, log_audit_and_emit)
register_case_management_sockets(socketio, storage)
if __name__ == "__main__":
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    # DEMO_DEBUG=1 enables Flask debug mode for local development. Leave
    # unset for the actual jury demo — debug mode shows full Python
    # tracebacks on screen if anything throws mid-presentation.
    debug_mode = os.environ.get("DEMO_DEBUG") == "1"
    socketio.run(app, host="0.0.0.0", port=5001, debug=debug_mode, use_reloader=False, allow_unsafe_werkzeug=True)