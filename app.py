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

from flask_socketio import SocketIO, join_room, leave_room
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

# ---- lightweight service-health tracking for the Admin "System Status"
# panel. Updated by the background loop / socket connect-disconnect
# handlers rather than faked -- these reflect what's actually running in
# this process.
system_health_state = {
    "last_tick_ts": time.time(),
    "connected_clients": 0,
}

# Static per-metric baselines the detector was trained against (mirrors
# simulator.METRIC_BASELINES) -- exposed read-only so the Security Manager
# dashboard can translate live metrics into plain-English business impact
# without duplicating detector internals or fabricating numbers.
from simulator import METRIC_BASELINES

# Audit action labels that belong on the Admin console's "Recent Admin
# Actions" panel -- configuration/governance events only, never SOC
# response actions (those live on the Analyst audit trail instead).
ADMIN_AUDIT_ACTIONS = [
    "Created user",
    "Deleted user",
    "Reset password",
    "Updated detection thresholds",
    "Reset demo data",
]


# Socket.IO room joined only by connections whose role can view the audit
# trail (SOC Analyst / System Administrator) -- see on_connect() below.
AUDIT_ROOM = "audit_viewers"


def log_audit_and_emit(action, sector=None, detail=""):
    """Record an audit entry (who did what, when) and push it live to
    connected clients whose role is actually permitted to see the audit
    trail -- Security Managers don't get audit data pushed to their
    browser at all, not just hidden in the UI."""
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
    socketio.emit("audit_log", {"entries": [entry]}, room=AUDIT_ROOM)


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
    """Continuously generate telemetry, score it, propagate, persist, and push to clients."""
    while True:
        system_health_state["last_tick_ts"] = time.time()
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
                "metric_scores": result["metric_scores"],
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
                    "risk_score": round(risk_score, 1),
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


# ---------------- role-specific dashboards ----------------
# Each role lands on a genuinely different workspace over the same
# underlying KAVACH data -- different navigation, KPIs, primary widgets,
# and actions, not one dashboard with cards hidden by role.

@app.route("/")
@auth.login_required
def index():
    return redirect(url_for(auth.current_home_endpoint()))


@app.route("/analyst")
@auth.permission_required("view_alerts")
def analyst_dashboard():
    """SOC console -- operational, real-time, alert-centric, response-focused."""
    return render_template(
        "analyst.html",
        role=auth.current_role(),
        role_display=auth.current_role_display(),
        display_name=auth.current_name(),
        kpis=storage.alert_kpis(),
        contained_count=sum(1 for v in contained.values() if v > 0),
        sectors=SECTORS,
        sector_labels=SECTOR_LABEL,
    )


@app.route("/manager")
@auth.permission_required("view_security_posture")
def manager_dashboard():
    """Security posture console -- strategic, organizational, risk-centric,
    decision-focused. No operational response controls live here."""
    return render_template(
        "manager.html",
        role=auth.current_role(),
        role_display=auth.current_role_display(),
        display_name=auth.current_name(),
        sectors=SECTORS,
        sector_labels=SECTOR_LABEL,
        sector_weights=SECTOR_WEIGHTS,
    )


@app.route("/admin")
@auth.permission_required("view_system_health")
def admin_dashboard():
    """Admin console -- technical, configuration-centric, system-health-
    focused. Deliberately NOT analyst+manager+admin combined: no SOC
    response actions, no risk/posture widgets live here."""
    replay_status = {s: simulator.is_replaying(s) for s in SECTORS}
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
    return render_template(
        "admin.html",
        role=auth.current_role(),
        role_display=auth.current_role_display(),
        display_name=auth.current_name(),
        users=storage.list_users(),
        roles=auth.ROLES,
        role_display_map=auth.ROLE_DISPLAY,
        error=request.args.get("error"),
        success=request.args.get("success"),
        sectors=SECTORS,
        sector_labels=SECTOR_LABEL,
        thresholds=sector_thresholds,
        replay_status=replay_status,
        secret_key_from_env=bool(os.environ.get("SECRET_KEY")),
        webhook_configured=bool(notifier.WEBHOOK_URL),
        replay_sectors=[SECTOR_LABEL.get(s, s) for s in REPLAY_FILES.keys()],
        audit_entries=audit_entries,
        audit_filters=audit_filters,
    )


@app.route("/admin/audit/export")
@auth.permission_required("view_system_audit_logs")
def admin_audit_export():
    """CSV export of the (optionally filtered) audit trail -- same filters
    as the on-screen table, so what an admin sees is exactly what they get
    in the exported file, just without the 200-row on-screen cap."""
    entries = storage.audit_log_filtered(
        actor=request.args.get("actor") or None,
        sector=request.args.get("sector") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
        limit=100000,
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["time", "actor", "role", "action", "sector", "detail"])
    for e in entries:
        writer.writerow([e.get("time"), e.get("actor"), e.get("role"),
                          e.get("action"), e.get("sector") or "", e.get("detail") or ""])
    log_audit_and_emit("Exported audit trail", detail=f"{len(entries)} entries")
    filename = f"kavach_audit_trail_{int(time.time())}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )



@app.route("/api/history/<sector>")
@auth.login_required
def api_history(sector):
    if sector not in SECTORS:
        return jsonify({"error": "unknown sector"}), 404
    return jsonify(storage.sector_history(sector, limit=120))


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
@auth.permission_required("view_audit_logs", "view_system_audit_logs")
def api_audit():
    return jsonify(storage.recent_audit(50))


@app.route("/api/incident-kpis")
@auth.permission_required("view_alerts", "view_incident_summary")
def api_incident_kpis():
    """Live alert/incident counts -- powers the Analyst KPI row and the
    Manager security-posture summary from the same underlying triage data."""
    kpis = storage.alert_kpis()
    kpis["contained_sectors"] = sum(1 for v in contained.values() if v > 0)
    kpis["incidents_24h"] = storage.incident_count_since(INCIDENT_WINDOW_SECONDS)
    return jsonify(kpis)


@app.route("/api/metrics/baselines")
@auth.login_required
def api_metric_baselines():
    """Read-only normal-condition baselines (mean, std) per telemetry
    metric -- lets the Security Manager dashboard translate live sector
    metrics into plain-English business impact without re-deriving or
    faking detector internals."""
    return jsonify(METRIC_BASELINES)


@app.route("/api/admin/system-health")
@auth.permission_required("view_system_health")
def api_admin_system_health():
    """Live health snapshot of KAVACH's own backend services, for the Admin
    console's System Status panel -- derived from real process state, not
    hardcoded 'all green' values."""
    now = time.time()
    seconds_since_tick = now - system_health_state["last_tick_ts"]
    detection_status = "ONLINE" if seconds_since_tick < 5 else (
        "WARNING" if seconds_since_tick < 15 else "OFFLINE"
    )

    try:
        storage.recent_audit(1)
        db_status = "ONLINE"
    except Exception:
        db_status = "ERROR"

    notifier_status = "ONLINE" if notifier.WEBHOOK_URL else "WARNING"
    notifier_detail = "Webhook configured" if notifier.WEBHOOK_URL else "Optional webhook not configured"

    return jsonify({
        "services": [
            {"name": "Detection Engine", "status": detection_status,
             "detail": f"Last scoring tick {seconds_since_tick:.1f}s ago"},
            {"name": "Telemetry Simulator", "status": detection_status,
             "detail": "Synthetic + CSV replay sources" if any(
                 simulator.is_replaying(s) for s in SECTORS) else "Synthetic generation"},
            {"name": "Database (SQLite)", "status": db_status, "detail": "kavach.db"},
            {"name": "Socket.IO Real-Time Service", "status": "ONLINE",
             "detail": f"{system_health_state['connected_clients']} client(s) connected"},
            {"name": "Notification Service", "status": notifier_status, "detail": notifier_detail},
        ],
    })


@app.route("/api/admin/summary")
@auth.permission_required("view_system_health")
def api_admin_summary():
    """Dashboard-friendly snapshot for the Admin console: user/role counts,
    current thresholds, and recent governance actions."""
    users = storage.list_users()
    role_counts = {r: 0 for r in auth.ROLES}
    for u in users:
        role_counts[u["role"]] = role_counts.get(u["role"], 0) + 1
    return jsonify({
        "total_users": len(users),
        "role_counts": role_counts,
        "thresholds": sector_thresholds,
        "recent_actions": storage.recent_audit_by_actions(ADMIN_AUDIT_ACTIONS, limit=15),
    })


@app.route("/report/<sector>")
@auth.permission_required("generate_incident_reports", "generate_reports")
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
@auth.permission_required("generate_incident_reports", "generate_reports")
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


# ---------------- admin routes (system configuration & governance) ----------------

@app.route("/admin/reset-demo", methods=["POST"])
@auth.permission_required("reset_demo_environment")
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
    return redirect(url_for("admin_dashboard", success="Demo data cleared — log, risk history, and audit trail reset."))


@app.route("/admin/thresholds/update", methods=["POST"])
@auth.permission_required("configure_thresholds")
def admin_update_thresholds():
    sector = request.form.get("sector", "")
    if sector not in SECTORS:
        return redirect(url_for("admin_dashboard", error="Unknown sector."))

    try:
        alert_threshold = float(request.form.get("alert_threshold", ""))
        critical_threshold = float(request.form.get("critical_threshold", ""))
    except ValueError:
        return redirect(url_for("admin_dashboard", error="Thresholds must be numbers."))

    if not (0 <= alert_threshold <= 100 and 0 <= critical_threshold <= 100):
        return redirect(url_for("admin_dashboard", error="Thresholds must be between 0 and 100."))
    if critical_threshold <= alert_threshold:
        return redirect(url_for("admin_dashboard", error="Critical threshold must be higher than the alert threshold."))

    actor = session.get("display_name", "Unknown")
    storage.update_threshold(sector, alert_threshold, critical_threshold, actor)
    sector_thresholds[sector] = {"alert_threshold": alert_threshold, "critical_threshold": critical_threshold}

    log_audit_and_emit(
        "Updated detection thresholds", sector=sector,
        detail=f"alert>{alert_threshold}, critical>{critical_threshold}",
    )
    socketio.emit("thresholds_updated", {"sector": sector, **sector_thresholds[sector]})
    return redirect(url_for("admin_dashboard", success=f"Thresholds updated for {SECTOR_LABEL.get(sector, sector)}."))


@app.route("/admin/users/add", methods=["POST"])
@auth.permission_required("manage_users")
def admin_add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "")
    display_name = request.form.get("display_name", "").strip() or username

    if not username or not password or role not in auth.ROLES:
        return redirect(url_for("admin_dashboard", error="All fields are required and role must be valid."))
    if storage.get_user(username):
        return redirect(url_for("admin_dashboard", error=f"Username '{username}' already exists."))

    storage.add_user(username, generate_password_hash(password), role, display_name)
    log_audit_and_emit("Created user", detail=f"{username} ({role})")
    return redirect(url_for("admin_dashboard", success=f"User '{username}' created."))


@app.route("/admin/users/<username>/delete", methods=["POST"])
@auth.permission_required("manage_users")
def admin_delete_user(username):
    target = storage.get_user(username)
    if not target:
        return redirect(url_for("admin_dashboard", error="User not found."))
    if username == session.get("username"):
        return redirect(url_for("admin_dashboard", error="You can't delete your own account."))
    if target["role"] == "admin" and storage.count_users_by_role("admin") <= 1:
        return redirect(url_for("admin_dashboard", error="Can't delete the last remaining admin."))

    storage.delete_user(username)
    log_audit_and_emit("Deleted user", detail=username)
    return redirect(url_for("admin_dashboard", success=f"User '{username}' deleted."))


@app.route("/admin/users/<username>/reset-password", methods=["POST"])
@auth.permission_required("reset_passwords")
def admin_reset_password(username):
    new_password = request.form.get("new_password", "")
    if not storage.get_user(username):
        return redirect(url_for("admin_dashboard", error="User not found."))
    if not new_password:
        return redirect(url_for("admin_dashboard", error="New password can't be empty."))

    storage.update_password(username, generate_password_hash(new_password))
    log_audit_and_emit("Reset password", detail=username)
    return redirect(url_for("admin_dashboard", success=f"Password reset for '{username}'."))


# ---------------- socket events ----------------
# Every state-changing event below re-checks the actor's permission
# server-side via auth.has_permission(); a client simply not rendering a
# button is never treated as the authorization boundary.

@socketio.on("connect")
def on_connect():
    if "role" not in session:
        return False  # reject unauthenticated socket connections

    system_health_state["connected_clients"] += 1

    socketio.emit(
        "log_history",
        {"log": storage.recent_logs(30)},
        to=request.sid,
    )

    # Only clients whose role can actually view the audit trail join the
    # room that receives it -- both the initial history and live updates.
    if auth.has_permission("view_audit_logs") or auth.has_permission("view_system_audit_logs"):
        join_room(AUDIT_ROOM)
        socketio.emit(
            "audit_log",
            {"entries": storage.recent_audit(50)},
            to=request.sid,
        )

    socketio.emit(
        "session_info",
        {"role": session.get("role"), "role_display": auth.current_role_display(),
         "name": session.get("display_name")},
        to=request.sid,
    )
    socketio.emit(
        "thresholds_bulk",
        {"thresholds": sector_thresholds},
        to=request.sid,
    )


@socketio.on("disconnect")
def on_disconnect():
    system_health_state["connected_clients"] = max(0, system_health_state["connected_clients"] - 1)


@socketio.on("trigger_attack")
def on_trigger_attack(data):
    if not auth.has_permission("trigger_demo_attack"):
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
    if not auth.has_permission("contain_sector"):
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
    if not auth.has_permission("mark_false_positive"):
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
    if not auth.has_permission("update_alert_status"):
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

# These are same-origin, session-authenticated JSON APIs called via fetch()
# from analyst.js -- there's no HTML <form> to carry a hidden csrf_token
# field, so without this they 400 on every single POST/PUT/DELETE (create,
# close, link, comment, ...), which is why the incident workflow appeared
# built but never actually worked end-to-end. GET-only routes don't need it.
_CASE_MGMT_MUTATING_ENDPOINTS = [
    "create_incident_api", "update_incident_api", "close_incident_api", "delete_incident_api",
    "add_alert_to_incident_api", "remove_alert_from_incident_api",
    "link_incidents_api", "unlink_incidents_api",
    "add_comment_api", "update_comment_api", "delete_comment_api",
]
for _endpoint in _CASE_MGMT_MUTATING_ENDPOINTS:
    csrf.exempt(app.view_functions[_endpoint])
if __name__ == "__main__":
    t = threading.Thread(target=background_loop, daemon=True)
    t.start()
    # DEMO_DEBUG=1 enables Flask debug mode for local development. Leave
    # unset for the actual jury demo — debug mode shows full Python
    # tracebacks on screen if anything throws mid-presentation.
    debug_mode = os.environ.get("DEMO_DEBUG") == "1"
    socketio.run(app, host="0.0.0.0", port=5001, debug=debug_mode, use_reloader=False, allow_unsafe_werkzeug=True)