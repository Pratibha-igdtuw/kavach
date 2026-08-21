"""
SQLite persistence for the anomaly log, risk-score history, user accounts,
audit trail, and case management — so the dashboard survives restarts, renders
historical trend charts, keeps a durable record of who did what, and supports
incident grouping, linking, and team collaboration.

Tables:
  - log: Anomaly detections (individual alerts)
  - risk_history: Time-series risk scores per sector
  - users: User accounts (analyst/executive/admin)
  - audit_log: Compliance audit trail (who did what when)
  - sector_thresholds: Per-sector alert/critical thresholds
  - notifier_config: Webhook configuration (Slack/Discord)
  - incident: Main case/incident record
  - incident_alert: M:N link (alerts → incidents)
  - incident_link: Incident relationships (related, chain, etc.)
  - incident_comment: Collaboration thread per incident
"""
import json
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "kavach.db"


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    except Exception as e:
        c.rollback()
        raise
    finally:
        c.close()


def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                time_str TEXT,
                sector TEXT,
                message TEXT,
                severity TEXT,
                attack_type TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                sector TEXT,
                risk_score REAL,
                is_anomaly INTEGER
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_ts REAL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                time_str TEXT,
                actor TEXT,
                role TEXT,
                action TEXT,
                sector TEXT,
                detail TEXT
            )
        """)
        # Per-sector configurable detection thresholds (risk-score cutoffs).
        # alert_threshold  — score above which a reading is flagged as an anomaly.
        # critical_threshold — score above which a sector is considered critical
        #                       (drives card color, exec summary, blast-radius ETA).
        c.execute("""
            CREATE TABLE IF NOT EXISTS sector_thresholds (
                sector TEXT PRIMARY KEY,
                alert_threshold REAL NOT NULL,
                critical_threshold REAL NOT NULL,
                updated_by TEXT,
                updated_ts REAL
            )
        """)
        # Persisted webhook config (admin-settable) — a single row (id=1) is
        # upserted in place. Falls back to env vars in notifier.py if this
        # table has no row yet, so nothing breaks on an existing DB.
        c.execute("""
            CREATE TABLE IF NOT EXISTS notifier_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                webhook_url TEXT,
                webhook_kind TEXT,
                updated_by TEXT,
                updated_ts REAL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_log_sector ON log(sector)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_history_sector_ts ON risk_history(sector, ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")

        # ---- lightweight migrations: add triage/MITRE columns to `log` if an
        # older kavach.db (pre-triage-queue) is already on disk. Each ALTER is
        # tried independently so a partially-migrated DB still finishes.
        existing_cols = {row["name"] for row in c.execute("PRAGMA table_info(log)").fetchall()}
        migrations = {
            "status": "ALTER TABLE log ADD COLUMN status TEXT",
            "mitre_id": "ALTER TABLE log ADD COLUMN mitre_id TEXT",
            "mitre_label": "ALTER TABLE log ADD COLUMN mitre_label TEXT",
            "ack_by": "ALTER TABLE log ADD COLUMN ack_by TEXT",
            "ack_ts": "ALTER TABLE log ADD COLUMN ack_ts REAL",
            "resolved_by": "ALTER TABLE log ADD COLUMN resolved_by TEXT",
            "resolved_ts": "ALTER TABLE log ADD COLUMN resolved_ts REAL",
            # Explainability columns: the detector always computes these, but
            # until this migration they were silently dropped on insert (see
            # insert_log below) -- so drill-down/incident views could never
            # show *why* a score was high once the live socket payload was gone.
            "forest_risk": "ALTER TABLE log ADD COLUMN forest_risk REAL",
            "trend_risk": "ALTER TABLE log ADD COLUMN trend_risk REAL",
            "metric_scores": "ALTER TABLE log ADD COLUMN metric_scores TEXT",
        }
        for col, ddl in migrations.items():
            if col not in existing_cols:
                try:
                    c.execute(ddl)
                except sqlite3.OperationalError:
                    # Column already exists or other issue, skip
                    pass

        # Initialize case management tables (safe to call on existing DB)
    init_case_management_db()


# ---------------- anomaly log ----------------

def insert_log(entry):
    """Inserts a log/anomaly entry. If entry carries a `status` (i.e. it's a
    genuine anomaly that belongs in the triage queue, as opposed to a
    propagation/manual/system note), that status plus MITRE mapping fields
    are persisted too. Also persists the detector's explainability output
    (forest_risk / trend_risk / per-metric z-scores) when present, so *why*
    a score was high survives a page refresh instead of only existing in the
    live socket payload. Returns the new row's id so callers can reference
    it for later triage state changes."""
    metric_scores = entry.get("metric_scores")
    metric_scores_json = None
    if metric_scores:
        try:
            metric_scores_json = json.dumps(metric_scores)
        except (TypeError, ValueError):
            metric_scores_json = None
    
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO log (ts, time_str, sector, message, severity, attack_type, "
            "status, mitre_id, mitre_label, forest_risk, trend_risk, metric_scores) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), entry.get("time", ""), entry.get("sector", ""), 
             entry.get("message", ""), entry.get("severity", ""),
             entry.get("attack_type"), entry.get("status"),
             entry.get("mitre_id"), entry.get("mitre_label"),
             entry.get("forest_risk"), entry.get("trend_risk"),
             metric_scores_json),
        )
        return cur.lastrowid


def insert_risk_point(sector, risk_score, is_anomaly):
    with _conn() as c:
        c.execute(
            "INSERT INTO risk_history (ts, sector, risk_score, is_anomaly) VALUES (?, ?, ?, ?)",
            (time.time(), sector, risk_score, int(is_anomaly)),
        )


def recent_logs(limit=30):
    with _conn() as c:
        rows = c.execute(
            "SELECT id, ts, time_str as time, sector, message, severity, attack_type, "
            "status, mitre_id, mitre_label, ack_by, ack_ts, resolved_by, resolved_ts, "
            "forest_risk, trend_risk, metric_scores "
            "FROM log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        out = []
        for r in reversed(rows):
            d = dict(r)
            raw_scores = d.pop("metric_scores", None)
            try:
                d["metric_scores"] = json.loads(raw_scores) if raw_scores else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                d["metric_scores"] = {}
            d["forest_risk"] = float(d.get("forest_risk") or 0.0)
            d["trend_risk"] = float(d.get("trend_risk") or 0.0)
            out.append(d)
        return out


def update_alert_status(log_id, status, actor):
    """Move an alert through New -> Acknowledged -> Resolved. Returns the
    updated row (with sector, so the caller can broadcast it), or None if
    the id doesn't exist or isn't a triage-eligible entry."""
    valid_statuses = {"new", "acknowledged", "resolved"}
    if status not in valid_statuses:
        return None
    with _conn() as c:
        row = c.execute(
            "SELECT id, sector, status FROM log WHERE id = ? AND status IS NOT NULL",
            (log_id,),
        ).fetchone()
        if not row:
            return None

        now = time.time()
        if status == "acknowledged":
            c.execute(
                "UPDATE log SET status = ?, ack_by = ?, ack_ts = ? WHERE id = ?",
                (status, actor, now, log_id),
            )
        elif status == "resolved":
            c.execute(
                "UPDATE log SET status = ?, resolved_by = ?, resolved_ts = ? WHERE id = ?",
                (status, actor, now, log_id),
            )
        else:  # back to "new"
            c.execute("UPDATE log SET status = ? WHERE id = ?", (status, log_id))

        return {"id": log_id, "sector": row["sector"], "status": status}


def alert_counts_by_status():
    """{'new': n, 'acknowledged': n, 'resolved': n} across all triage-eligible entries."""
    with _conn() as c:
        rows = c.execute(
            "SELECT status, COUNT(*) as cnt FROM log WHERE status IS NOT NULL GROUP BY status"
        ).fetchall()
        return {r["status"]: r["cnt"] for r in rows}


def alert_kpis():
    """Summary counts for the Analyst SOC console KPI row: critical (open,
    high-severity), new, and active (not yet resolved) alerts, all drawn
    from the same triage-eligible `log` rows the alert queue already uses."""
    with _conn() as c:
        critical = c.execute(
            "SELECT COUNT(*) as cnt FROM log WHERE status IS NOT NULL "
            "AND status != 'resolved' AND severity = 'high'"
        ).fetchone()["cnt"]
        new = c.execute(
            "SELECT COUNT(*) as cnt FROM log WHERE status = 'new'"
        ).fetchone()["cnt"]
        active = c.execute(
            "SELECT COUNT(*) as cnt FROM log WHERE status IS NOT NULL AND status != 'resolved'"
        ).fetchone()["cnt"]
        return {"critical": critical, "new": new, "active_incidents": active}


def sector_history(sector, limit=120):
    with _conn() as c:
        rows = c.execute(
            "SELECT ts, risk_score, is_anomaly FROM risk_history "
            "WHERE sector = ? ORDER BY id DESC LIMIT ?", (sector, limit)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


def sector_incident_window(sector, lookback_seconds=1800):
    """Logs and risk points for the last N seconds, for report generation."""
    cutoff = time.time() - lookback_seconds
    with _conn() as c:
        logs = c.execute(
            "SELECT time_str as time, sector, message, severity, attack_type, "
            "status, mitre_id, mitre_label "
            "FROM log WHERE sector = ? AND ts >= ? ORDER BY id ASC", (sector, cutoff)
        ).fetchall()
        points = c.execute(
            "SELECT ts, risk_score, is_anomaly FROM risk_history "
            "WHERE sector = ? AND ts >= ? ORDER BY id ASC", (sector, cutoff)
        ).fetchall()
        return [dict(r) for r in logs], [dict(r) for r in points]


def incident_count_since(lookback_seconds=86400):
    """Count of genuine anomaly detections (not propagation/manual/admin
    entries) in the trailing window — used for the executive summary."""
    cutoff = time.time() - lookback_seconds
    with _conn() as c:
        row = c.execute(
            "SELECT COUNT(*) as cnt FROM log WHERE ts >= ? AND message LIKE 'Anomaly detected%'",
            (cutoff,),
        ).fetchone()
        return row["cnt"] if row else 0


# ---------------- users ----------------

def get_user(username):
    with _conn() as c:
        row = c.execute(
            "SELECT username, password_hash, role, display_name FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None


def list_users():
    with _conn() as c:
        rows = c.execute(
            "SELECT username, role, display_name FROM users ORDER BY "
            "CASE role WHEN 'admin' THEN 0 WHEN 'analyst' THEN 1 ELSE 2 END, username"
        ).fetchall()
        return [dict(r) for r in rows]


def count_users_by_role(role):
    with _conn() as c:
        row = c.execute("SELECT COUNT(*) as cnt FROM users WHERE role = ?", (role,)).fetchone()
        return row["cnt"] if row else 0


def add_user(username, password_hash, role, display_name):
    with _conn() as c:
        c.execute(
            "INSERT INTO users (username, password_hash, role, display_name, created_ts) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, role, display_name, time.time()),
        )


def delete_user(username):
    with _conn() as c:
        c.execute("DELETE FROM users WHERE username = ?", (username,))


def update_password(username, password_hash):
    with _conn() as c:
        c.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (password_hash, username),
        )


def seed_default_users(defaults):
    """defaults: list of (username, password_hash, role, display_name).
    Only inserts accounts that don't already exist — safe to call every boot."""
    with _conn() as c:
        for username, password_hash, role, display_name in defaults:
            existing = c.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not existing:
                c.execute(
                    "INSERT INTO users (username, password_hash, role, display_name, created_ts) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (username, password_hash, role, display_name, time.time()),
                )


# ---------------- per-sector detection thresholds ----------------

def seed_default_thresholds(defaults):
    """defaults: list of (sector, alert_threshold, critical_threshold).
    Only inserts sectors that don't already have a row — safe every boot."""
    with _conn() as c:
        for sector, alert_threshold, critical_threshold in defaults:
            existing = c.execute(
                "SELECT 1 FROM sector_thresholds WHERE sector = ?", (sector,)
            ).fetchone()
            if not existing:
                c.execute(
                    "INSERT INTO sector_thresholds (sector, alert_threshold, critical_threshold, "
                    "updated_by, updated_ts) VALUES (?, ?, ?, ?, ?)",
                    (sector, alert_threshold, critical_threshold, "system", time.time()),
                )


def get_all_thresholds():
    with _conn() as c:
        rows = c.execute(
            "SELECT sector, alert_threshold, critical_threshold FROM sector_thresholds"
        ).fetchall()
        return {r["sector"]: {"alert_threshold": r["alert_threshold"],
                               "critical_threshold": r["critical_threshold"]} for r in rows}


def update_threshold(sector, alert_threshold, critical_threshold, actor):
    with _conn() as c:
        c.execute(
            "INSERT INTO sector_thresholds (sector, alert_threshold, critical_threshold, "
            "updated_by, updated_ts) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(sector) DO UPDATE SET alert_threshold = excluded.alert_threshold, "
            "critical_threshold = excluded.critical_threshold, updated_by = excluded.updated_by, "
            "updated_ts = excluded.updated_ts",
            (sector, alert_threshold, critical_threshold, actor, time.time()),
        )


# ---------------- audit trail ----------------

def insert_audit(actor, role, action, sector=None, detail=""):
    with _conn() as c:
        c.execute(
            "INSERT INTO audit_log (ts, time_str, actor, role, action, sector, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), time.strftime("%H:%M:%S"), actor, role, action, sector, detail),
        )


def recent_audit(limit=50):
    with _conn() as c:
        rows = c.execute(
            "SELECT time_str as time, actor, role, action, sector, detail "
            "FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


def audit_log_filtered(actor=None, sector=None, date_from=None, date_to=None, limit=1000):
    """Compliance-grade audit query for the admin panel: optional filters by
    actor (substring match), sector (exact), and an inclusive date range
    (date_from/date_to as 'YYYY-MM-DD' strings, interpreted in local time).
    Newest first. Used for both the on-screen table and the CSV export, so
    the two always agree on what "the filtered audit trail" means."""
    clauses = []
    params = []
    if actor:
        clauses.append("actor LIKE ?")
        params.append(f"%{actor}%")
    if sector:
        clauses.append("sector = ?")
        params.append(sector)
    if date_from:
        try:
            clauses.append("ts >= ?")
            params.append(time.mktime(time.strptime(date_from, "%Y-%m-%d")))
        except ValueError:
            pass
    if date_to:
        try:
            # end-of-day for the "to" date, so that date is inclusive
            clauses.append("ts <= ?")
            params.append(time.mktime(time.strptime(date_to, "%Y-%m-%d")) + 86399)
        except ValueError:
            pass

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with _conn() as c:
        rows = c.execute(
            f"SELECT time_str as time, actor, role, action, sector, detail "
            f"FROM audit_log {where} ORDER BY id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


def recent_audit_by_actions(actions, limit=20):
    """Audit entries whose `action` is in the given list, most recent first.
    Used by the Admin console's "Recent Admin Actions" panel so it only
    shows configuration/governance events, not SOC response actions."""
    if not actions:
        return []
    placeholders = ",".join("?" for _ in actions)
    with _conn() as c:
        rows = c.execute(
            f"SELECT time_str as time, actor, role, action, sector, detail "
            f"FROM audit_log WHERE action IN ({placeholders}) ORDER BY id DESC LIMIT ?",
            (*actions, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------- notifier (webhook) config ----------------

def get_notifier_config():
    """Returns {'webhook_url', 'webhook_kind', 'updated_by', 'updated_ts'} if
    an admin has ever set one via the panel, else None (caller should then
    fall back to env vars for backward compatibility)."""
    with _conn() as c:
        row = c.execute(
            "SELECT webhook_url, webhook_kind, updated_by, updated_ts "
            "FROM notifier_config WHERE id = 1"
        ).fetchone()
        return dict(row) if row else None


def set_notifier_config(webhook_url, webhook_kind, actor):
    with _conn() as c:
        c.execute(
            "INSERT INTO notifier_config (id, webhook_url, webhook_kind, updated_by, updated_ts) "
            "VALUES (1, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET webhook_url = excluded.webhook_url, "
            "webhook_kind = excluded.webhook_kind, updated_by = excluded.updated_by, "
            "updated_ts = excluded.updated_ts",
            (webhook_url, webhook_kind, actor, time.time()),
        )


# ---------------- demo reset ----------------

def reset_demo_data():
    """Wipes anomaly log, risk history, and audit trail — everything that
    accumulates during a live demo run — while leaving user accounts and
    threshold configuration untouched. Used by the admin 'Reset Demo'
    action so the dashboard can be handed to the next judge looking clean,
    without restarting the whole server (which would also lose users)."""
    with _conn() as c:
        c.execute("DELETE FROM log")
        c.execute("DELETE FROM risk_history")
        c.execute("DELETE FROM audit_log")


# ---------------- executive analytics ----------------

def risk_history_range(sector, lookback_seconds=604800):
    """Return time-series risk points for a sector over the last N seconds
    (default 7 days), ordered chronologically. Used for trend charts."""
    cutoff = time.time() - lookback_seconds
    with _conn() as c:
        rows = c.execute(
            "SELECT ts, risk_score FROM risk_history "
            "WHERE sector = ? AND ts >= ? ORDER BY ts ASC",
            (sector, cutoff),
        ).fetchall()
        return [{"ts": r["ts"], "risk_score": r["risk_score"]} for r in rows]


def soc_performance_metrics(lookback_seconds=604800):
    """Analyst/SOC team performance metrics (7-day trailing window):
    - avg_time_to_ack: seconds from incident creation to acknowledgment
    - avg_time_to_resolve: seconds from creation to resolution
    - pct_contained: % of all incidents that had a containment action
    - total_incidents: count of genuine anomalies (not propagation/admin notes)
    """
    cutoff = time.time() - lookback_seconds
    with _conn() as c:
        # All triage-eligible log entries created in the window (genuine anomalies)
        all_rows = c.execute(
            "SELECT ts, status, ack_ts, resolved_ts FROM log "
            "WHERE ts >= ? AND status IS NOT NULL",
            (cutoff,),
        ).fetchall()

        # Count entries with containment action logged in this window
        contained_count = c.execute(
            "SELECT COUNT(*) as cnt FROM log "
            "WHERE ts >= ? AND message LIKE '%Containment protocol%'",
            (cutoff,),
        ).fetchone()
        contained = contained_count["cnt"] if contained_count else 0

        if not all_rows:
            return {
                "avg_time_to_ack_seconds": 0,
                "avg_time_to_resolve_seconds": 0,
                "pct_contained": 0.0,
                "total_incidents": 0,
            }

        ack_times = []
        resolve_times = []
        for row in all_rows:
            if row["ack_ts"]:
                ack_times.append(row["ack_ts"] - row["ts"])
            if row["resolved_ts"]:
                resolve_times.append(row["resolved_ts"] - row["ts"])

        avg_ack = sum(ack_times) / len(ack_times) if ack_times else 0
        avg_resolve = sum(resolve_times) / len(resolve_times) if resolve_times else 0
        pct_contained = (contained / len(all_rows) * 100) if all_rows else 0.0

        return {
            "avg_time_to_ack_seconds": round(avg_ack),
            "avg_time_to_resolve_seconds": round(avg_resolve),
            "pct_contained": round(pct_contained, 1),
            "total_incidents": len(all_rows),
        }


def top_incidents_this_week(limit=10):
    """Top incidents by severity/risk over the last 7 days, for the board
    report — includes message, sector, severity, time, MITRE ID."""
    cutoff = time.time() - 604800
    with _conn() as c:
        rows = c.execute(
            "SELECT time_str, sector, message, severity, mitre_id, mitre_label "
            "FROM log "
            "WHERE ts >= ? AND status IS NOT NULL "
            "ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, id DESC "
            "LIMIT ?",
            (cutoff, limit),
        ).fetchall()
        return [dict(r) for r in rows]


# ============================================================================
# CASE MANAGEMENT — Incident Grouping, Linking, Collaboration
# ============================================================================

def init_case_management_db():
    """Add case management schema to an existing KAVACH database.
    
    New tables:
      - incident: Main case/incident record (title, description, status, severity)
      - incident_alert: M:N link between incidents and log entries
      - incident_link: Relationship between two incidents (related, chain, etc.)
      - incident_comment: Thread of analyst notes/comments per incident
    
    Call once during app startup (safe to call on existing DB).
    """
    with _conn() as c:
        # Main incident/case record
        c.execute("""
            CREATE TABLE IF NOT EXISTS incident (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT NOT NULL DEFAULT 'medium',
                sector TEXT,
                ts REAL NOT NULL,
                created_by TEXT NOT NULL,
                closed_ts REAL,
                closed_by TEXT,
                root_cause TEXT,
                resolution_summary TEXT
            )
        """)
        
        # M:N link: which alerts belong to this incident
        c.execute("""
            CREATE TABLE IF NOT EXISTS incident_alert (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                log_id INTEGER NOT NULL,
                added_ts REAL NOT NULL,
                added_by TEXT NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES incident(id) ON DELETE CASCADE,
                FOREIGN KEY(log_id) REFERENCES log(id) ON DELETE CASCADE,
                UNIQUE(incident_id, log_id)
            )
        """)
        
        # Related incidents (attack chains, correlated events)
        c.execute("""
            CREATE TABLE IF NOT EXISTS incident_link (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id_a INTEGER NOT NULL,
                incident_id_b INTEGER NOT NULL,
                relation_type TEXT NOT NULL DEFAULT 'related',
                notes TEXT,
                created_ts REAL NOT NULL,
                created_by TEXT NOT NULL,
                FOREIGN KEY(incident_id_a) REFERENCES incident(id) ON DELETE CASCADE,
                FOREIGN KEY(incident_id_b) REFERENCES incident(id) ON DELETE CASCADE,
                UNIQUE(incident_id_a, incident_id_b, relation_type)
            )
        """)
        
        # Comments/collaboration thread per incident
        c.execute("""
            CREATE TABLE IF NOT EXISTS incident_comment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                author TEXT NOT NULL,
                body TEXT NOT NULL,
                ts REAL NOT NULL,
                edited_ts REAL,
                edited_by TEXT,
                FOREIGN KEY(incident_id) REFERENCES incident(id) ON DELETE CASCADE
            )
        """)
        
        # Indices for common queries
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_status ON incident(status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_sector ON incident(sector)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_ts ON incident(ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_alert_incident ON incident_alert(incident_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_alert_log ON incident_alert(log_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_link_a ON incident_link(incident_id_a)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_link_b ON incident_link(incident_id_b)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_comment_incident ON incident_comment(incident_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_incident_comment_ts ON incident_comment(ts)")


# ---- INCIDENT CRUD ----

def create_incident(title, description, sector, severity, created_by):
    """Create a new incident/case. Returns the incident ID."""
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO incident (title, description, sector, severity, status, ts, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (title, description, sector, severity, "open", time.time(), created_by),
        )
        return cur.lastrowid


def get_incident(incident_id):
    """Fetch a single incident by ID with all metadata."""
    with _conn() as c:
        row = c.execute("SELECT * FROM incident WHERE id = ?", (incident_id,)).fetchone()
        return dict(row) if row else None


def list_incidents(status=None, sector=None, limit=100, offset=0):
    """List incidents with optional filters. Returns list of dicts."""
    clauses = []
    params = []
    
    if status:
        clauses.append("status = ?")
        params.append(status)
    if sector:
        clauses.append("sector = ?")
        params.append(sector)
    
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    
    with _conn() as c:
        rows = c.execute(
            f"SELECT * FROM incident {where} ORDER BY ts DESC LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def update_incident(incident_id, **kwargs):
    """Update incident fields (title, description, status, severity, 
    root_cause, resolution_summary, closed_ts, closed_by)."""
    allowed_fields = {
        "title", "description", "status", "severity", 
        "root_cause", "resolution_summary", "closed_ts", "closed_by"
    }
    updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
    
    if not updates:
        return False
    
    set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
    with _conn() as c:
        c.execute(
            f"UPDATE incident SET {set_clause} WHERE id = ?",
            (*updates.values(), incident_id),
        )
        return True


def close_incident(incident_id, root_cause, resolution_summary, closed_by):
    """Mark an incident as closed with root cause and resolution."""
    return update_incident(
        incident_id,
        status="closed",
        root_cause=root_cause,
        resolution_summary=resolution_summary,
        closed_ts=time.time(),
        closed_by=closed_by,
    )


def delete_incident(incident_id):
    """Delete an incident (cascades to alerts, links, comments)."""
    with _conn() as c:
        c.execute("DELETE FROM incident WHERE id = ?", (incident_id,))


# ---- INCIDENT ↔ ALERT LINKING ----

def add_alert_to_incident(incident_id, log_id, added_by):
    """Associate a log entry (alert) with an incident."""
    with _conn() as c:
        try:
            c.execute(
                "INSERT INTO incident_alert (incident_id, log_id, added_ts, added_by) "
                "VALUES (?, ?, ?, ?)",
                (incident_id, log_id, time.time(), added_by),
            )
            return True
        except sqlite3.IntegrityError:
            # Already linked
            return False


def remove_alert_from_incident(incident_id, log_id):
    """Unlink an alert from an incident."""
    with _conn() as c:
        c.execute(
            "DELETE FROM incident_alert WHERE incident_id = ? AND log_id = ?",
            (incident_id, log_id),
        )


def get_incident_alerts(incident_id):
    """Fetch all alerts (log entries) for an incident, chronologically."""
    with _conn() as c:
        rows = c.execute(
            """
            SELECT l.id, l.ts, l.time_str, l.sector, l.message, l.severity, l.attack_type,
                   l.status, l.mitre_id, l.mitre_label, l.forest_risk, l.trend_risk,
                   l.metric_scores
            FROM log l
            INNER JOIN incident_alert ia ON l.id = ia.log_id
            WHERE ia.incident_id = ?
            ORDER BY l.ts ASC
            """,
            (incident_id,),
        ).fetchall()
        
        results = []
        for r in rows:
            d = dict(r)
            raw_scores = d.pop("metric_scores", None)
            try:
                d["metric_scores"] = json.loads(raw_scores) if raw_scores else {}
            except (TypeError, ValueError, json.JSONDecodeError):
                d["metric_scores"] = {}
            d["forest_risk"] = float(d.get("forest_risk") or 0.0)
            d["trend_risk"] = float(d.get("trend_risk") or 0.0)
            results.append(d)
        return results


def get_alert_incidents(log_id):
    """Fetch all incidents a log entry (alert) is part of."""
    with _conn() as c:
        rows = c.execute(
            """
            SELECT i.* FROM incident i
            INNER JOIN incident_alert ia ON i.id = ia.incident_id
            WHERE ia.log_id = ?
            ORDER BY i.ts DESC
            """,
            (log_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ---- INCIDENT LINKING (RELATIONSHIPS) ----

def link_incidents(incident_id_a, incident_id_b, relation_type, notes, created_by):
    """Create a link between two incidents (related, chain, etc.).
    
    relation_type can be: 'related', 'chain', 'copied', 'duplicate'.
    Automatically normalizes so lower ID is always 'a' for dedup.
    """
    # Normalize: always store with lower ID as 'a'
    if incident_id_a > incident_id_b:
        incident_id_a, incident_id_b = incident_id_b, incident_id_a
    
    with _conn() as c:
        try:
            c.execute(
                "INSERT INTO incident_link "
                "(incident_id_a, incident_id_b, relation_type, notes, created_ts, created_by) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (incident_id_a, incident_id_b, relation_type, notes, time.time(), created_by),
            )
            return True
        except sqlite3.IntegrityError:
            # Link already exists
            return False


def unlink_incidents(incident_id_a, incident_id_b, relation_type):
    """Remove a link between two incidents."""
    if incident_id_a > incident_id_b:
        incident_id_a, incident_id_b = incident_id_b, incident_id_a
    
    with _conn() as c:
        c.execute(
            "DELETE FROM incident_link "
            "WHERE incident_id_a = ? AND incident_id_b = ? AND relation_type = ?",
            (incident_id_a, incident_id_b, relation_type),
        )


def get_incident_links(incident_id):
    """Fetch all linked incidents (both directions) for a given incident."""
    with _conn() as c:
        # Links where this incident is 'a'
        rows_a = c.execute(
            """
            SELECT il.*, i.title, i.status, i.severity, i.sector
            FROM incident_link il
            INNER JOIN incident i ON il.incident_id_b = i.id
            WHERE il.incident_id_a = ?
            """,
            (incident_id,),
        ).fetchall()
        
        # Links where this incident is 'b'
        rows_b = c.execute(
            """
            SELECT il.*, i.title, i.status, i.severity, i.sector
            FROM incident_link il
            INNER JOIN incident i ON il.incident_id_a = i.id
            WHERE il.incident_id_b = ?
            """,
            (incident_id,),
        ).fetchall()
        
        return {
            "outgoing": [dict(r) for r in rows_a],
            "incoming": [dict(r) for r in rows_b],
        }


# ---- INCIDENT COMMENTS / COLLABORATION ----

def add_comment(incident_id, author, body):
    """Add a comment to an incident."""
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO incident_comment (incident_id, author, body, ts) "
            "VALUES (?, ?, ?, ?)",
            (incident_id, author, body, time.time()),
        )
        return cur.lastrowid


def get_incident_comments(incident_id):
    """Fetch all comments for an incident, chronologically."""
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM incident_comment WHERE incident_id = ? ORDER BY ts ASC",
            (incident_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def update_comment(comment_id, body, edited_by):
    """Edit a comment."""
    with _conn() as c:
        c.execute(
            "UPDATE incident_comment SET body = ?, edited_ts = ?, edited_by = ? WHERE id = ?",
            (body, time.time(), edited_by, comment_id),
        )


def delete_comment(comment_id):
    """Delete a comment."""
    with _conn() as c:
        c.execute("DELETE FROM incident_comment WHERE id = ?", (comment_id,))


# ---- INCIDENT ANALYTICS / TIMELINES ----

def get_incident_timeline(incident_id):
    """Fetch a complete timeline of an incident:
    - All linked alerts (from incident_alert)
    - All incident status changes / metadata updates (audit trail)
    - All comments
    
    Merged and sorted by timestamp for a comprehensive narrative view.
    """
    alerts = get_incident_alerts(incident_id)
    comments = get_incident_comments(incident_id)
    
    timeline_events = []
    
    # Add alerts as events
    for alert in alerts:
        timeline_events.append({
            "type": "alert",
            "ts": alert["ts"],
            "time_str": alert["time_str"],
            "severity": alert["severity"],
            "sector": alert["sector"],
            "message": alert["message"],
            "attack_type": alert.get("attack_type"),
            "mitre_id": alert.get("mitre_id"),
            "log_id": alert["id"],
        })
    
    # Add comments as events
    for comment in comments:
        timeline_events.append({
            "type": "comment",
            "ts": comment["ts"],
            "author": comment["author"],
            "body": comment["body"],
            "edited_ts": comment.get("edited_ts"),
            "edited_by": comment.get("edited_by"),
        })
    
    # Sort by timestamp
    timeline_events.sort(key=lambda x: x["ts"])
    
    return timeline_events


def suggest_incident_links(incident_id):
    """Suggest other incidents to link (based on MITRE technique, sector, time window).
    
    Returns list of incidents sorted by relevance score.
    
    FIX: Properly handle empty or small technique sets without SQL parameter issues.
    """
    current = get_incident(incident_id)
    if not current:
        return []
    
    # Get MITRE techniques from alerts in this incident
    alerts = get_incident_alerts(incident_id)
    techniques = [a.get("mitre_id") for a in alerts if a.get("mitre_id")]
    techniques = list(set(techniques))  # Deduplicate
    
    # Find other open incidents in same sector or with same MITRE technique
    # created in the last 30 days
    cutoff = time.time() - (30 * 24 * 60 * 60)
    
    with _conn() as c:
        # Build query based on whether we have techniques
        if techniques:
            # Use a CASE statement to match on techniques
            technique_placeholders = ",".join("?" * len(techniques))
            query = f"""
                SELECT DISTINCT i.id, i.title, i.sector, i.status, i.ts,
                       COUNT(DISTINCT ia.log_id) as alert_count
                FROM incident i
                LEFT JOIN incident_alert ia ON i.id = ia.incident_id
                WHERE i.id != ? AND i.ts >= ? AND i.status IN ('open', 'investigating')
                  AND (i.sector = ? OR EXISTS (
                    SELECT 1 FROM incident_alert ia2
                    INNER JOIN log l ON ia2.log_id = l.id
                    WHERE ia2.incident_id = i.id AND l.mitre_id IN ({technique_placeholders})
                  ))
                GROUP BY i.id
                ORDER BY i.ts DESC
                LIMIT 10
            """
            params = [incident_id, cutoff, current.get("sector")] + techniques
            rows = c.execute(query, params).fetchall()
        else:
            # No techniques, just match on sector
            query = """
                SELECT DISTINCT i.id, i.title, i.sector, i.status, i.ts,
                       COUNT(DISTINCT ia.log_id) as alert_count
                FROM incident i
                LEFT JOIN incident_alert ia ON i.id = ia.incident_id
                WHERE i.id != ? AND i.ts >= ? AND i.status IN ('open', 'investigating')
                  AND i.sector = ?
                GROUP BY i.id
                ORDER BY i.ts DESC
                LIMIT 10
            """
            rows = c.execute(query, [incident_id, cutoff, current.get("sector")]).fetchall()
        
        return [dict(r) for r in rows]


def incident_stats():
    """Return incident summary statistics."""
    with _conn() as c:
        total = c.execute("SELECT COUNT(*) as cnt FROM incident").fetchone()["cnt"]
        open_incidents = c.execute(
            "SELECT COUNT(*) as cnt FROM incident WHERE status IN ('open', 'investigating')"
        ).fetchone()["cnt"]
        closed = c.execute(
            "SELECT COUNT(*) as cnt FROM incident WHERE status = 'closed'"
        ).fetchone()["cnt"]
        
        # Average time to close
        closed_times = c.execute(
            "SELECT AVG(closed_ts - ts) as avg_time FROM incident WHERE status = 'closed' AND closed_ts IS NOT NULL"
        ).fetchone()
        avg_close_time = int(closed_times["avg_time"]) if closed_times and closed_times["avg_time"] else 0
        
        return {
            "total": total,
            "open": open_incidents,
            "closed": closed,
            "avg_time_to_close_seconds": avg_close_time,
        }