"""
SQLite persistence for the anomaly log, risk-score history, user accounts,
and the audit trail — so the dashboard survives restarts, renders historical
trend charts, and keeps a durable record of who did what.
"""
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = "kavach.db"


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
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
        c.execute("CREATE INDEX IF NOT EXISTS idx_log_sector ON log(sector)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_history_sector_ts ON risk_history(sector, ts)")

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
        }
        for col, ddl in migrations.items():
            if col not in existing_cols:
                c.execute(ddl)


# ---------------- anomaly log ----------------

def insert_log(entry):
    """Inserts a log/anomaly entry. If entry carries a `status` (i.e. it's a
    genuine anomaly that belongs in the triage queue, as opposed to a
    propagation/manual/system note), that status plus MITRE mapping fields
    are persisted too. Returns the new row's id so callers can reference it
    for later triage state changes."""
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO log (ts, time_str, sector, message, severity, attack_type, "
            "status, mitre_id, mitre_label) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), entry["time"], entry["sector"], entry["message"],
             entry["severity"], entry.get("attack_type"), entry.get("status"),
             entry.get("mitre_id"), entry.get("mitre_label")),
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
            "SELECT id, time_str as time, sector, message, severity, attack_type, "
            "status, mitre_id, mitre_label, ack_by, resolved_by "
            "FROM log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


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