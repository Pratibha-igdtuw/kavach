"""
Session-based auth with a strict role/permission model.

Three roles, each a genuinely different workspace over the same KAVACH data:

  - analyst   (displayed "SOC Analyst")         : Detect -> Investigate -> Respond -> Resolve
  - executive (displayed "Security Manager")    : Assess -> Prioritize -> Decide -> Report
  - admin     (displayed "System Administrator"): Configure -> Maintain -> Govern

The underlying stored role values (analyst / executive / admin) are kept
as-is for database compatibility -- only the *display* name for "executive"
changes (to "Security Manager"). Internally this file is the single source
of truth for what each role can do; every protected route/API/Socket.IO
handler checks permissions from here rather than hand-rolling role
comparisons, so authorization logic lives in exactly one place.

Accounts live in the `users` table (storage.py), passwords are hashed with
werkzeug's scrypt-based hasher. On first boot, three demo accounts are
seeded if the table is empty -- see seed_default_users_if_needed() below.
"""
from functools import wraps

from flask import session, redirect, url_for, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

import storage

# Stored role values -- unchanged for DB/session compatibility.
ROLES = ("analyst", "executive", "admin")

# Human-facing names per the new role philosophy. "executive" now reads as
# "Security Manager" everywhere in the UI even though the stored value and
# demo username stay the same.
ROLE_DISPLAY = {
    "analyst": "SOC Analyst",
    "executive": "Security Manager",
    "admin": "System Administrator",
}

ROLE_TAGLINE = {
    "analyst": "Detect \u2192 Investigate \u2192 Respond \u2192 Resolve",
    "executive": "Assess \u2192 Prioritize \u2192 Decide \u2192 Report",
    "admin": "Configure \u2192 Maintain \u2192 Govern",
}

# Which dashboard a role lands on after login / at "/".
HOME_ENDPOINT = {
    "analyst": "analyst_dashboard",
    "executive": "manager_dashboard",
    "admin": "admin_dashboard",
}

# ---------------------------------------------------------------------------
# Permission model (section 4 of the RBAC spec). Every capability in the app
# maps to exactly one permission string, and each role owns a fixed set.
# Nothing here is inherited automatically between roles -- an admin does NOT
# get analyst/manager permissions just by virtue of being admin, and vice
# versa. If a role needs a capability, it must be listed explicitly below.
# ---------------------------------------------------------------------------
PERMISSIONS = {
    "analyst": {
        "view_live_telemetry",
        "view_alerts",
        "investigate_alerts",
        "acknowledge_alerts",
        "update_alert_status",
        "mark_false_positive",
        "resolve_incidents",
        "contain_sector",
        "view_threat_map",
        "view_risk_analysis",
        "generate_incident_reports",
        "view_audit_logs",
        "trigger_demo_attack",
    },
    "executive": {  # Security Manager
        "view_security_posture",
        "view_risk",
        "view_sector_comparison",
        "view_incident_summary",
        "view_threat_landscape",
        "view_business_impact",
        "view_trends",
        "generate_reports",
        "view_recommendations",
    },
    "admin": {
        "view_system_health",
        "manage_users",
        "manage_roles",
        "reset_passwords",
        "configure_detection_rules",
        "configure_thresholds",
        "configure_sectors",
        "view_system_audit_logs",
        "manage_system_configuration",
        "perform_maintenance",
        "reset_demo_environment",
    },
}


def seed_default_users_if_needed():
    """Called once at startup. Only seeds accounts that don't already exist,
    so it's safe to call on every restart without resetting passwords an
    admin has since changed."""
    storage.seed_default_users([
        ("analyst", generate_password_hash("analyst123"), "analyst", "SOC Analyst"),
        ("exec", generate_password_hash("exec123"), "executive", "Security Manager"),
        ("admin", generate_password_hash("admin123"), "admin", "System Administrator"),
    ])


def check_credentials(username, password):
    user = storage.get_user(username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def current_role():
    return session.get("role")


def current_role_display():
    return ROLE_DISPLAY.get(session.get("role"), session.get("role", "Unknown"))


def current_name():
    return session.get("display_name", "Guest")


def current_username():
    return session.get("username")


def current_home_endpoint():
    return HOME_ENDPOINT.get(session.get("role"), "login")


# ---------------------------------------------------------------------------
# Permission checks
# ---------------------------------------------------------------------------

def has_permission(permission, role=None):
    """True if `role` (default: the current session's role) has `permission`.
    This is the single choke point every authorization check should route
    through -- server-side, not just for hiding UI."""
    role = role or session.get("role")
    return permission in PERMISSIONS.get(role, ())


def has_any_permission(*permissions):
    return any(has_permission(p) for p in permissions)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def _wants_json():
    """Heuristic: API/XHR-ish requests get a JSON 401/403 instead of an HTML
    redirect to /login, so an unauthorized fetch() fails loudly rather than
    silently receiving a login page as its "data"."""
    return (
        request.path.startswith("/api/")
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "role" not in session:
            if _wants_json():
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def permission_required(*permissions, require_all=False):
    """Server-side authorization gate. Usage:

        @auth.permission_required("contain_sector")
        def ...

    By default any ONE of the listed permissions is sufficient; pass
    require_all=True to require every permission listed. Unauthenticated
    requests get redirected to login (or 401 JSON); authenticated-but-
    unauthorized requests get a 403 -- never a silent redirect that could
    look like success, and never a data leak."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "role" not in session:
                if _wants_json():
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("login", next=request.path))
            ok = all(has_permission(p) for p in permissions) if require_all \
                else any(has_permission(p) for p in permissions)
            if not ok:
                return jsonify({"error": "You do not have permission to perform this action."}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def role_required(*roles):
    """Gate a whole page/route to specific stored role values. Prefer
    permission_required for anything that maps to a concrete capability;
    this is for dashboard/landing pages that are simply "this role's
    workspace" rather than a single permission."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "role" not in session:
                if _wants_json():
                    return jsonify({"error": "Authentication required"}), 401
                return redirect(url_for("login", next=request.path))
            if session.get("role") not in roles:
                return jsonify({"error": "You do not have permission to view this page."}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


# Back-compat alias: previously the only "elevated" role was admin, and a
# few call sites still just want "must be logged in as admin".
def admin_required(view):
    return role_required("admin")(view)