"""
Session-based auth with three roles:
  - analyst   : operational control (trigger/contain/mark-FP/reports), no
                executive summary panel
  - executive : read-only dashboard + executive summary + reports, no control actions
  - admin     : superset — everything analyst has (operational controls) PLUS
                the executive summary PLUS user management (add/remove
                accounts, reset passwords, tune detection thresholds)

Accounts live in the `users` table (storage.py), passwords are hashed with
werkzeug's scrypt-based hasher (already a Flask dependency, nothing extra to
install). On first boot, three demo accounts are seeded if the table is
empty — see seed_default_users_if_needed() below.
"""
from functools import wraps

from flask import session, redirect, url_for, request
from werkzeug.security import generate_password_hash, check_password_hash

import storage

ROLES = ("analyst", "executive", "admin")


def seed_default_users_if_needed():
    """Called once at startup. Only seeds accounts that don't already exist,
    so it's safe to call on every restart without resetting passwords an
    admin has since changed."""
    storage.seed_default_users([
        ("analyst", generate_password_hash("analyst123"), "analyst", "SOC Analyst"),
        ("exec", generate_password_hash("exec123"), "executive", "Executive Viewer"),
        ("admin", generate_password_hash("admin123"), "admin", "System Admin"),
    ])


def check_credentials(username, password):
    user = storage.get_user(username)
    if user and check_password_hash(user["password_hash"], password):
        return user
    return None


def current_role():
    return session.get("role")


def current_name():
    return session.get("display_name", "Guest")


def current_username():
    return session.get("username")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "role" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def analyst_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "analyst":
            return {"error": "Analyst role required"}, 403
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "role" not in session:
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            return {"error": "Admin role required"}, 403
        return view(*args, **kwargs)
    return wrapped