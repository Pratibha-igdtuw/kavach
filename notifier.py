"""
Fires an outbound webhook (Slack or Discord) when a critical anomaly is
detected, so a SOC channel gets pinged in real time instead of someone
having to stare at the dashboard.

Config resolution order (checked once at import, then overridable at
runtime from the admin panel):

    1. DB row in notifier_config (set via Admin → Notification Config UI —
       this is the only way an admin can change it without touching env
       vars or restarting the process).
    2. Env vars, as a zero-config fallback for anyone who doesn't use the
       admin UI:
         KAVACH_WEBHOOK_URL   - the Slack incoming-webhook or Discord webhook URL
         KAVACH_WEBHOOK_KIND  - "slack" (default) or "discord" — controls payload shape

If no URL is configured either way, every call below is a silent no-op, so
the app runs exactly as before with zero config.

Sends triggered by real detections happen on a background thread so a
slow/failed webhook call never blocks the 2-second telemetry loop. The
admin "send test alert" action posts synchronously instead, since the
panel needs to report success/failure back to the person who clicked it.
"""
import os
import threading

import requests

import storage

SEVERITY_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡"}


def _load_initial_config():
    """DB config (admin-set) wins if present; otherwise fall back to env
    vars. Wrapped in try/except so a fresh DB without the table yet (e.g.
    mid-migration) can't crash import."""
    try:
        row = storage.get_notifier_config()
    except Exception:
        row = None
    if row and row.get("webhook_url"):
        return row["webhook_url"], (row.get("webhook_kind") or "slack").lower()
    return (
        os.environ.get("KAVACH_WEBHOOK_URL", ""),
        os.environ.get("KAVACH_WEBHOOK_KIND", "slack").lower(),
    )


WEBHOOK_URL, WEBHOOK_KIND = _load_initial_config()


def _build_payload(entry):
    emoji = SEVERITY_EMOJI.get(entry.get("severity"), "⚪")
    sector_label = (entry.get("sector") or "unknown").replace("_", " ").title()
    text = (
        f"{emoji} *KAVACH ALERT* — {sector_label}\n"
        f"{entry.get('message', '')}\n"
        f"Severity: {entry.get('severity', 'n/a').upper()}"
    )
    if entry.get("mitre_id"):
        text += f" · MITRE {entry['mitre_id']} ({entry.get('mitre_label', '')})"

    if WEBHOOK_KIND == "discord":
        return {"content": text}
    return {"text": text}  # Slack incoming-webhook format


def _send(entry):
    try:
        requests.post(WEBHOOK_URL, json=_build_payload(entry), timeout=5)
    except requests.RequestException as exc:
        # Never let a network hiccup take down the detection loop — just
        # print so it shows up in server logs during a demo/debug session.
        print(f"[notifier] webhook send failed: {exc}")


def notify_critical(entry):
    """Fire-and-forget a webhook alert for a high-severity log entry.
    No-op if no webhook is configured (DB or env)."""
    if not WEBHOOK_URL:
        return
    if entry.get("severity") != "high":
        return
    threading.Thread(target=_send, args=(entry,), daemon=True).start()


def is_configured():
    return bool(WEBHOOK_URL)


def current_config():
    """For the admin System Health panel / Notification Config form."""
    return {"webhook_url": WEBHOOK_URL, "webhook_kind": WEBHOOK_KIND, "configured": is_configured()}


def set_webhook_config(webhook_url, webhook_kind, actor):
    """Admin-only: persist to the DB and swap the in-memory config so it
    takes effect immediately, no restart needed."""
    global WEBHOOK_URL, WEBHOOK_KIND
    webhook_url = (webhook_url or "").strip()
    webhook_kind = (webhook_kind or "slack").strip().lower()
    if webhook_kind not in ("slack", "discord"):
        webhook_kind = "slack"
    storage.set_notifier_config(webhook_url, webhook_kind, actor)
    WEBHOOK_URL, WEBHOOK_KIND = webhook_url, webhook_kind


def send_test_alert():
    """Admin-only: synchronously POST a clearly-labeled test alert (reusing
    the same payload builder/format as real critical alerts) so the panel
    can report success/failure back right away instead of firing blind.
    Returns (ok: bool, message: str)."""
    if not WEBHOOK_URL:
        return False, "No webhook URL configured."
    test_entry = {
        "sector": "system",
        "message": "This is a test alert from the KAVACH Admin panel — webhook config is working.",
        "severity": "high",
        "mitre_id": None,
    }
    try:
        resp = requests.post(WEBHOOK_URL, json=_build_payload(test_entry), timeout=6)
        if 200 <= resp.status_code < 300:
            return True, f"Test alert sent ({resp.status_code})."
        return False, f"Webhook responded with status {resp.status_code}."
    except requests.RequestException as exc:
        return False, f"Send failed: {exc}"