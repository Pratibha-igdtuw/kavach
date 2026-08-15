"""
Fires an outbound webhook (Slack or Discord) when a critical anomaly is
detected, so a SOC channel gets pinged in real time instead of someone
having to stare at the dashboard.

Configured entirely via environment variables so nothing here needs a code
change to turn on for a demo:

    KAVACH_WEBHOOK_URL   - the Slack incoming-webhook or Discord webhook URL
    KAVACH_WEBHOOK_KIND  - "slack" (default) or "discord" — controls payload shape

If KAVACH_WEBHOOK_URL isn't set, every call below is a silent no-op, so the
app runs exactly as before with zero config.

Sends happen on a background thread so a slow/failed webhook call never
blocks the 2-second telemetry loop.
"""
import os
import threading

import requests

WEBHOOK_URL = os.environ.get("KAVACH_WEBHOOK_URL", "")
WEBHOOK_KIND = os.environ.get("KAVACH_WEBHOOK_KIND", "slack").lower()

SEVERITY_EMOJI = {"high": "🔴", "medium": "🟠", "low": "🟡"}


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
    No-op if KAVACH_WEBHOOK_URL isn't configured."""
    if not WEBHOOK_URL:
        return
    if entry.get("severity") != "high":
        return
    threading.Thread(target=_send, args=(entry,), daemon=True).start()