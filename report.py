"""
Auto-generated incident report: summarizes an attack timeline for a sector
from persisted history, in markdown. Meant to be the "so what did we
actually do about it" artifact — turns KAVACH from a monitor into something
that produces a defensible record.
"""
import time

from storage import sector_incident_window

SECTOR_LABEL = {"hospital": "Hospital", "power_grid": "Power Grid", "bank": "Bank"}


def generate_incident_report(sector, contained=False):
    logs, points = sector_incident_window(sector, lookback_seconds=1800)
    label = SECTOR_LABEL.get(sector, sector)
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    peak = max((p["risk_score"] for p in points), default=0)
    anomalies = [l for l in logs if "Anomaly" in l["message"] or "Dependency" in l["message"]]
    attack_types = sorted({l["attack_type"] for l in logs if l.get("attack_type")})
    mitre_techniques = sorted({
        (l["mitre_id"], l["mitre_label"]) for l in logs if l.get("mitre_id")
    })
    triaged = [l for l in logs if l.get("status")]
    unresolved = [l for l in triaged if l.get("status") != "resolved"]

    lines = []
    lines.append(f"# KAVACH Incident Report — {label}")
    lines.append("")
    lines.append(f"**Generated:** {now_str}  ")
    lines.append(f"**Sector:** {label}  ")
    lines.append(f"**Window:** last 30 minutes  ")
    lines.append(f"**Peak risk score:** {peak:.1f} / 100  ")
    lines.append(f"**Containment action taken:** {'Yes' if contained else 'No'}  ")
    if triaged:
        lines.append(f"**Triage status:** {len(triaged) - len(unresolved)}/{len(triaged)} alert(s) resolved  ")
    lines.append("")

    if mitre_techniques:
        lines.append("## MITRE ATT&CK Mapping")
        for technique_id, technique_name in mitre_techniques:
            lines.append(f"- **{technique_id}** — {technique_name}")
        lines.append("")

    lines.append("## Summary")
    if not logs:
        lines.append("No anomalies or propagation events recorded for this sector in the observed window.")
    else:
        atype_str = ", ".join(attack_types) if attack_types else "unclassified"
        lines.append(
            f"{len(anomalies)} alert(s) recorded. "
            f"Suspected attack pattern(s): **{atype_str}**. "
            f"Peak risk reached {peak:.1f}/100."
        )
    lines.append("")

    lines.append("## Timeline")
    if not logs:
        lines.append("_No events in window._")
    else:
        for entry in logs:
            sev = entry["severity"].upper()
            atype = f" · type: {entry['attack_type']}" if entry.get("attack_type") else ""
            mitre = f" · MITRE {entry['mitre_id']}" if entry.get("mitre_id") else ""
            status = f" · status: {entry['status']}" if entry.get("status") else ""
            lines.append(f"- `{entry['time']}` **[{sev}]** {entry['message']}{atype}{mitre}{status}")
    lines.append("")

    lines.append("## Recommended Next Steps")
    if peak >= 75:
        lines.append("- Sector reached critical risk. Verify containment held and rotate any exposed credentials.")
        lines.append("- Review dependent sectors for lingering propagation risk.")
        lines.append("- Preserve logs for post-incident forensics.")
    elif peak >= 45:
        lines.append("- Sector reached elevated risk but did not cross critical threshold.")
        lines.append("- Confirm whether the trigger was legitimate load or a probing attempt.")
    else:
        lines.append("- No significant risk elevation observed. No action required.")
    lines.append("")
    lines.append("---")
    lines.append("_Generated automatically by KAVACH — Sentinel Eye. This report reflects simulated telemetry from a prototype and is not derived from production security systems._")

    return "\n".join(lines)