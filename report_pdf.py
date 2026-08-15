"""
PDF version of the incident report — same underlying data as report.py's
Markdown report (storage.sector_incident_window), rendered with reportlab
so analysts/executives can download something that opens cleanly outside
a Markdown viewer and is easy to attach to a compliance email.

reportlab is pure-Python (no system libraries like wkhtmltopdf/WeasyPrint
need), so this stays a one-line pip install.
"""
import io
import time

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, ListFlowable, ListItem,
)

from storage import sector_incident_window

SECTOR_LABEL = {"hospital": "Hospital", "power_grid": "Power Grid", "bank": "Bank"}

_SEVERITY_HEX = {
    "HIGH": "#c0392b",
    "MEDIUM": "#d68910",
    "LOW": "#2874a6",
}


def generate_incident_report_pdf(sector, contained=False):
    """Returns raw PDF bytes for the given sector's incident report."""
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

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("KavachTitle", parent=styles["Title"], textColor=colors.HexColor("#1b2a41"))
    h2 = ParagraphStyle("KavachH2", parent=styles["Heading2"], textColor=colors.HexColor("#1b2a41"),
                         spaceBefore=14, spaceAfter=6)
    body = styles["BodyText"]
    meta = ParagraphStyle("Meta", parent=body, textColor=colors.HexColor("#555555"), fontSize=9)

    story = [
        Paragraph(f"KAVACH Incident Report — {label}", title_style),
        Spacer(1, 6),
        Paragraph(f"Generated: {now_str}", meta),
        Spacer(1, 10),
    ]

    # ---- meta table ----
    meta_rows = [
        ["Sector", label],
        ["Window", "Last 30 minutes"],
        ["Peak risk score", f"{peak:.1f} / 100"],
        ["Containment action taken", "Yes" if contained else "No"],
    ]
    if triaged:
        meta_rows.append(["Triage status", f"{len(triaged) - len(unresolved)}/{len(triaged)} alert(s) resolved"])
    meta_table = Table(meta_rows, colWidths=[2.2 * inch, 3.8 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1b2a41")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ]))
    story.append(meta_table)

    # ---- MITRE mapping ----
    if mitre_techniques:
        story.append(Paragraph("MITRE ATT&CK Mapping", h2))
        items = [ListItem(Paragraph(f"<b>{tid}</b> — {tname}", body)) for tid, tname in mitre_techniques]
        story.append(ListFlowable(items, bulletType="bullet", leftIndent=14))

    # ---- summary ----
    story.append(Paragraph("Summary", h2))
    if not logs:
        story.append(Paragraph(
            "No anomalies or propagation events recorded for this sector in the observed window.", body))
    else:
        atype_str = ", ".join(attack_types) if attack_types else "unclassified"
        story.append(Paragraph(
            f"{len(anomalies)} alert(s) recorded. Suspected attack pattern(s): "
            f"<b>{atype_str}</b>. Peak risk reached {peak:.1f}/100.", body))

    # ---- timeline ----
    story.append(Paragraph("Timeline", h2))
    if not logs:
        story.append(Paragraph("No events in window.", body))
    else:
        for entry in logs:
            sev = entry["severity"].upper()
            atype = f" · type: {entry['attack_type']}" if entry.get("attack_type") else ""
            mitre = f" · MITRE {entry['mitre_id']}" if entry.get("mitre_id") else ""
            status = f" · status: {entry['status']}" if entry.get("status") else ""
            sev_hex = _SEVERITY_HEX.get(sev, "#000000")
            line = (
                f"<font color='#555555'>{entry['time']}</font> "
                f"<font color='{sev_hex}'><b>[{sev}]</b></font> "
                f"{entry['message']}{atype}{mitre}{status}"
            )
            story.append(Paragraph(line, ParagraphStyle("TL", parent=body, fontSize=9, spaceAfter=4)))

    # ---- recommended next steps ----
    story.append(Paragraph("Recommended Next Steps", h2))
    if peak >= 75:
        steps = [
            "Sector reached critical risk. Verify containment held and rotate any exposed credentials.",
            "Review dependent sectors for lingering propagation risk.",
            "Preserve logs for post-incident forensics.",
        ]
    elif peak >= 45:
        steps = [
            "Sector reached elevated risk but did not cross critical threshold.",
            "Confirm whether the trigger was legitimate load or a probing attempt.",
        ]
    else:
        steps = ["No significant risk elevation observed. No action required."]
    story.append(ListFlowable([ListItem(Paragraph(s, body)) for s in steps], bulletType="bullet", leftIndent=14))

    story.append(Spacer(1, 18))
    story.append(Paragraph(
        "Generated automatically by KAVACH — Sentinel Eye. This report reflects simulated "
        "telemetry from a prototype and is not derived from production security systems.",
        ParagraphStyle("Footer", parent=body, fontSize=7.5, textColor=colors.HexColor("#888888")),
    ))

    doc.build(story)
    return buf.getvalue()