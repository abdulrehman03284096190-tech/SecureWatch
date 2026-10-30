"""PDF reporting from persisted SecureWatch observations."""
from __future__ import annotations

from datetime import datetime
from html import escape
import json
from pathlib import Path
from typing import Any
import unicodedata

from database.db_manager import DatabaseManager


def _pdf_text(value: object) -> str:
    text = "".join(
        character for character in str(value)
        if character in "\t\n" or unicodedata.category(character)[0] != "C"
    )
    return escape(text.encode("cp1252", "replace").decode("cp1252"))


def generate_pdf_report(
    path: str | Path,
    database: DatabaseManager,
    *,
    computer: str = "Unavailable",
    operating_system: str = "Unavailable",
    monitoring_status: str = "Unavailable",
    defender_status: str = "Not queried in this session",
    period: str = "All retained local records",
) -> Path:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError("PDF reports require ReportLab. Install project requirements.") from exc

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    alerts = database.alerts(limit=500)
    scans = database.file_scans(limit=500)
    with database.connect() as connection:
        findings = connection.execute(
            "SELECT timestamp,rule_id,severity,title,evidence,source "
            "FROM event_findings ORDER BY id DESC LIMIT 500"
        ).fetchall()
        notes = connection.execute(
            """SELECT n.timestamp,n.alert_id,n.note FROM investigation_notes n
               ORDER BY n.id DESC LIMIT 500"""
        ).fetchall()
        defender_detections = connection.execute(
            """SELECT timestamp,threat_id,threat_name,action_success,
                      process_name,resources
               FROM defender_detections ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        actions = connection.execute(
            """SELECT timestamp,action,result FROM actions ORDER BY id DESC LIMIT 100"""
        ).fetchall()
        events = connection.execute(
            """SELECT timestamp,log_name,event_id,record_id,level,provider,message
               FROM windows_events ORDER BY id DESC LIMIT 200"""
        ).fetchall()
        latest_run = connection.execute(
            "SELECT timestamp,summary FROM monitoring_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
    generated = datetime.now().astimezone().isoformat(timespec="seconds")
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "SecureWatchBody", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.5, leading=9, alignment=TA_LEFT, wordWrap="CJK",
    )
    story: list[Any] = [
        Paragraph("SecureWatch Security Report", styles["Title"]),
        Paragraph(f"Generated: {_pdf_text(generated)}", styles["Normal"]),
        Paragraph(f"Computer: {_pdf_text(computer)}", styles["Normal"]),
        Paragraph(f"Operating system: {_pdf_text(operating_system)}", styles["Normal"]),
        Paragraph(f"Reporting period: {_pdf_text(period)}", styles["Normal"]),
        Paragraph(f"Monitoring status: {_pdf_text(monitoring_status)}", styles["Normal"]),
        Paragraph(f"Microsoft Defender status: {_pdf_text(defender_status)}", styles["Normal"]),
        Spacer(1, 5 * mm),
        Paragraph("Scope and limitations", styles["Heading2"]),
        Paragraph(
            "This report contains locally stored observations and rule-based findings. "
            "A finding is not proof of compromise, and absence of a finding is not proof "
            "that a device is secure. Defender and Windows event data depend on "
            "platform availability, permissions, audit configuration, and retention.",
            body,
        ),
    ]

    def add_table(title: str, headers: list[str], rows: list[list[object]]) -> None:
        story.append(Paragraph(escape(title), styles["Heading2"]))
        cells = [[Paragraph(_pdf_text(value), body) for value in headers]]
        cells.extend([
            [Paragraph(_pdf_text(value), body) for value in row]
            for row in rows
        ])
        table = LongTable(
            cells, repeatRows=1, colWidths=[(A4[0] - 40 * mm) / len(headers)] * len(headers),
            hAlign="LEFT",
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e78")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#eef3f8")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.extend((table, Spacer(1, 4 * mm)))

    severity_counts: dict[str, int] = {}
    for alert in alerts:
        severity_counts[alert["severity"]] = severity_counts.get(alert["severity"], 0) + 1
    add_table(
        "Alert severity summary", ["Severity", "Count"],
        [[severity, count] for severity, count in sorted(severity_counts.items())]
        or [["No persisted alerts", 0]],
    )
    metric_rows: list[list[object]] = []
    if latest_run:
        try:
            metrics = json.loads(latest_run["summary"])
            metric_rows = [
                ["Computer", metrics.get("computer", "Unavailable")],
                ["Operating system", metrics.get("os", "Unavailable")],
                ["CPU percent", metrics.get("cpu_percent", "Unavailable")],
                ["Memory percent", metrics.get("memory_percent", "Unavailable")],
                ["Disk percent", metrics.get("disk_percent", "Unavailable")],
                ["Process count", metrics.get("process_count", "Unavailable")],
                ["Sampled at", metrics.get("sampled_at", latest_run["timestamp"])],
            ]
        except (TypeError, json.JSONDecodeError):
            metric_rows = [["Metrics", "Latest monitoring record could not be parsed"]]
    add_table(
        "Latest monitoring metrics", ["Metric", "Observed value"],
        metric_rows or [["Metrics", "No persisted monitoring cycle"]],
    )
    add_table(
        "Security alerts", ["Time", "Severity", "Rule", "Status", "Title", "Evidence"],
        [[row["timestamp"], row["severity"], row["rule_id"], row["status"],
          row["title"], row["details"]] for row in alerts]
        or [["", "", "", "", "No persisted alerts", ""]],
    )
    add_table(
        "File analysis", ["Time", "Result", "Path", "Size", "SHA-256"],
        [[row["timestamp"], row["result"], row["path"], row["size"], row["sha256"]]
         for row in scans]
        or [["", "", "No file analysis records", "", ""]],
    )
    add_table(
        "Detection findings", ["Time", "Rule", "Severity", "Title", "Evidence", "Source"],
        [[row["timestamp"], row["rule_id"], row["severity"], row["title"],
          row["evidence"], row["source"]] for row in findings]
        or [["", "", "", "No persisted rule findings", "", ""]],
    )
    add_table(
        "Recent Windows events",
        ["Time", "Log", "Event ID", "Record ID", "Level", "Provider", "Message"],
        [[row["timestamp"], row["log_name"], row["event_id"], row["record_id"],
          row["level"], row["provider"], row["message"]] for row in events]
        or [["", "", "", "", "", "", "No persisted Windows events"]],
    )
    add_table(
        "Microsoft Defender detection history",
        ["Time", "Threat", "Threat ID", "Action success", "Process", "Resources"],
        [[row["timestamp"], row["threat_name"], row["threat_id"],
          row["action_success"], row["process_name"], row["resources"]]
         for row in defender_detections]
        or [["", "No retained Defender detections", "", "", "", ""]],
    )
    add_table(
        "Security-relevant application actions",
        ["Time", "Action", "Result"],
        [[row["timestamp"], row["action"], row["result"]] for row in actions]
        or [["", "No retained application actions", ""]],
    )
    add_table(
        "Investigation notes", ["Time", "Alert ID", "Note"],
        [[row["timestamp"], row["alert_id"], row["note"]] for row in notes]
        or [["", "", "No investigation notes"]],
    )
    document = SimpleDocTemplate(
        str(target), pagesize=A4, rightMargin=20 * mm, leftMargin=20 * mm,
        topMargin=22 * mm, bottomMargin=20 * mm, title="SecureWatch Security Report",
    )

    def page_chrome(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(20 * mm, A4[1] - 12 * mm, "SecureWatch Security Report")
        canvas.setStrokeColor(colors.lightgrey)
        canvas.line(20 * mm, A4[1] - 15 * mm, A4[0] - 20 * mm, A4[1] - 15 * mm)
        canvas.drawString(20 * mm, 12 * mm, "SecureWatch — local defensive monitoring")
        canvas.drawRightString(A4[0] - 20 * mm, 12 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(story, onFirstPage=page_chrome, onLaterPages=page_chrome)
    return target
