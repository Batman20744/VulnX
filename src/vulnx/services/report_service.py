import csv
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from sqlalchemy.orm import Session

from vulnx.models.finding import VulnerabilityFinding
from vulnx.models.scan import ScanRecord
from vulnx.models.asset import SoftwareAsset
from vulnx.services.risk_scoring import (
    calculate_risk_score,
    classify_risk,
)


def _is_synthetic(finding):
    description = (finding.description or "").lower()
    return (
        "synthetic" in description
        or "test-fixture" in description
    )


def _collect_report_data(db: Session):
    findings = (
        db.query(VulnerabilityFinding)
        .order_by(VulnerabilityFinding.id.desc())
        .all()
    )

    scans = (
        db.query(ScanRecord)
        .order_by(ScanRecord.id.desc())
        .all()
    )

    assets = db.query(SoftwareAsset).all()

    verified = [f for f in findings if not _is_synthetic(f)]
    demo = [f for f in findings if _is_synthetic(f)]

    severity = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for finding in verified:
        level = (finding.severity or "UNKNOWN").upper()
        if level not in severity:
            level = "UNKNOWN"
        severity[level] += 1

    scored = [
        calculate_risk_score(
            f.cvss_score,
            f.epss_score,
            f.is_kev,
        )
        for f in verified
    ]

    average_risk = round(sum(scored) / len(scored), 2) if scored else 0

    return {
        "findings": findings,
        "verified": verified,
        "demo": demo,
        "scans": scans,
        "assets": assets,
        "severity": severity,
        "average_risk": average_risk,
        "kev_count": sum(1 for f in verified if f.is_kev is True),
    }


def generate_vulnerability_csv(db: Session) -> bytes:
    """Generate a CSV export of vulnerability findings."""

    data = _collect_report_data(db)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Finding ID",
        "CVE ID",
        "Title",
        "Severity",
        "CVSS Score",
        "EPSS Score",
        "KEV Status",
        "Risk Score",
        "Risk Priority",
        "Asset ID",
        "Scan ID",
        "Status",
        "Remediation",
        "Detected At",
        "Data Type",
    ])

    for finding in data["findings"]:
        synthetic = _is_synthetic(finding)

        score = calculate_risk_score(
            finding.cvss_score,
            finding.epss_score,
            finding.is_kev,
        )

        writer.writerow([
            finding.id,
            finding.cve_id,
            finding.title,
            finding.severity,
            finding.cvss_score,
            finding.epss_score,
            "DEMO VALUE" if synthetic else (
                "YES" if finding.is_kev is True else
                "NO" if finding.is_kev is False else "UNKNOWN"
            ),
            score,
            classify_risk(score),
            finding.asset_id,
            finding.scan_id,
            finding.status,
            finding.remediation,
            finding.detected_at,
            "SYNTHETIC" if synthetic else "VERIFIED",
        ])

    return output.getvalue().encode("utf-8-sig")


def generate_security_pdf(db: Session) -> bytes:
    """Generate an executive vulnerability assessment PDF."""

    data = _collect_report_data(db)

    buffer = io.BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "VulnXTitle",
        parent=styles["Title"],
        textColor=colors.HexColor("#2A9D8F"),
        alignment=TA_CENTER,
        fontSize=24,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "VulnXSubtitle",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#64746D"),
        fontSize=9,
    )

    heading_style = ParagraphStyle(
        "VulnXHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#167C70"),
        spaceBefore=14,
        spaceAfter=8,
    )

    story = []

    story.append(Paragraph("VulnX", title_style))
    story.append(
        Paragraph(
            "SECURITY VULNERABILITY ASSESSMENT REPORT",
            subtitle_style,
        )
    )
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["Normal"],
    ))

    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Executive Summary", heading_style))

    summary_data = [
        ["Metric", "Result"],
        ["Total Findings", str(len(data["findings"]))],
        ["Verified Findings", str(len(data["verified"]))],
        ["Synthetic Test Findings", str(len(data["demo"]))],
        ["Registered Assets", str(len(data["assets"]))],
        ["Total Scans", str(len(data["scans"]))],
        ["Verified KEV Findings", str(data["kev_count"])],
        ["Average Verified Risk Score", str(data["average_risk"])],
    ]

    summary_table = Table(summary_data, colWidths=[85 * mm, 75 * mm])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173D36")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F0F5F3")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#172723")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD8D2")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(summary_table)

    story.append(Paragraph("Severity Distribution", heading_style))

    severity_data = [["Severity", "Verified Findings"]]

    for level, count in data["severity"].items():
        severity_data.append([level, str(count)])

    severity_table = Table(
        severity_data,
        colWidths=[85 * mm, 75 * mm],
    )

    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173D36")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD8D2")),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))

    story.append(severity_table)

    story.append(Paragraph("Vulnerability Details", heading_style))

    finding_rows = [[
        "CVE",
        "Severity",
        "CVSS",
        "Risk",
        "Status",
    ]]

    for finding in data["verified"]:
        score = calculate_risk_score(
            finding.cvss_score,
            finding.epss_score,
            finding.is_kev,
        )

        finding_rows.append([
            finding.cve_id or "N/A",
            finding.severity or "UNKNOWN",
            str(finding.cvss_score if finding.cvss_score is not None else "N/A"),
            str(score),
            finding.status or "UNKNOWN",
        ])

    if not data["verified"]:
        finding_rows.append([
            "No verified findings",
            "-",
            "-",
            "-",
            "-",
        ])

    finding_table = Table(
        finding_rows,
        repeatRows=1,
        colWidths=[42 * mm, 30 * mm, 22 * mm, 22 * mm, 35 * mm],
    )

    finding_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173D36")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD8D2")),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    story.append(finding_table)

    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph(
        "Data Integrity Notice",
        heading_style,
    ))

    story.append(Paragraph(
        "Synthetic demonstration findings are excluded from verified "
        "severity and KEV statistics. Their values are not evidence of "
        "real-world vulnerability intelligence. Risk scores are "
        "prioritization estimates based on available stored data.",
        styles["BodyText"],
    ))

    document.build(story)

    return buffer.getvalue()