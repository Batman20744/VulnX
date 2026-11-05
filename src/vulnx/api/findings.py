
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vulnx.core.database import get_db
from vulnx.models.finding import VulnerabilityFinding

from vulnx.services.risk_scoring import (
    calculate_risk_score,
    classify_risk,
)


router = APIRouter(
    prefix="/findings",
    tags=["Vulnerability Findings"],
)


def serialize_finding(finding):
    """Serialize a finding with its calculated risk information."""

    risk_score = calculate_risk_score(
        cvss_score=finding.cvss_score,
        epss_score=finding.epss_score,
        is_kev=finding.is_kev,
    )

    return {
        "id": finding.id,
        "asset_id": finding.asset_id,
        "scan_id": finding.scan_id,
        "cve_id": finding.cve_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "cvss_score": finding.cvss_score,
        "epss_score": finding.epss_score,
        "is_kev": finding.is_kev,
        "risk_score": risk_score,
        "risk_priority": classify_risk(risk_score),
        "remediation": finding.remediation,
        "status": finding.status,
        "detected_at": finding.detected_at,
    }


def get_risk_sorted_findings(findings):
    """Sort findings by risk score, highest first."""

    return sorted(
        findings,
        key=lambda finding: (
            calculate_risk_score(
                finding.cvss_score,
                finding.epss_score,
                finding.is_kev,
            ),
            finding.id,
        ),
        reverse=True,
    )


# GET all findings, ordered by risk
@router.get("/")
def list_findings(
    db: Session = Depends(get_db),
):
    findings = (
        db.query(VulnerabilityFinding)
        .all()
    )

    sorted_findings = get_risk_sorted_findings(findings)

    return [
        serialize_finding(finding)
        for finding in sorted_findings
    ]


# GET findings belonging to a scan
@router.get("/scan/{scan_id}")
def get_findings_by_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    findings = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.scan_id == scan_id
        )
        .all()
    )

    sorted_findings = get_risk_sorted_findings(findings)

    return [
        serialize_finding(finding)
        for finding in sorted_findings
    ]


# GET findings belonging to an asset
@router.get("/asset/{asset_id}")
def get_findings_by_asset(
    asset_id: int,
    db: Session = Depends(get_db),
):
    findings = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.asset_id == asset_id
        )
        .all()
    )

    sorted_findings = get_risk_sorted_findings(findings)

    return [
        serialize_finding(finding)
        for finding in sorted_findings
    ]


# GET overall risk summary
@router.get("/risk-summary")
def get_risk_summary(
    db: Session = Depends(get_db),
):
    """Return overall vulnerability risk statistics."""

    findings = (
        db.query(VulnerabilityFinding)
        .all()
    )

    summary = {
        "total_findings": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "kev_findings": 0,
        "average_risk_score": 0,
    }

    total_score = 0

    for finding in findings:
        score = calculate_risk_score(
            finding.cvss_score,
            finding.epss_score,
            finding.is_kev,
        )

        priority = classify_risk(score).lower()

        summary[priority] += 1
        total_score += score

        if finding.is_kev:
            summary["kev_findings"] += 1

    if findings:
        summary["average_risk_score"] = round(
            total_score / len(findings),
            2,
        )

    return summary


# GET one vulnerability finding
@router.get("/{finding_id}")
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db),
):
    finding = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.id == finding_id
        )
        .first()
    )

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability finding not found.",
        )

    return serialize_finding(finding)
