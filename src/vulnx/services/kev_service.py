
from sqlalchemy.orm import Session

from vulnx.models.finding import VulnerabilityFinding
from vulnx.intelligence.kev_client import fetch_kev_catalog


def refresh_finding_kev(db: Session) -> dict:
    """
    Refresh CISA KEV status for existing findings.
    """

    findings = (
        db.query(VulnerabilityFinding)
        .all()
    )

    if not findings:
        return {
            "total_findings": 0,
            "kev_findings": 0,
            "updated_findings": 0,
        }

    # Fetch catalog before changing database records.
    kev_ids = fetch_kev_catalog()

    updated_count = 0
    kev_count = 0

    try:
        for finding in findings:
            is_listed = finding.cve_id.upper() in kev_ids

            if finding.is_kev != is_listed:
                finding.is_kev = is_listed
                updated_count += 1

            if is_listed:
                kev_count += 1

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "total_findings": len(findings),
        "kev_findings": kev_count,
        "updated_findings": updated_count,
    }
