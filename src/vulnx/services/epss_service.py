
from sqlalchemy.orm import Session

from vulnx.models.finding import VulnerabilityFinding
from vulnx.intelligence.epss_client import fetch_epss_scores


def refresh_finding_epss(db: Session) -> dict:
    """
    Retrieve EPSS scores and update existing findings.

    Existing scores are preserved if the API does not
    return a score for a particular CVE.
    """

    findings = (
        db.query(VulnerabilityFinding)
        .all()
    )

    if not findings:
        return {
            "total_findings": 0,
            "cves_requested": 0,
            "findings_updated": 0,
            "scores_received": 0,
        }

    cve_ids = sorted({
        finding.cve_id
        for finding in findings
    })

    scores = fetch_epss_scores(cve_ids)

    updated_count = 0

    try:
        for finding in findings:
            score = scores.get(finding.cve_id.upper())

            if score is not None:
                finding.epss_score = score
                updated_count += 1

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "total_findings": len(findings),
        "cves_requested": len(cve_ids),
        "findings_updated": updated_count,
        "scores_received": len(scores),
    }
