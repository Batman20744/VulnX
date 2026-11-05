
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from vulnx.models.asset import SoftwareAsset
from vulnx.models.scan import ScanRecord
from vulnx.models.finding import VulnerabilityFinding
from vulnx.models.cve_intelligence import CVEIntelligence

from vulnx.services.asset_vulnerability_scanner import (
    scan_asset_for_cves,
)


def run_asset_scan(
    asset_id: int,
    db: Session,
) -> dict:

    asset = (
        db.query(SoftwareAsset)
        .filter(SoftwareAsset.id == asset_id)
        .first()
    )

    if asset is None:
        raise ValueError(f"Asset {asset_id} not found.")

    scan = ScanRecord(
        scan_name=f"VulnX Asset Scan - {asset.asset_name}",
        scan_type="software_vulnerability",
        target=asset.asset_name,
        status="running",
        total_assets=1,
        total_findings=0,
    )

    db.add(scan)
    db.flush()

    try:
        results = scan_asset_for_cves(asset_id, db)

        confirmed_findings = []

        for result in results:

            if result["status"] != "affected":
                continue

            cve_record = (
                db.query(CVEIntelligence)
                .filter(
                    CVEIntelligence.cve_id == result["cve_id"]
                )
                .first()
            )

            if cve_record is None:
                continue

            finding = VulnerabilityFinding(
                asset_id=asset.id,
                scan_id=scan.id,
                cve_id=cve_record.cve_id,
                title=cve_record.cve_id,
                description=cve_record.description,
                severity=cve_record.severity,
                cvss_score=cve_record.cvss_score,
                status="open",
                remediation=(
                    "Review the vendor security advisory "
                    "and upgrade to a verified fixed version."
                ),
            )

            db.add(finding)

            confirmed_findings.append(result)

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }

        for result in confirmed_findings:
            severity = (result["severity"] or "UNKNOWN").upper()

            if severity not in severity_counts:
                severity = "UNKNOWN"

            severity_counts[severity] += 1

        scan.total_findings = len(confirmed_findings)
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = json.dumps({
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "total_cves_checked": len(results),
            "confirmed_findings": len(confirmed_findings),
            "severity_counts": severity_counts,
        })

        db.commit()
        db.refresh(scan)

        return {
            "scan_id": scan.id,
            "asset_id": asset.id,
            "asset_name": asset.asset_name,
            "status": scan.status,
            "total_cves_checked": len(results),
            "total_findings": scan.total_findings,
            "severity_counts": severity_counts,
        }

    except Exception:
        db.rollback()
        raise
