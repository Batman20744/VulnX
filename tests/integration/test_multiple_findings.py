
import json

from vulnx.core.database import SessionLocal
from vulnx.models.asset import SoftwareAsset
from vulnx.models.cve_intelligence import CVEIntelligence
from vulnx.models.finding import VulnerabilityFinding
from vulnx.services.scan_service import run_asset_scan


def test_multiple_vulnerabilities_in_one_scan():
    db = SessionLocal()
    asset = None

    test_cve_ids = [
        "CVE-2099-1001",
        "CVE-2099-1002",
    ]

    try:
        asset = SoftwareAsset(
            asset_name="VulnX-Multi-CVE-Test",
            software_name="TestProduct",
            software_version="1.5.0",
            vendor="TestVendor",
            operating_system="Test OS",
            asset_type="software",
            description="Synthetic multi-CVE integration test.",
        )

        db.add(asset)

        for cve_id in test_cve_ids:
            cve = CVEIntelligence(
                cve_id=cve_id,
                description="Synthetic integration-test vulnerability.",
                severity="HIGH",
                cvss_score=8.0,
                cvss_version="3.1",
                references=json.dumps([]),
                configurations=json.dumps([
                    {
                        "operator": "OR",
                        "negate": False,
                        "matches": [
                            {
                                "criteria": (
                                    "cpe:2.3:a:testvendor:"
                                    "testproduct:*:*:*:*:*:*:*:*"
                                ),
                                "vulnerable": True,
                                "version_start_including": "1.0.0",
                                "version_end_excluding": "2.0.0",
                            }
                        ],
                        "children": [],
                    }
                ]),
                source="VulnX-Test-Fixture",
            )

            db.add(cve)

        db.commit()
        db.refresh(asset)

        result = run_asset_scan(asset.id, db)

        assert result["status"] == "completed"
        assert result["total_findings"] == 2
        assert result["severity_counts"]["HIGH"] == 2

        saved_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.scan_id == result["scan_id"],
                VulnerabilityFinding.asset_id == asset.id,
            )
            .all()
        )

        saved_cve_ids = {
            finding.cve_id for finding in saved_findings
        }

        assert saved_cve_ids == set(test_cve_ids)

        print("Multiple vulnerability test passed.")
        print("Scan ID:", result["scan_id"])
        print("Findings saved:", len(saved_findings))

    finally:
        db.rollback()

        if asset is not None and asset.id is not None:
            db.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.asset_id == asset.id
            ).delete(synchronize_session=False)

            db.query(CVEIntelligence).filter(
                CVEIntelligence.cve_id.in_(test_cve_ids)
            ).delete(synchronize_session=False)

            db.query(SoftwareAsset).filter(
                SoftwareAsset.id == asset.id
            ).delete(synchronize_session=False)

            db.commit()

        db.close()
