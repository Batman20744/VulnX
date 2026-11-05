
import json

from vulnx.core.database import SessionLocal
from vulnx.models.asset import SoftwareAsset
from vulnx.models.cve_intelligence import CVEIntelligence
from vulnx.models.finding import VulnerabilityFinding
from vulnx.models.scan import ScanRecord
from vulnx.services.scan_service import run_asset_scan


def test_repeated_scans_create_separate_findings():
    db = SessionLocal()

    asset = None
    test_cve_id = "CVE-2099-1003"

    try:
        asset = SoftwareAsset(
            asset_name="VulnX-Repeated-Scan-Test",
            software_name="RepeatProduct",
            software_version="1.5.0",
            vendor="RepeatVendor",
            operating_system="Test OS",
            asset_type="software",
            description="Synthetic repeated-scan test.",
        )

        cve = CVEIntelligence(
            cve_id=test_cve_id,
            description="Synthetic repeated-scan vulnerability.",
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
                                "cpe:2.3:a:repeatvendor:"
                                "repeatproduct:*:*:*:*:*:*:*:*"
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

        db.add_all([asset, cve])
        db.commit()
        db.refresh(asset)

        first_result = run_asset_scan(asset.id, db)
        second_result = run_asset_scan(asset.id, db)

        assert first_result["status"] == "completed"
        assert second_result["status"] == "completed"

        assert first_result["scan_id"] != second_result["scan_id"]

        assert first_result["total_findings"] == 1
        assert second_result["total_findings"] == 1

        scan_ids = [
            first_result["scan_id"],
            second_result["scan_id"],
        ]

        saved_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.asset_id == asset.id,
                VulnerabilityFinding.cve_id == test_cve_id,
                VulnerabilityFinding.scan_id.in_(scan_ids),
            )
            .all()
        )

        assert len(saved_findings) == 2

        for scan_id in scan_ids:
            count = (
                db.query(VulnerabilityFinding)
                .filter(
                    VulnerabilityFinding.scan_id == scan_id,
                    VulnerabilityFinding.asset_id == asset.id,
                    VulnerabilityFinding.cve_id == test_cve_id,
                )
                .count()
            )

            assert count == 1

        print("Repeated scan test passed.")
        print("First scan ID:", first_result["scan_id"])
        print("Second scan ID:", second_result["scan_id"])
        print("Total findings across both scans:", len(saved_findings))

    finally:
        db.rollback()

        if asset is not None and asset.id is not None:
            db.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.asset_id == asset.id
            ).delete(synchronize_session=False)

            db.query(ScanRecord).filter(
                ScanRecord.target == asset.asset_name
            ).delete(synchronize_session=False)

            db.query(CVEIntelligence).filter(
                CVEIntelligence.cve_id == test_cve_id
            ).delete(synchronize_session=False)

            db.query(SoftwareAsset).filter(
                SoftwareAsset.id == asset.id
            ).delete(synchronize_session=False)

            db.commit()

        db.close()
