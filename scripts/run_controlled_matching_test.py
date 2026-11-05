
import json

from vulnx.core.database import SessionLocal
from vulnx.models.asset import SoftwareAsset
from vulnx.models.cve_intelligence import CVEIntelligence
from vulnx.models.finding import VulnerabilityFinding

from vulnx.services.scan_service import run_asset_scan


TEST_ASSET_NAME = "VulnX-Test-Log4j"
TEST_CVE_ID = "CVE-2099-0001"


def main():
    db = SessionLocal()

    try:
        # 1. Create or retrieve synthetic test asset.
        asset = (
            db.query(SoftwareAsset)
            .filter(
                SoftwareAsset.asset_name == TEST_ASSET_NAME
            )
            .first()
        )

        if asset is None:
            asset = SoftwareAsset(
                asset_name=TEST_ASSET_NAME,
                software_name="Log4j",
                vendor="Apache",
                operating_system="Test Environment",
                asset_type="software",
                description="Synthetic VulnX matching test asset.",
            )
            db.add(asset)

        # Always set the intended test version.
        asset.software_version = "2.15.0"

        db.flush()

        print("Test asset ID:", asset.id)
        print("Test software version:", asset.software_version)

        # 2. Define a synthetic NVD-style CPE configuration.
        configurations = [
            {
                "operator": "OR",
                "negate": False,
                "matches": [
                    {
                        "criteria": (
                            "cpe:2.3:a:apache:log4j:*:"
                            "*:*:*:*:*:*:*"
                        ),
                        "vulnerable": True,
                        "match_criteria_id": None,
                        "version_start_including": "2.15.0",
                        "version_start_excluding": None,
                        "version_end_including": None,
                        "version_end_excluding": "2.16.0",
                    }
                ],
                "children": [],
            }
        ]

        # 3. Create or update synthetic CVE intelligence.
        cve = (
            db.query(CVEIntelligence)
            .filter(
                CVEIntelligence.cve_id == TEST_CVE_ID
            )
            .first()
        )

        if cve is None:
            cve = CVEIntelligence(cve_id=TEST_CVE_ID)
            db.add(cve)

        cve.description = (
            "Synthetic vulnerability used only for "
            "VulnX controlled testing."
        )
        cve.severity = "CRITICAL"
        cve.cvss_score = 10.0
        cve.cvss_version = "3.1"
        cve.references = json.dumps([])
        cve.configurations = json.dumps(configurations)
        cve.source = "VulnX-Test-Fixture"

        db.commit()
        db.refresh(asset)

        # 4. Execute the actual VulnX scan service.
        print("\nRunning controlled vulnerability scan...")

        result = run_asset_scan(
            asset_id=asset.id,
            db=db,
        )

        print("\nSCAN RESULT")
        print("=" * 40)

        for key, value in result.items():
            print(f"{key}: {value}")

        # 5. Verify the synthetic finding was persisted.
        finding = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.scan_id == result["scan_id"],
                VulnerabilityFinding.asset_id == asset.id,
                VulnerabilityFinding.cve_id == TEST_CVE_ID,
            )
            .first()
        )

        print("\nDATABASE VERIFICATION")
        print("=" * 40)

        if finding is None:
            raise AssertionError(
                "Expected synthetic vulnerability finding "
                "was not saved."
            )

        print("Finding ID:", finding.id)
        print("CVE ID:", finding.cve_id)
        print("Asset ID:", finding.asset_id)
        print("Scan ID:", finding.scan_id)
        print("Severity:", finding.severity)
        print("Status:", finding.status)

        # 6. Verify that Log4Shell is not reported for this test version.
        log4shell_finding = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.scan_id == result["scan_id"],
                VulnerabilityFinding.asset_id == asset.id,
                VulnerabilityFinding.cve_id == "CVE-2021-44228",
            )
            .first()
        )

        assert result["status"] == "completed"
        assert result["total_findings"] == 1
        assert finding.status == "open"
        assert log4shell_finding is None

        print("\nSUCCESS: Controlled vulnerability test passed.")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
