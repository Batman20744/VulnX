
import pytest

from vulnx.core.database import SessionLocal
from vulnx.models.asset import SoftwareAsset
from vulnx.models.scan import ScanRecord
from vulnx.models.finding import VulnerabilityFinding
from vulnx.services.scan_service import run_asset_scan


def test_asset_with_no_matching_vulnerabilities():
    db = SessionLocal()

    asset = SoftwareAsset(
        asset_name="VulnX-Clean-Test-Asset",
        software_name="UnlistedSoftware",
        software_version="1.0.0",
        vendor="TestVendor",
        operating_system="Test OS",
        asset_type="software",
        description="Integration test asset with no matching CVEs.",
    )

    try:
        db.add(asset)
        db.commit()
        db.refresh(asset)

        result = run_asset_scan(asset.id, db)

        assert result["status"] == "completed"
        assert result["total_findings"] == 0

        scan = (
            db.query(ScanRecord)
            .filter(ScanRecord.id == result["scan_id"])
            .first()
        )

        assert scan is not None
        assert scan.status == "completed"
        assert scan.total_findings == 0

        findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.scan_id == result["scan_id"]
            )
            .all()
        )

        assert findings == []

    finally:
        db.rollback()

        # Remove only the dedicated test asset and its test scan.
        if asset.id is not None:
            db.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.asset_id == asset.id
            ).delete(synchronize_session=False)

            db.query(ScanRecord).filter(
                ScanRecord.target == asset.asset_name
            ).delete(synchronize_session=False)

            db.query(SoftwareAsset).filter(
                SoftwareAsset.id == asset.id
            ).delete(synchronize_session=False)

            db.commit()

        db.close()

def test_scan_missing_asset():
    db = SessionLocal()

    try:
        with pytest.raises(ValueError, match="Asset -1 not found"):
            run_asset_scan(-1, db)

        # Verify that no scan was created for the missing asset.
        scan = (
            db.query(ScanRecord)
            .filter(ScanRecord.target == "-1")
            .first()
        )

        assert scan is None

    finally:
        db.close()

def test_scan_failure_rolls_back_database_changes(monkeypatch):
    db = SessionLocal()

    asset = SoftwareAsset(
        asset_name="VulnX-Rollback-Test",
        software_name="RollbackProduct",
        software_version="1.0.0",
        vendor="TestVendor",
        operating_system="Test OS",
        asset_type="software",
        description="Synthetic rollback integration test.",
    )

    try:
        db.add(asset)
        db.commit()
        db.refresh(asset)

        def simulate_scan_failure(asset_id, session):
            raise RuntimeError("Simulated scanner failure")

        monkeypatch.setattr(
            "vulnx.services.scan_service.scan_asset_for_cves",
            simulate_scan_failure,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated scanner failure",
        ):
            run_asset_scan(asset.id, db)

        # The failed scan must not remain in the database.
        failed_scan = (
            db.query(ScanRecord)
            .filter(
                ScanRecord.target == asset.asset_name
            )
            .first()
        )

        assert failed_scan is None

    finally:
        db.rollback()

        if asset.id is not None:
            db.query(SoftwareAsset).filter(
                SoftwareAsset.id == asset.id
            ).delete(synchronize_session=False)

            db.commit()

        db.close()
