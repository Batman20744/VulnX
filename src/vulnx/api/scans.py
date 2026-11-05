
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vulnx.core.database import get_db
from vulnx.services.scan_service import run_asset_scan
from vulnx.models.scan import ScanRecord


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


@router.post("/assets/{asset_id}")
def scan_asset(
    asset_id: int,
    db: Session = Depends(get_db),
):
    try:
        return run_asset_scan(asset_id, db)

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )


@router.get("/")
def list_scans(
    db: Session = Depends(get_db),
):
    scans = (
        db.query(ScanRecord)
        .order_by(ScanRecord.id.desc())
        .all()
    )

    return [
        {
            "id": scan.id,
            "scan_name": scan.scan_name,
            "scan_type": scan.scan_type,
            "target": scan.target,
            "status": scan.status,
            "total_assets": scan.total_assets,
            "total_findings": scan.total_findings,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
        }
        for scan in scans
    ]


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(ScanRecord)
        .filter(ScanRecord.id == scan_id)
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    return {
        "id": scan.id,
        "scan_name": scan.scan_name,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "total_assets": scan.total_assets,
        "total_findings": scan.total_findings,
        "summary": scan.summary,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }
