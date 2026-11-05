
import asyncio
import httpx

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vulnx.core.database import get_db
from vulnx.models.cve_intelligence import CVEIntelligence

from vulnx.services.cve_service import fetch_and_store_cve
from vulnx.services.epss_service import refresh_finding_epss
from vulnx.services.kev_service import refresh_finding_kev

from vulnx.intelligence.nvd_client import NVDClientError


router = APIRouter(
    prefix="/cves",
    tags=["CVE Intelligence"],
)


# GET all stored CVE records
@router.get("/")
def get_all_cves(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """Return stored CVE records."""

    if skip < 0 or not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Invalid pagination parameters.",
        )

    records = (
        db.query(CVEIntelligence)
        .order_by(CVEIntelligence.id)
        .offset(skip)
        .limit(limit)
        .all()
    )

    return [
        {
            "id": record.id,
            "cve_id": record.cve_id,
            "description": record.description,
            "severity": record.severity,
            "cvss_score": record.cvss_score,
            "cvss_version": record.cvss_version,
            "published": record.published,
            "last_modified": record.last_modified,
            "source": record.source,
            "retrieved_at": record.retrieved_at,
        }
        for record in records
    ]


# POST refresh EPSS intelligence
@router.post("/refresh-epss")
def refresh_epss(
    db: Session = Depends(get_db),
):
    """Refresh EPSS scores from FIRST."""

    try:
        result = refresh_finding_epss(db)

        return {
            "message": "EPSS intelligence refreshed successfully.",
            **result,
        }

    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="EPSS API request timed out.",
        ) from exc

    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve EPSS intelligence.",
        ) from exc


# POST refresh CISA KEV intelligence
@router.post("/refresh-kev")
def refresh_kev(
    db: Session = Depends(get_db),
):
    """Refresh KEV status using the official CISA catalog."""

    try:
        result = refresh_finding_kev(db)

        return {
            "message": "CISA KEV intelligence refreshed successfully.",
            **result,
        }

    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=504,
            detail="CISA KEV catalog request timed out.",
        ) from exc

    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve CISA KEV intelligence.",
        ) from exc


# GET one stored CVE record
@router.get("/{cve_id}")
def get_cve(
    cve_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve one stored CVE record."""

    record = (
        db.query(CVEIntelligence)
        .filter(
            CVEIntelligence.cve_id == cve_id.upper()
        )
        .first()
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="CVE record not found.",
        )

    return {
        "id": record.id,
        "cve_id": record.cve_id,
        "description": record.description,
        "severity": record.severity,
        "cvss_score": record.cvss_score,
        "cvss_version": record.cvss_version,
        "published": record.published,
        "last_modified": record.last_modified,
        "source": record.source,
        "retrieved_at": record.retrieved_at,
    }


# POST refresh one CVE from NVD
@router.post("/{cve_id}/refresh")
async def refresh_cve(
    cve_id: str,
    db: Session = Depends(get_db),
):
    """Fetch the latest CVE information from NVD."""

    if not cve_id.upper().startswith("CVE-"):
        raise HTTPException(
            status_code=422,
            detail="Invalid CVE ID format.",
        )

    try:
        record = await asyncio.wait_for(
            fetch_and_store_cve(cve_id, db),
            timeout=30.0,
        )

        return {
            "message": "CVE intelligence refreshed successfully.",
            "cve_id": record.cve_id,
            "severity": record.severity,
            "cvss_score": record.cvss_score,
            "source": record.source,
        }

    except NVDClientError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="CVE refresh timed out.",
        ) from exc
