from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from vulnx.core.database import get_db
from vulnx.models.asset import SoftwareAsset
from vulnx.schemas.asset import (
    AssetCreate,
    AssetUpdate,
    AssetResponse,
)


router = APIRouter(
    prefix="/assets",
    tags=["Asset Inventory"],
)


@router.post(
    "/",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_asset(
    asset_data: AssetCreate,
    db: Session = Depends(get_db),
):
    asset = SoftwareAsset(**asset_data.model_dump())

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return asset


@router.get("/", response_model=list[AssetResponse])
def get_assets(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    if skip < 0 or not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Invalid pagination parameters",
        )

    return (
        db.query(SoftwareAsset)
        .order_by(SoftwareAsset.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
):
    asset = db.query(SoftwareAsset).filter(
        SoftwareAsset.id == asset_id
    ).first()

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    return asset


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset_data: AssetUpdate,
    db: Session = Depends(get_db),
):
    asset = db.query(SoftwareAsset).filter(
        SoftwareAsset.id == asset_id
    ).first()

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    updates = asset_data.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided",
        )

    for field, value in updates.items():
        setattr(asset, field, value)

    db.commit()
    db.refresh(asset)

    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
):
    asset = db.query(SoftwareAsset).filter(
        SoftwareAsset.id == asset_id
    ).first()

    if asset is None:
        raise HTTPException(
            status_code=404,
            detail="Asset not found",
        )

    db.delete(asset)
    db.commit()