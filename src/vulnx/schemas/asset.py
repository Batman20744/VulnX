from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AssetCreate(BaseModel):
    asset_name: str = Field(min_length=1, max_length=150)
    software_name: str = Field(min_length=1, max_length=200)
    software_version: str = Field(min_length=1, max_length=100)

    vendor: str | None = Field(default=None, max_length=150)
    operating_system: str | None = Field(default=None, max_length=150)

    asset_type: str = Field(default="software", max_length=50)
    description: str | None = None


class AssetUpdate(BaseModel):
    asset_name: str | None = Field(default=None, min_length=1, max_length=150)
    software_name: str | None = Field(default=None, min_length=1, max_length=200)
    software_version: str | None = Field(default=None, min_length=1, max_length=100)

    vendor: str | None = Field(default=None, max_length=150)
    operating_system: str | None = Field(default=None, max_length=150)

    asset_type: str | None = Field(default=None, max_length=50)
    description: str | None = None


class AssetResponse(BaseModel):
    id: int
    asset_name: str
    software_name: str
    software_version: str
    vendor: str | None
    operating_system: str | None
    asset_type: str
    description: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)