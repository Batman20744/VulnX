from datetime import datetime, timezone

from sqlalchemy import (
    String,
    Integer,
    DateTime,
    Text,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column

from vulnx.core.database import Base


class SoftwareAsset(Base):
    __tablename__ = "software_assets"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        index=True
    )

    software_name: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        index=True
    )

    software_version: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    vendor: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    operating_system: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    asset_type: Mapped[str] = mapped_column(
        String(50),
        default="software",
        nullable=False
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        Index(
            "ix_asset_software_vendor",
            "software_name",
            "vendor"
        ),
    )