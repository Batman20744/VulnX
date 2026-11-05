
from datetime import datetime, timezone

from sqlalchemy import (
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column

from vulnx.core.database import Base


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    asset_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("software_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    scan_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("scan_records.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    cve_id: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True
    )

    title: Mapped[str] = mapped_column(
        String(250),
        nullable=False
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    epss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    is_kev: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )

    remediation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="open",
        nullable=False
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        Index(
            "ix_finding_scan_asset_cve",
            "scan_id",
            "asset_id",
            "cve_id",
            unique=True
        ),
    )
