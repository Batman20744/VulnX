from datetime import datetime, timezone

from sqlalchemy import (
    Integer,
    String,
    DateTime,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from vulnx.core.database import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True
    )

    scan_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False
    )

    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False
    )

    target: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="pending",
        nullable=False
    )

    total_assets: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )

    total_findings: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )