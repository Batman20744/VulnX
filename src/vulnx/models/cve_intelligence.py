
from datetime import datetime, timezone

from sqlalchemy import (
    String,
    Float,
    DateTime,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from vulnx.core.database import Base


class CVEIntelligence(Base):
    __tablename__ = "cve_intelligence"

    id: Mapped[int] = mapped_column(
        primary_key=True,
        index=True
    )

    cve_id: Mapped[str] = mapped_column(
        String(30),
        unique=True,
        nullable=False,
        index=True
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        default="UNKNOWN",
        nullable=False
    )

    cvss_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    cvss_version: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True
    )

    published: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    last_modified: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    references: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    # Original NVD CPE configuration tree stored as JSON.
    configurations: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    source: Mapped[str] = mapped_column(
        String(30),
        default="NVD",
        nullable=False
    )

    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
