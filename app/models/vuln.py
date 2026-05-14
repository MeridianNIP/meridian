from __future__ import annotations

from datetime import datetime
from decimal import Decimal
import uuid

from sqlalchemy import ARRAY, DateTime, Integer, Numeric, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class VulnScan(Base):
    __tablename__ = "vuln_scans"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="running")
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class VulnFinding(Base):
    __tablename__ = "vuln_findings"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    component: Mapped[str] = mapped_column(Text, nullable=False)
    installed_version: Mapped[str] = mapped_column(Text, nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    references_: Mapped[list[str]] = mapped_column("references_", ARRAY(Text), nullable=False, default=list)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    suppression_note: Mapped[str | None] = mapped_column(Text)
    ticket_ref: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
