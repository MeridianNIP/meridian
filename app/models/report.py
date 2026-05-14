from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class ReportSchedule(Base, TimestampMixin):
    """A configured recurring report. Owned by a user; admins can schedule
    on behalf of the organisation (owner_id can be NULL for system-owned)."""

    __tablename__ = "report_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(Text, nullable=False)
    report_type: Mapped[str] = mapped_column(Text, nullable=False)
    # Cadence is declarative — one of: daily / weekly / monthly / custom.
    # `cron_expression` is populated for every row (derived from cadence)
    # so the celery tick loop can run a single comparison.
    cadence: Mapped[str] = mapped_column(Text, nullable=False, default="daily")
    cron_expression: Mapped[str] = mapped_column(Text, nullable=False)
    timezone_name: Mapped[str] = mapped_column(Text, nullable=False, default="UTC")
    format: Mapped[str] = mapped_column(Text, nullable=False, default="csv")  # csv|html
    delivery: Mapped[str] = mapped_column(Text, nullable=False, default="download")  # download|email
    email_to: Mapped[str | None] = mapped_column(Text)  # comma-separated list
    filters: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ReportRun(Base):
    """One execution of a schedule (or ad-hoc). Artifact lives on disk
    under the reports_dir; row retains metadata + status."""

    __tablename__ = "report_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_schedules.id", ondelete="SET NULL"),
    )
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    report_type: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(Text, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text, nullable=False, default="running")  # running|success|failed
    artifact_path: Mapped[str | None] = mapped_column(Text)
    artifact_bytes: Mapped[int | None] = mapped_column(BigInteger)
    row_count: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict | None] = mapped_column(JSONB)
