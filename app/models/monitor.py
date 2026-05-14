from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import ARRAY, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Monitor(Base, TimestampMixin):
    __tablename__ = "monitors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # monitor_type enum
    target: Mapped[str] = mapped_column(Text, nullable=False)
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    notify_channels: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, default=list
    )
    # Per-monitor notification tuning — all optional, sensible defaults
    # match the old hardcoded behaviour so an unedited monitor keeps
    # firing the way it used to.
    fail_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    recovery_notify: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    quiet_hours_start: Mapped[int | None] = mapped_column(Integer)  # 0-23 UTC, NULL = none
    quiet_hours_end: Mapped[int | None] = mapped_column(Integer)  # 0-23 UTC
    renotify_interval_min: Mapped[int | None] = mapped_column(Integer)  # 0/NULL = off
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_status: Mapped[str | None] = mapped_column(Text)
    last_sample_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_value: Mapped[float | None] = mapped_column(Float)
    consecutive_fails: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="both")


class MonitorSample(Base):
    __tablename__ = "monitor_samples"
    monitor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitors.id", ondelete="CASCADE"),
        primary_key=True,
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[float | None] = mapped_column(Float)
    detail: Mapped[dict | None] = mapped_column(JSONB)


class MonitorIncident(Base):
    __tablename__ = "monitor_incidents"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    monitor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitors.id", ondelete="CASCADE"),
        nullable=False,
    )
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSONB)
    acked_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
