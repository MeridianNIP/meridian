from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class NetworkDevice(Base):
    __tablename__ = "network_devices"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    mgmt_host: Mapped[str] = mapped_column(Text, nullable=False)
    mgmt_port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    username: Mapped[str | None] = mapped_column(Text)
    secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id"))
    enable_secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    auto_backup: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    retain_snapshots_count: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    site: Mapped[str | None] = mapped_column(Text)
    last_backup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_backup_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_backup_error: Mapped[str | None] = mapped_column(Text)
    last_config_sha256: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DeviceConfigSnapshot(Base):
    __tablename__ = "device_config_snapshots"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False,
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    trigger_kind: Mapped[str] = mapped_column(Text, nullable=False)
    raw_config: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_hex: Mapped[str] = mapped_column(Text, nullable=False)
    line_count: Mapped[int | None] = mapped_column(Integer)
    prev_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("device_config_snapshots.id"),
    )
    diff_from_prev: Mapped[str | None] = mapped_column(Text)
    diff_lines_added: Mapped[int | None] = mapped_column(Integer)
    diff_lines_removed: Mapped[int | None] = mapped_column(Integer)
    captured_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))


class DeviceBackupRun(Base):
    __tablename__ = "device_backup_runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trigger_kind: Mapped[str] = mapped_column(Text, nullable=False)
    devices_attempted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_ok: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="running")
