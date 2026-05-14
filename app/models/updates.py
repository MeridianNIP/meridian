from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class UpdateSnapshot(Base):
    __tablename__ = "update_snapshots"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    db_included: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config_included: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    files_included: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UpdateHistoryEntry(Base):
    __tablename__ = "update_history"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    component: Mapped[str] = mapped_column(Text, nullable=False)
    from_version: Mapped[str | None] = mapped_column(Text)
    to_version: Mapped[str] = mapped_column(Text, nullable=False)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    applied_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("update_snapshots.id"))
    status: Mapped[str] = mapped_column(Text, nullable=False, default="ok")
    notes: Mapped[str | None] = mapped_column(Text)


class VersionManifest(Base):
    __tablename__ = "version_manifest"
    component_name: Mapped[str] = mapped_column(Text, primary_key=True)
    category: Mapped[str] = mapped_column(Text, primary_key=True)
    tested_on_debian: Mapped[str] = mapped_column(Text, primary_key=True, default="13")
    pinned_version: Mapped[str] = mapped_column(Text, nullable=False)
    min_version: Mapped[str | None] = mapped_column(Text)
    max_version: Mapped[str | None] = mapped_column(Text)
    purpose: Mapped[str | None] = mapped_column(Text)
    release_channel: Mapped[str] = mapped_column(Text, nullable=False, default="stable")
    manifest_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    upstream_url: Mapped[str | None] = mapped_column(Text)
    changelog_url: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    pinned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VersionDrift(Base):
    __tablename__ = "version_drift"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    component_name: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    found_version: Mapped[str] = mapped_column(Text, nullable=False)
    expected_version: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    note: Mapped[str | None] = mapped_column(Text)


class SystemUpdateRun(Base):
    __tablename__ = "system_update_runs"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reboot: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    output_tail: Mapped[str | None] = mapped_column(Text)
    packages_count: Mapped[int | None] = mapped_column(Integer)
    reboot_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cancelled_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
