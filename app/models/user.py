from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import BYTEA, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text)
    password_hash: Mapped[str | None] = mapped_column(Text)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    primary_auth: Mapped[str] = mapped_column(String, nullable=False, default="credential")
    role: Mapped[str] = mapped_column(String, nullable=False, default="viewer")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret_enc: Mapped[bytes | None] = mapped_column(BYTEA)
    phone_e164: Mapped[str | None] = mapped_column(Text)
    sms_carrier_gateway: Mapped[str | None] = mapped_column(Text)
    recovery_email: Mapped[str | None] = mapped_column(Text)
    recovery_phone: Mapped[str | None] = mapped_column(Text)
    avatar_path: Mapped[str | None] = mapped_column(Text)
    timezone: Mapped[str] = mapped_column(Text, nullable=False, default="UTC")
    preferences: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    external_id: Mapped[str | None] = mapped_column(Text)
    max_concurrent_sessions: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    idle_timeout_override_min: Mapped[int | None] = mapped_column(Integer)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Group(Base, TimestampMixin):
    __tablename__ = "groups"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class UserGroup(Base):
    __tablename__ = "user_groups"
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("groups.id", ondelete="CASCADE"), primary_key=True
    )
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    added_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))


class Permission(Base):
    __tablename__ = "permissions"
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)
    requires_two_person: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
