from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, BigInteger, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import BYTEA, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class License(Base):
    __tablename__ = "license"
    __table_args__ = (CheckConstraint("id = 1", name="license_single_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    license_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), unique=True)
    tier: Mapped[str] = mapped_column(String, nullable=False, default="free")
    max_users: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    max_concurrent_installs: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    customer_name: Mapped[str | None] = mapped_column(Text)
    customer_id: Mapped[str | None] = mapped_column(Text)
    contact_email: Mapped[str | None] = mapped_column(Text)
    features: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    signed_payload: Mapped[str | None] = mapped_column(Text)
    signature_algorithm: Mapped[str] = mapped_column(Text, nullable=False, default="Ed25519")
    signing_key_id: Mapped[str] = mapped_column(Text, nullable=False, default="k1")
    nonce: Mapped[str | None] = mapped_column(Text)
    bound_domain: Mapped[str | None] = mapped_column(Text)
    bound_fingerprint_hash: Mapped[str | None] = mapped_column(Text)
    bound_instance_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    activation_mode: Mapped[str] = mapped_column(Text, nullable=False, default="online")
    grace_days: Mapped[int] = mapped_column(Integer, nullable=False, default=14)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_verify_status: Mapped[str | None] = mapped_column(Text)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_hash: Mapped[bytes | None] = mapped_column(BYTEA)


class LicenseActivation(Base):
    __tablename__ = "license_activations"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    license_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    instance_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    fingerprint_hash: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str | None] = mapped_column(INET)
    ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_hash: Mapped[bytes | None] = mapped_column(BYTEA)


class LicenseVerification(Base):
    __tablename__ = "license_verifications"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict | None] = mapped_column(JSONB)
    row_hash: Mapped[bytes | None] = mapped_column(BYTEA)
