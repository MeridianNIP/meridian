from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, BigInteger, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class AcmeAccount(Base, TimestampMixin):
    __tablename__ = "acme_accounts"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider: Mapped[str] = mapped_column(Text, nullable=False, default="letsencrypt")
    environment: Mapped[str] = mapped_column(Text, nullable=False, default="production")
    email: Mapped[str] = mapped_column(Text, nullable=False)
    key_secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    dns_provider: Mapped[str | None] = mapped_column(Text)
    dns_secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class Certificate(Base, TimestampMixin):
    __tablename__ = "certificates"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cert_type: Mapped[str] = mapped_column(Text, nullable=False)   # cert_type enum
    common_name: Mapped[str] = mapped_column(Text, nullable=False)
    sans: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    issuer: Mapped[str | None] = mapped_column(Text)
    serial_hex: Mapped[str | None] = mapped_column(Text)
    fingerprint_sha256: Mapped[str | None] = mapped_column(Text)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    key_type: Mapped[str | None] = mapped_column(Text)
    key_size: Mapped[int | None] = mapped_column(Integer)
    signature_alg: Mapped[str | None] = mapped_column(Text)
    leaf_pem: Mapped[str | None] = mapped_column(Text)
    chain_pem: Mapped[str | None] = mapped_column(Text)
    private_key_ref: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    auto_renew: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    managed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acme_account_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("acme_accounts.id"))
    challenge: Mapped[str | None] = mapped_column(Text)
    renew_before_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    deploy_target: Mapped[str | None] = mapped_column(Text)
    last_renewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_renew_status: Mapped[str | None] = mapped_column(Text)
    ocsp_stapled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ct_logged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    hsts_policy: Mapped[str | None] = mapped_column(Text)
    notify_channels: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(Text)


class CsrRequest(Base, TimestampMixin):
    __tablename__ = "csr_requests"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_cn: Mapped[str] = mapped_column(Text, nullable=False)
    sans: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    key_type: Mapped[str] = mapped_column(Text, nullable=False)
    key_secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    csr_pem: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    submitted_ca: Mapped[str | None] = mapped_column(Text)
    signed_cert_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("certificates.id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))


class CertEvent(Base):
    __tablename__ = "cert_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("certificates.id", ondelete="CASCADE"), nullable=False)
    event: Mapped[str] = mapped_column(Text, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    detail: Mapped[dict | None] = mapped_column(JSONB)
    row_hash: Mapped[bytes | None] = mapped_column()
