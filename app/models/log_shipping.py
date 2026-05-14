from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class LogShippingDestination(Base, TimestampMixin):
    """External log collector. Up to three rows allowed — enforcement at
    the service layer, not a schema constraint, so an admin can rotate
    between destinations during a cutover without hitting a hard cap.

    One row ships one stream to one collector. `kind` drives the
    transport adapter (syslog/splunk_hec/elastic/cef-over-syslog).
    Secret material (HEC token, API key, mTLS key) lives in the vault
    and is referenced by `auth_secret_id`.
    """

    __tablename__ = "log_shipping_destinations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # syslog|splunk_hec|elastic|cef
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    endpoint: Mapped[str] = mapped_column(Text, nullable=False)  # URL or host:port
    transport: Mapped[str] = mapped_column(Text, nullable=False, default="tcp")  # tcp|udp|tls|https
    facility: Mapped[str | None] = mapped_column(Text)  # syslog facility (local0..local7)
    index_or_sourcetype: Mapped[str | None] = mapped_column(Text)  # splunk index / ECS index pattern
    auth_secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id"))
    ca_cert_path: Mapped[str | None] = mapped_column(Text)  # optional TLS CA bundle
    event_filter: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    # categories to include; empty = everything
    batch_size: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    flush_interval_s: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    last_shipped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_cursor_ts: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    events_shipped_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
