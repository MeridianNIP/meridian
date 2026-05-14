from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class DirectoryIntegration(Base, TimestampMixin):
    __tablename__ = "directory_integrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(Text, nullable=False)  # directory_type enum
    name: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    fqdn: Mapped[str | None] = mapped_column(Text)
    netbios_name: Mapped[str | None] = mapped_column(Text)
    primary_uri: Mapped[str | None] = mapped_column(Text)
    fallback_uri: Mapped[str | None] = mapped_column(Text)
    base_dn: Mapped[str | None] = mapped_column(Text)
    bind_account: Mapped[str | None] = mapped_column(Text)
    bind_secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id"))
    auth_method: Mapped[str] = mapped_column(Text, nullable=False, default="password")
    ca_cert_path: Mapped[str | None] = mapped_column(Text)
    query_timeout_s: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_test_error: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
