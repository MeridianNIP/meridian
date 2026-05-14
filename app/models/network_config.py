from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import BigInteger, DateTime, ForeignKey, SmallInteger, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class NetworkConfig(Base, TimestampMixin):
    """Singleton row holding the currently-applied network settings.
    `settings` is a JSONB dict with sub-objects for `ip`, `dns`, `proxy`.
    `apply_status` is the outcome of the last apply_now() call."""

    __tablename__ = "network_config"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, default=1)
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    apply_status: Mapped[str | None] = mapped_column(Text)
    apply_detail: Mapped[dict | None] = mapped_column(JSONB)


class NetworkConfigHistory(Base):
    """Append-only audit trail of every apply attempt."""

    __tablename__ = "network_config_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    applied_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    settings: Mapped[dict] = mapped_column(JSONB, nullable=False)
    apply_status: Mapped[str] = mapped_column(Text, nullable=False)
    apply_detail: Mapped[dict | None] = mapped_column(JSONB)
