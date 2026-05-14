from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class NotifChannel(Base, TimestampMixin):
    __tablename__ = "notif_channels"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    kind: Mapped[str] = mapped_column(Text, nullable=False)   # notif_channel_type enum
    target: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id"))


class NotifDelivery(Base):
    __tablename__ = "notif_deliveries"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    channel_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("notif_channels.id", ondelete="CASCADE"), nullable=False,
    )
    subject: Mapped[str | None] = mapped_column(Text)
    body: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict | None] = mapped_column(JSONB)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
