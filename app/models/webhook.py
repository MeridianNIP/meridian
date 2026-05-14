from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, Boolean, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Webhook(Base):
    __tablename__ = "webhooks"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    direction: Mapped[str] = mapped_column(Text, nullable=False)       # webhook_direction enum
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str | None] = mapped_column(Text)                       # outbound target
    events: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    secret_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("secrets.id"))
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    webhook_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("webhooks.id", ondelete="CASCADE"), nullable=False,
    )
    direction: Mapped[str] = mapped_column(Text, nullable=False)
    event: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    response: Mapped[str | None] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
