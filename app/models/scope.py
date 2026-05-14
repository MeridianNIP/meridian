from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import CIDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ScopeRule(Base):
    __tablename__ = "scope_rules"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    cidr: Mapped[str] = mapped_column(CIDR, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
