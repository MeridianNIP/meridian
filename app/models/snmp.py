from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class SnmpCommunity(Base, TimestampMixin):
    __tablename__ = "snmp_communities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    access: Mapped[str] = mapped_column(Text, nullable=False, default="ro")
    community: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_sources: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    v3_user: Mapped[str | None] = mapped_column(Text)
    v3_auth_key: Mapped[str | None] = mapped_column(Text)
    v3_priv_key: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
