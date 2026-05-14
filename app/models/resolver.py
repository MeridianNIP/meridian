from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class Resolver(Base, TimestampMixin):
    """A DNS resolver entry -- either admin-curated (house, owner NULL) or
    user-private (owner set). Dropdowns in DNS Tools show House + Mine;
    the Propagation tool uses only house entries flagged as
    is_propagation_default.
    """
    __tablename__ = "resolvers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    region: Mapped[str | None] = mapped_column(Text)
    notes: Mapped[str | None] = mapped_column(Text)
    is_propagation_default: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    group_tag: Mapped[str | None] = mapped_column(Text)
