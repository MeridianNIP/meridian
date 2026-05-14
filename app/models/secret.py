"""Thin ORM shim for the existing `secrets` table.

The secrets vault is driven through raw SQL in app/secrets_vault/ — the
rotation / key-versioning logic doesn't map cleanly to an ORM. This
class exists only so FK references on other models (directory bind,
log shipping auth tokens, threat-intel API keys, device credentials)
resolve inside SQLAlchemy's metadata at write time; without it any
INSERT that references `secrets(id)` can raise
`NoReferencedTableError` on first use.
"""

from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import BYTEA, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Secret(Base):
    __tablename__ = "secrets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)  # secret_category enum
    description: Mapped[str | None] = mapped_column(Text)
    ciphertext: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    nonce: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    owner_scope: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    rotation_due: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_accessed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    access_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
