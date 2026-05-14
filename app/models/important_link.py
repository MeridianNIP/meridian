from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class ImportantLink(Base, TimestampMixin):
    """User-editable bookmarks. Two scopes:

    * `scope='global'` — created by an admin, visible to everyone.
      `user_id` IS NULL. Personal sort orders are stored separately
      (every user can reorder global links in their own view).
    * `scope='user'` — owned by a single user (`user_id` is set),
      visible only to them.

    `sort_order` is the default ordering. Per-user overrides of global
    link ordering live in `user.preferences['link_order']` — keeps the
    link table small and read-mostly.
    """

    __tablename__ = "important_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scope: Mapped[str] = mapped_column(Text, nullable=False)  # 'global' | 'user'
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE")
    )
    name: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str | None] = mapped_column(Text)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
