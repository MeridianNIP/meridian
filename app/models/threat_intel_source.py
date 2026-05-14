from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ThreatIntelSource(Base):
    """Catalog of Threat Intel providers (tabs on /ui/threat-intel).

    One row per source. `enabled` hides the tab when off. `config` carries
    per-source overrides that an admin can tweak without a code deploy:
    base_url, timeout_s, auth_header. Seeded at first boot so the admin
    page always has the full list of 12 built-in providers.
    """

    __tablename__ = "threat_intel_sources"

    source_key: Mapped[str] = mapped_column(Text, primary_key=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(Text, nullable=False)  # vulnerability|reputation|exposure
    requires_key: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default="now()"
    )
