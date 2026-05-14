from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin


class ThreatIntelIntegration(Base, TimestampMixin):
    """External threat-intel API keys: AbuseIPDB, GreyNoise, VirusTotal,
    URLScan, Shodan, Censys. One row per (kind, name) so a customer can
    store e.g. both a personal and a team API key for the same service.
    The API key itself is stored encrypted in the `secrets` table and
    referenced by `api_key_secret_id`, mirroring DirectoryIntegration's
    bind-password pattern so rotation + audit go through the same vault.
    """
    __tablename__ = "threat_intel_integrations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(Text, nullable=False)       # threat_intel_kind enum
    name: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    api_key_secret_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("secrets.id"))
    last_tested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_test_error: Mapped[str | None] = mapped_column(Text)
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
