from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import ARRAY, Boolean, CheckConstraint, DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Branding(Base):
    __tablename__ = "branding"
    __table_args__ = (CheckConstraint("id = 1", name="branding_single_row"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    # Identity
    display_name: Mapped[str] = mapped_column(Text, nullable=False, default="Meridian")
    short_name: Mapped[str] = mapped_column(Text, nullable=False, default="Meridian")
    support_email: Mapped[str | None] = mapped_column(Text)
    support_url: Mapped[str | None] = mapped_column(Text)
    privacy_url: Mapped[str | None] = mapped_column(Text)
    imprint_url: Mapped[str | None] = mapped_column(Text)

    # Defaults
    default_timezone: Mapped[str] = mapped_column(Text, nullable=False, default="UTC")
    date_format: Mapped[str] = mapped_column(Text, nullable=False, default="iso")

    # Visual
    logo_path: Mapped[str | None] = mapped_column(Text)
    favicon_path: Mapped[str | None] = mapped_column(Text)
    login_bg_path: Mapped[str | None] = mapped_column(Text)
    pdf_header_path: Mapped[str | None] = mapped_column(Text)
    theme: Mapped[str] = mapped_column(Text, nullable=False, default="dark")
    accent_hex: Mapped[str] = mapped_column(Text, nullable=False, default="#20c896")

    # Login page
    pre_login_warning: Mapped[str | None] = mapped_column(Text)
    aup_require_first_login: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    aup_reprompt_on_change: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    aup_show_footer_link: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Email + outbound
    email_from_name: Mapped[str | None] = mapped_column(Text)
    email_from_address: Mapped[str | None] = mapped_column(Text)
    email_signature: Mapped[str | None] = mapped_column(Text)
    slack_sender_name: Mapped[str | None] = mapped_column(Text)
    teams_sender_name: Mapped[str | None] = mapped_column(Text)
    sms_sender_identity: Mapped[str | None] = mapped_column(Text)
    pdf_footer_text: Mapped[str | None] = mapped_column(Text)
    pdf_watermark: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # SSH
    ssh_motd: Mapped[str | None] = mapped_column(Text)
    ssh_motd_on_every_login: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Session policy
    session_idle_timeout_default_min: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    session_idle_timeout_max_min: Mapped[int] = mapped_column(Integer, nullable=False, default=1440)
    session_idle_timeout_options: Mapped[list[int]] = mapped_column(
        ARRAY(Integer),
        nullable=False,
        default=lambda: [10, 30, 60, 120, 0],
    )
    session_idle_never_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    session_idle_custom_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Password policy (fed from Global Settings → Password policy).
    password_min_length: Mapped[int] = mapped_column(Integer, nullable=False, default=12)
    password_required_classes: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    password_max_age_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    password_history_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=5)

    # MFA policy
    mfa_requirement: Mapped[str] = mapped_column(Text, nullable=False, default="admins_only")
    mfa_allowed_methods: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=lambda: ["totp"]
    )
    mfa_backup_codes_count: Mapped[int] = mapped_column(Integer, nullable=False, default=10)

    # Account lockout
    lockout_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    lockout_duration_min: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    lockout_unlock_mode: Mapped[str] = mapped_column(Text, nullable=False, default="admin_or_time")

    # Audit retention (the retention_rules table handles other scopes)
    audit_online_days: Mapped[int] = mapped_column(Integer, nullable=False, default=365)
    audit_archive_days: Mapped[int] = mapped_column(Integer, nullable=False, default=2555)
    audit_archive_target: Mapped[str] = mapped_column(Text, nullable=False, default="local")

    # Logo link-through (customer-configurable)
    logo_click_url: Mapped[str] = mapped_column(Text, nullable=False, default="https://meridiannip.com")
    logo_click_target: Mapped[str] = mapped_column(Text, nullable=False, default="_blank")

    # Enterprise
    vendor_attribution_hidden: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Audit
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id"),
    )


def load(db) -> Branding:
    """Fetch the single branding row. Raises KeyError if the table is empty,
    which only happens on a not-yet-seeded install."""
    from sqlalchemy import select

    row = db.execute(select(Branding).where(Branding.id == 1)).scalar_one_or_none()
    if row is None:
        raise KeyError("branding row not found · run install.sh to seed the database")
    return row
