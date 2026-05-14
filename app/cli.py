from __future__ import annotations

from datetime import UTC, datetime
import sys
import uuid

import click
from sqlalchemy import select

from app.auth.password import hash_password
from app.config import get_settings
from app.db import session_scope
from app.models.user import User


@click.group()
def cli() -> None:
    """meridian-nip command-line tools."""


# --- version / doctor --------------------------------------------------------


@cli.command()
def version() -> None:
    s = get_settings()
    click.echo(f"Meridian {s.manifest_version}")
    click.echo(f"Portal:        {s.portal_name}  ({s.portal_domain})")
    click.echo(f"DSN:           {s.db_dsn.split('@')[-1]}")
    click.echo(f"Airgapped:     {s.airgapped}")


@cli.command()
def doctor() -> None:
    """Pre-flight checks. Safe to run any time; changes nothing."""
    ok = True

    def check(label: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        mark = click.style("✓", fg="green") if cond else click.style("✗", fg="red")
        click.echo(f"  {mark} {label}  {detail}")
        if not cond:
            ok = False

    s = get_settings()
    check("master_key readable", s.master_key_path.is_file(), str(s.master_key_path))
    check("row_hmac_key readable", s.row_hmac_key_path.is_file(), str(s.row_hmac_key_path))

    try:
        with session_scope() as db:
            db.execute(select(1))
        check("postgresql reachable", True)
    except Exception as e:
        check("postgresql reachable", False, str(e))

    if not ok:
        sys.exit(1)


# --- users -------------------------------------------------------------------


@cli.group()
def users() -> None:
    """User management."""


@users.command("create")
@click.option("--username", required=True)
@click.option("--email", required=True)
@click.option("--role", default="admin", type=click.Choice(["super_admin", "admin", "analyst", "viewer"]))
@click.option("--temp-password", required=True)
@click.option("--force-change-at-login", is_flag=True)
def users_create(
    username: str, email: str, role: str, temp_password: str, force_change_at_login: bool
) -> None:
    with session_scope() as db:
        existing = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if existing is not None:
            raise click.ClickException(f"user {username!r} already exists")
        now = datetime.now(UTC)
        u = User(
            id=uuid.uuid4(),
            username=username,
            email=email,
            role=role,
            enabled=True,
            password_hash=hash_password(temp_password),
            primary_auth="credential",
            preferences={"force_change_password": bool(force_change_at_login)},
            created_at=now,
            updated_at=now,
        )
        db.add(u)
    click.echo(f"Created user {username!r} ({role}).")


# --- entry point -------------------------------------------------------------

if __name__ == "__main__":
    cli()
