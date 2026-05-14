from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.dns.dig import DigRequest, DigResult, _IPV4_RE, run_dig


# Fallback panel of public resolvers used only when the `resolvers` DB table
# is empty or unreachable. Normally the installer seeds these same 16 into
# the DB under the "house" scope where admins can add / remove / re-tag
# them; check_propagation() prefers the DB-backed list so customer
# customization works.
PUBLIC_RESOLVERS: tuple[tuple[str, str], ...] = (
    ("Cloudflare",    "1.1.1.1"),
    ("Google",        "8.8.8.8"),
    ("Quad9",         "9.9.9.9"),
    ("OpenDNS",       "208.67.222.222"),
    ("AdGuard",       "94.140.14.14"),
    ("NextDNS",       "45.90.28.193"),
    ("Verisign",      "64.6.64.6"),
    ("DNS.Watch",     "84.200.69.80"),
    ("Mullvad",       "194.242.2.2"),
    ("Yandex",        "77.88.8.8"),
    ("Neustar",       "156.154.70.1"),
    ("Comodo",        "8.26.56.26"),
    ("SafeDNS",       "195.46.39.39"),
    ("CleanBrowsing", "185.228.168.168"),
    ("Hurricane EL",  "74.82.42.42"),
    ("CenturyLink",   "205.171.3.65"),
)


@dataclass(frozen=True)
class PropRow:
    provider: str
    resolver_ip: str
    answer: str | None
    ok: bool
    duration_ms: int
    error: str | None


@dataclass(frozen=True)
class PropagationReport:
    target: str
    record_type: str
    rows: tuple[PropRow, ...]
    unique_answers: tuple[str, ...]
    divergence: bool


def _extract_first_answer(stdout: str) -> str | None:
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        return line
    return None


def _load_active_panel(user_id=None, group_tag: str | None = None
                       ) -> tuple[tuple[str, str], ...]:
    """DB-first resolver panel. Always includes house resolvers flagged
    as propagation defaults; if a user_id is supplied, also includes
    that user's personal resolvers with the same flag. When group_tag
    is provided, only resolvers with a matching group_tag are included
    (for customers with 5+ DNS servers and 5+ cache servers in separate
    groups). Falls back to the hardcoded PUBLIC_RESOLVERS tuple only
    when no group filter is set AND the DB is empty."""
    try:
        from app.db import session_scope
        from app.models.resolver import Resolver
        from sqlalchemy import select, or_, func
        with session_scope() as db:
            cond = (Resolver.owner_user_id.is_(None))
            if user_id is not None:
                cond = or_(cond, Resolver.owner_user_id == user_id)
            stmt = (select(Resolver.name, Resolver.ip)
                    .where(Resolver.is_propagation_default.is_(True), cond))
            if group_tag:
                stmt = stmt.where(Resolver.group_tag == group_tag)
            rows = db.execute(
                stmt.order_by(Resolver.owner_user_id.nullsfirst(), func.lower(Resolver.name))
            ).all()
        panel = tuple((r.name, str(r.ip)) for r in rows)
        if panel:
            return panel
        return PUBLIC_RESOLVERS if not group_tag else ()
    except Exception:
        return PUBLIC_RESOLVERS


async def check_propagation(target: str, record_type: str = "A", *,
                            user_id=None, group_tag: str | None = None) -> PropagationReport:
    from app.safety.limits import (
        PROPAGATION_MAX_RESOLVERS, PROPAGATION_PER_RESOLVER_TIMEOUT_S,
        PROPAGATION_CONCURRENCY, bounded_gather,
    )
    full_panel = _load_active_panel(user_id=user_id, group_tag=group_tag)
    # Hard cap on panel size: even if the operator's resolver_panel has 200
    # rows, a single propagation request fires at most PROPAGATION_MAX_RESOLVERS
    # of them. Defends against an over-eager admin building a massive panel
    # and accidentally turning every "check propagation" click into a fan-out
    # storm against upstream resolvers.
    panel = full_panel[:PROPAGATION_MAX_RESOLVERS]
    tasks = []
    for _, ip in panel:
        if not _IPV4_RE.match(ip):
            continue
        req = DigRequest(
            target=target, record_type=record_type, resolver=ip,
            flags=("+short", "+noall", "+answer"),
            timeout_s=PROPAGATION_PER_RESOLVER_TIMEOUT_S,
            tries=1,
        )
        tasks.append(run_dig(req))
    # bounded_gather caps concurrent dig subprocesses so we don't fork
    # PROPAGATION_MAX_RESOLVERS processes at once.
    raw_results: list[DigResult] = await bounded_gather(
        tasks, max_workers=PROPAGATION_CONCURRENCY, return_exceptions=False,
    )

    rows: list[PropRow] = []
    answers: set[str] = set()
    for (provider, ip), r in zip(panel, raw_results):
        answer = _extract_first_answer(r.stdout) if r.returncode == 0 else None
        if answer:
            answers.add(answer)
        err = None
        if not answer:
            stderr = (r.stderr or "").lower()
            is_timeout = (
                r.timed_out
                or "connection timed out" in stderr
                or "no servers could be reached" in stderr
                or "timed out" in stderr
            )
            if is_timeout:
                err = "timeout"
            elif r.returncode != 0:
                err = r.stderr.strip() or f"rc={r.returncode}"
            else:
                err = "no answer"
        rows.append(PropRow(
            provider=provider, resolver_ip=ip, answer=answer,
            ok=(r.returncode == 0 and answer is not None),
            duration_ms=r.duration_ms,
            error=err,
        ))

    return PropagationReport(
        target=target, record_type=record_type,
        rows=tuple(rows),
        unique_answers=tuple(sorted(answers)),
        divergence=len(answers) > 1,
    )
