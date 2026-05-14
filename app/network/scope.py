from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import time

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from app.models.scope import ScopeRule


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    classification: str  # 'internal' | 'external' | 'unknown'
    reason: str | None = None


# In-process cache with a short TTL. The rules table is tiny (dozens of rows at most),
# and the alternative (a DB hit per probe) would dominate the cost of a 1 ms ping.
_CACHE_TTL_S = 30.0
_cache: dict[str, tuple[float, list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]]] = {}


def _load(db: OrmSession) -> list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    entry = _cache.get("rules")
    now = time.monotonic()
    if entry and (now - entry[0]) < _CACHE_TTL_S:
        return entry[1]
    rows = db.execute(select(ScopeRule.kind, ScopeRule.cidr).where(ScopeRule.enabled.is_(True))).all()
    parsed: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for kind, cidr in rows:
        try:
            parsed.append((kind, ipaddress.ip_network(str(cidr), strict=False)))
        except ValueError:
            continue
    _cache["rules"] = (now, parsed)
    return parsed


def invalidate_cache() -> None:
    _cache.pop("rules", None)


def classify(db: OrmSession, host: str) -> ScopeDecision:
    """Return whether a host is internal/external plus a deny verdict.

    DNS names are treated as 'unknown' (no IP to classify against) — the caller
    then decides. Most call-sites only hard-gate when the host resolves to an IP.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return ScopeDecision(allowed=True, classification="unknown")

    rules = _load(db)

    for kind, net in rules:
        if kind == "deny" and ip in net:
            return ScopeDecision(
                allowed=False,
                classification="denied",
                reason=f"host {host} falls inside deny rule {net}",
            )

    # Overlay: explicit internal_extra / external_extra rules win over RFC1918 default.
    for kind, net in rules:
        if kind == "internal_extra" and ip in net:
            return ScopeDecision(allowed=True, classification="internal")
        if kind == "external_extra" and ip in net:
            return ScopeDecision(allowed=True, classification="external")

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return ScopeDecision(allowed=True, classification="internal")
    return ScopeDecision(allowed=True, classification="external")


def enforce(db: OrmSession, host: str, scope_of_use: str | None) -> None:
    """Raise ValueError if host violates deny list or scope_of_use.

    scope_of_use: 'internal' | 'external' | 'both' | None
    """
    decision = classify(db, host)
    if not decision.allowed:
        raise ValueError(decision.reason or f"host {host} denied by scope policy")
    if scope_of_use in (None, "both", "unknown"):
        return
    if decision.classification == "unknown":
        return
    if scope_of_use == "internal" and decision.classification != "internal":
        raise ValueError(
            f"scope_of_use=internal forbids probing {host} (classified as {decision.classification})"
        )
    if scope_of_use == "external" and decision.classification != "external":
        raise ValueError(
            f"scope_of_use=external forbids probing {host} (classified as {decision.classification})"
        )
