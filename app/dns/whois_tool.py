"""WHOIS + bulk WHOIS + typosquat scanner.

Each function is async and returns a plain dict so the routes stay thin.
The `whois` binary is already in the sandbox allowlist; we parse enough
of the output to populate a structured result without needing RDAP.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from app.sandbox.runner import run as sandbox_run


# Keys we try to extract from freeform whois output. Registrars format things
# differently, so we match a union of common labels — whichever shows up first
# wins. Anything unmatched is still surfaced via `raw` on the response.
_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("registrar",       ("Registrar:", "Registrar Name:", "Sponsoring Registrar:")),
    ("registrar_url",   ("Registrar URL:", "Registrar Website:", "Registrar's Website:")),
    ("registrar_iana_id", ("Registrar IANA ID:",)),
    ("registrar_abuse_email", ("Registrar Abuse Contact Email:",)),
    ("registrar_abuse_phone", ("Registrar Abuse Contact Phone:",)),
    ("whois_server",    ("Registrar WHOIS Server:", "WHOIS Server:", "Whois Server:")),
    ("registrant_org",  ("Registrant Organization:", "Registrant Organisation:", "Registrant:")),
    ("registrant_country", ("Registrant Country:",)),
    ("registrant_email", ("Registrant Email:",)),
    ("created",         ("Creation Date:", "Created On:", "Created:", "Registered on:", "domain_dateregistered:")),
    ("updated",         ("Updated Date:", "Last Updated:", "Updated:", "Last Modified:")),
    ("expires",         ("Registry Expiry Date:", "Expiration Date:", "Expires On:", "Expires:", "Expiration:", "paid-till:")),
    ("name_servers",    ("Name Server:", "Nameserver:", "nserver:")),
    ("status",          ("Domain Status:", "Status:")),
    ("dnssec",          ("DNSSEC:",)),
)


def _parse_whois(stdout: str) -> dict[str, Any]:
    """Best-effort key/value extraction from a whois response."""
    out: dict[str, Any] = {}
    for line in stdout.splitlines():
        s = line.strip()
        if not s or s.startswith(("%", "#", ">>>", ";")):
            continue
        for key, prefixes in _FIELDS:
            for prefix in prefixes:
                if s.lower().startswith(prefix.lower()):
                    value = s[len(prefix):].strip().rstrip(".")
                    if not value:
                        continue
                    # Multi-value fields (name_servers, status) build a list.
                    if key in ("name_servers", "status"):
                        out.setdefault(key, [])
                        if value not in out[key]:
                            out[key].append(value)
                    elif key not in out:
                        out[key] = value
                    break
    return out


_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


async def whois_domain(target: str, *, timeout_s: float = 10.0) -> dict[str, Any]:
    if not _DOMAIN_RE.match(target):
        raise ValueError(f"not a valid domain: {target!r}")
    result = await sandbox_run("whois", [target], timeout_s=timeout_s)
    parsed = _parse_whois(result.stdout)
    return {
        "target": target,
        "parsed": parsed,
        "returncode": result.returncode,
        "duration_ms": result.duration_ms,
        "raw": result.stdout[:20_000],  # cap; full output can be ~100kB
        "truncated": result.truncated,
    }


async def whois_bulk(targets: list[str], *, timeout_s: float = 10.0,
                    concurrency: int = 4) -> dict[str, Any]:
    """Run whois against many targets with a small concurrency limit so we
    don't get rate-limited by upstream WHOIS servers."""
    # Dedupe + validate up front — one bad entry shouldn't kill the whole run.
    clean: list[str] = []
    rejected: list[dict[str, str]] = []
    seen: set[str] = set()
    for t in targets:
        t = t.strip().lower()
        if not t or t in seen:
            continue
        seen.add(t)
        if not _DOMAIN_RE.match(t):
            rejected.append({"target": t, "error": "invalid domain"})
        else:
            clean.append(t)

    sem = asyncio.Semaphore(concurrency)

    async def _one(t: str) -> dict[str, Any]:
        async with sem:
            try:
                r = await whois_domain(t, timeout_s=timeout_s)
                p = r["parsed"] or {}
                return {
                    "target": t,
                    "registrar":          p.get("registrar"),
                    "registrar_url":      p.get("registrar_url"),
                    "registrar_iana_id":  p.get("registrar_iana_id"),
                    "registrar_abuse_email": p.get("registrar_abuse_email"),
                    "registrar_abuse_phone": p.get("registrar_abuse_phone"),
                    "whois_server":       p.get("whois_server"),
                    "registrant_org":     p.get("registrant_org"),
                    "registrant_country": p.get("registrant_country"),
                    "registrant_email":   p.get("registrant_email"),
                    "created":            p.get("created"),
                    "updated":            p.get("updated"),
                    "expires":            p.get("expires"),
                    "dnssec":             p.get("dnssec"),
                    "status":             p.get("status") or [],
                    "name_servers":       p.get("name_servers") or [],
                    "ok": r["returncode"] == 0,
                }
            except Exception as e:  # noqa: BLE001
                return {"target": t, "ok": False, "error": f"{type(e).__name__}: {e}"}

    rows = await asyncio.gather(*[_one(t) for t in clean])
    return {"rows": list(rows) + rejected, "total": len(clean) + len(rejected)}


# ----------------------------------------------------------------------------
# Typosquat / domain permutation scanner.
# ----------------------------------------------------------------------------
# Pure Python — no dnstwist dep. The generated set is a subset of what dnstwist
# produces (homoglyph substitutions across a small ASCII-lookalike table,
# character omission, transposition, insertion, and common TLD swaps). We then
# run a quick A-record lookup against each to see which permutations actually
# resolve. Anything that answers is worth a closer look.
_HOMOGLYPHS = {
    "a": "4",
    "b": "8",
    "e": "3",
    "g": "9",
    "i": "1",
    "l": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "z": "2",
}

_TLD_SWAPS = (
    "com", "net", "org", "co", "io", "app", "dev", "info", "biz",
    "cn", "ru", "xyz", "online", "site", "shop", "store", "cloud",
)


def _permutations(domain: str) -> set[str]:
    base, _, tld = domain.rpartition(".")
    if not base:
        return set()
    variants: set[str] = set()

    # Homoglyph: swap each letter once for its digit lookalike.
    for i, ch in enumerate(base.lower()):
        if ch in _HOMOGLYPHS:
            variants.add(base[:i] + _HOMOGLYPHS[ch] + base[i+1:] + "." + tld)

    # Omission: drop each character once.
    for i in range(len(base)):
        variants.add(base[:i] + base[i+1:] + "." + tld)

    # Transposition: swap each adjacent pair once.
    for i in range(len(base) - 1):
        swapped = base[:i] + base[i+1] + base[i] + base[i+2:]
        variants.add(swapped + "." + tld)

    # Insertion: duplicate each character once.
    for i, ch in enumerate(base):
        variants.add(base[:i+1] + ch + base[i+1:] + "." + tld)

    # TLD swap: keep the base, swap the TLD.
    for swap in _TLD_SWAPS:
        if swap != tld.lower():
            variants.add(base + "." + swap)

    # Never match the original — it's the baseline.
    variants.discard(domain.lower())
    return variants


async def typosquat_scan(target: str, *, max_variants: int = 150,
                         timeout_s: float = 3.0) -> dict[str, Any]:
    if not _DOMAIN_RE.match(target):
        raise ValueError(f"not a valid domain: {target!r}")

    variants = sorted(_permutations(target))[:max_variants]
    sem = asyncio.Semaphore(16)

    async def _resolve(host: str) -> dict[str, Any]:
        async with sem:
            r = await sandbox_run(
                "dig",
                [host, "A", "+short", "+noall", "+answer", "+time=2", "+tries=1"],
                timeout_s=timeout_s,
            )
            ips = [l.strip() for l in r.stdout.splitlines() if l.strip()
                   and not l.startswith(";") and re.match(r"^[\d.]+$", l.strip())]
            return {"variant": host, "resolved": bool(ips), "ips": ips}

    results = await asyncio.gather(*[_resolve(v) for v in variants])
    hits = [r for r in results if r["resolved"]]
    return {
        "target": target,
        "variants_checked": len(variants),
        "hits": hits,
        "total_hits": len(hits),
    }
