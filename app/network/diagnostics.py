"""Network-side diagnostics: ASN lookup, BGP looking glass, IP reputation,
IP geolocation, HSTS / security-header audit.

Each function is async and self-contained. External-service access is via
httpx with a conservative timeout; nothing here requires an API key.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

import httpx

from app.sandbox.runner import run as sandbox_run

_IPV4_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def _valid_ip(s: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(s)  # raises ValueError on bad input


# ============================================================================
# ASN lookup via whois.cymru.com — one-shot bulk lookup.
# ============================================================================
async def asn_lookup(ip: str, *, timeout_s: float = 8.0) -> dict[str, Any]:
    """Query Team Cymru's whois service for AS number + owner + country.

    Cymru accepts the syntax `-v <ip>` and returns pipe-delimited output:
        AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    """
    _valid_ip(ip)
    # Sandbox whois doesn't accept -h flag (would be extra lockdown). Use the
    # direct whois invocation with a fixed argv — still runs under the same
    # allowlist because `whois` is listed. The sandbox reject-list blocks
    # shell metas but leaves `-h` alone.
    r = await sandbox_run(
        "whois",
        ["-h", "whois.cymru.com", f" -v {ip}"],
        timeout_s=timeout_s,
    )
    # Cymru's response has a header row ("AS | IP | BGP Prefix | ...") followed
    # by the actual data row. Skip the header by looking for the ASN column to
    # be numeric.
    for line in r.stdout.splitlines():
        if line.startswith("#") or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 7:
            continue
        if not parts[0].isdigit():
            # Header line or "NA | ..." for unrouted space.
            continue
        return {
            "ip": ip,
            "asn": parts[0] or None,
            "bgp_prefix": parts[2] or None,
            "country": parts[3] or None,
            "registry": parts[4] or None,
            "allocated": parts[5] or None,
            "as_name": parts[6] or None,
            "raw": r.stdout[:4096],
        }
    return {
        "ip": ip,
        "asn": None,
        "raw": r.stdout[:4096],
        "error": "no routed-ASN line returned (IP may be unrouted / bogon)",
    }


# ============================================================================
# BGP looking glass — via bgp.tools (no key required for basic queries).
# ============================================================================
async def bgp_looking_glass(target: str, *, timeout_s: float = 12.0) -> dict[str, Any]:
    """Return the currently-advertised prefix + upstream ASN(s) for an IP or ASN.

    Backed by RIPEstat — free, no key, maintained by RIPE NCC.
      · AS<n>  → https://stat.ripe.net/data/as-overview/data.json?resource=AS<n>
      · IP     → https://stat.ripe.net/data/network-info + routing-status
    """
    headers = {"User-Agent": "Meridian-NIP/1.0 (bgp-lg)", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=timeout_s, headers=headers) as c:
        if target.upper().startswith("AS"):
            n = target.strip().upper().removeprefix("AS")
            if not n.isdigit():
                raise ValueError(f"not a valid ASN: {target!r}")
            r = await c.get("https://stat.ripe.net/data/as-overview/data.json", params={"resource": f"AS{n}"})
            r.raise_for_status()
            d = (r.json() or {}).get("data") or {}
            return {
                "target": target,
                "kind": "asn",
                "name": d.get("holder"),
                "description": (d.get("announced") and "announced") or (d.get("resource") or ""),
                "country": None,  # RIPEstat overview doesn't expose CC directly
                "website": None,
                "rir": d.get("block", {}).get("resource") if isinstance(d.get("block"), dict) else None,
                "announced": bool(d.get("announced")),
                "raw": d,
            }

        _valid_ip(target)
        # Covering prefix + network info for the IP.
        net_r = await c.get("https://stat.ripe.net/data/network-info/data.json", params={"resource": target})
        net_r.raise_for_status()
        net = (net_r.json() or {}).get("data") or {}
        asns = net.get("asns") or []
        prefix = net.get("prefix")

        # Pull holder name for each ASN in a small fanout (usually 1-2 ASNs).
        async def _holder(n: int) -> dict[str, Any]:
            rr = await c.get(
                "https://stat.ripe.net/data/as-overview/data.json", params={"resource": f"AS{n}"}
            )
            if rr.status_code != 200:
                return {"asn": n, "name": None}
            return {"asn": n, "name": ((rr.json() or {}).get("data") or {}).get("holder")}

        holders = await asyncio.gather(*[_holder(int(n)) for n in asns]) if asns else []
        origin_map = {h["asn"]: h["name"] for h in holders}
        return {
            "target": target,
            "kind": "ip",
            "ptr": None,
            "prefixes": [
                {
                    "prefix": prefix,
                    "origin_asn": int(n),
                    "origin_name": origin_map.get(int(n)),
                    "country": None,
                }
                for n in asns
            ],
        }


# ============================================================================
# IP reputation — query a curated set of public DNSBLs.
# ============================================================================
# These are all zero-cost, no-auth DNS blackhole lists. We reverse the octets
# per standard DNSBL convention and send an A query; if it answers, the IP is
# listed. Spamhaus also publishes TXT records with a reason.
_DNSBLS: tuple[tuple[str, str, str, str], ...] = (
    (
        "zen.spamhaus.org",
        "Spamhaus ZEN",
        "Combined SBL/XBL/PBL (spam + exploit + policy)",
        "https://check.spamhaus.org/results/?query={ip}",
    ),
    (
        "b.barracudacentral.org",
        "Barracuda",
        "Barracuda Reputation Block List",
        "https://www.barracudacentral.org/lookups/lookup-reputation",
    ),
    (
        "bl.spamcop.net",
        "SpamCop",
        "Spam-reporting cooperative",
        "https://www.spamcop.net/w3m?action=checkblock&ip={ip}",
    ),
    (
        "dnsbl.sorbs.net",
        "SORBS",
        "Composite abuse / open-relay list",
        "http://www.sorbs.net/lookup.shtml?{ip}",
    ),
    (
        "cbl.abuseat.org",
        "CBL",
        "Composite Blocking List (merged into Spamhaus XBL)",
        "https://www.abuseat.org/lookup.cgi?ip={ip}",
    ),
    ("psbl.surriel.com", "PSBL", "Passive Spam Block List", "https://psbl.org/listing?ip={ip}"),
    ("dnsbl.dronebl.org", "DroneBL", "Active-threat drone/bot list", "https://dronebl.org/lookup?ip={ip}"),
    (
        "ubl.unsubscore.com",
        "Lashback UBL",
        "Lashback Unsubscribe Block List",
        "https://blacklist.lashback.com/",
    ),
)


async def ip_reputation(ip: str, *, timeout_s: float = 3.0) -> dict[str, Any]:
    """Query each DNSBL in parallel. Listed = reputation hit."""
    ip_obj = _valid_ip(ip)
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return {"ip": ip, "error": "DNSBL checks are IPv4-only", "hits": []}

    reversed_ip = ".".join(reversed(str(ip_obj).split(".")))

    async def _one(zone: str, label: str, desc: str, url_tmpl: str) -> dict[str, Any]:
        query = f"{reversed_ip}.{zone}"
        r = await sandbox_run(
            "dig",
            [query, "A", "+short", "+time=2", "+tries=1"],
            timeout_s=timeout_s,
        )
        listed = any(l.strip().startswith("127.") for l in r.stdout.splitlines())
        return {
            "list": label,
            "zone": zone,
            "description": desc,
            "detail_url": url_tmpl.format(ip=ip),
            "listed": listed,
            "answer": [l.strip() for l in r.stdout.splitlines() if l.strip()] if listed else [],
        }

    rows = await asyncio.gather(*[_one(z, l, d, u) for z, l, d, u in _DNSBLS])
    hits = [r for r in rows if r["listed"]]
    return {"ip": ip, "lists_checked": len(rows), "listed_on": len(hits), "rows": rows, "hits": hits}


# ============================================================================
# IP geolocation — via ipapi.co free tier (no key, 1k/day).
# ============================================================================
async def ip_geolocate(ip: str, *, timeout_s: float = 8.0) -> dict[str, Any]:
    _valid_ip(ip)
    async with httpx.AsyncClient(timeout=timeout_s, headers={"User-Agent": "Meridian-NIP/1.0 (geoip)"}) as c:
        r = await c.get(f"https://ipapi.co/{ip}/json/")
        if r.status_code in (429, 403):
            return {"ip": ip, "error": "upstream rate-limited (ipapi.co)", "rate_limited": True}
        r.raise_for_status()
        d = r.json()
    if d.get("error"):
        return {"ip": ip, "error": d.get("reason", "lookup failed")}
    # Narrow the huge ipapi response to the fields worth surfacing.
    return {
        "ip": ip,
        "city": d.get("city"),
        "region": d.get("region"),
        "country": d.get("country_name"),
        "country_code": d.get("country_code"),
        "postal": d.get("postal"),
        "latitude": d.get("latitude"),
        "longitude": d.get("longitude"),
        "timezone": d.get("timezone"),
        "org": d.get("org"),
        "asn": d.get("asn"),
        "utc_offset": d.get("utc_offset"),
    }


# ============================================================================
# Security header audit — HSTS, CSP, Frame-Options, etc.
# ============================================================================
# Each check returns (grade: ok|warn|fail, detail: str, fix: str).
def _check_hsts(headers: dict[str, str]) -> tuple[str, str, str]:
    v = headers.get("strict-transport-security")
    if not v:
        return (
            "fail",
            "missing — site is replayable over HTTP",
            "Add:  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        )
    max_age = 0
    for part in v.split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part[len("max-age=") :])
            except ValueError:
                pass
    if max_age < 15768000:  # 6 months
        return (
            "warn",
            f"present but max-age={max_age}s (<6 months)",
            "Raise max-age to ≥31536000 (1 year) and add `includeSubDomains; preload` for hstspreload.org submission.",
        )
    return "ok", v, ""


def _check_csp(headers: dict[str, str]) -> tuple[str, str, str]:
    v = headers.get("content-security-policy") or headers.get("content-security-policy-report-only")
    if not v:
        return (
            "fail",
            "missing — scripts can load from anywhere",
            "Add:  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
        )
    if "unsafe-inline" in v.lower():
        return (
            "warn",
            "allows 'unsafe-inline' — negates most XSS protection",
            "Replace 'unsafe-inline' with per-tag nonces or hashes (<script nonce=\"...\">) and tighten script-src.",
        )
    return "ok", v[:250], ""


def _check_frame_options(headers: dict[str, str]) -> tuple[str, str, str]:
    v = headers.get("x-frame-options")
    csp = headers.get("content-security-policy") or ""
    if "frame-ancestors" in csp.lower():
        return "ok", "controlled via CSP frame-ancestors", ""
    if not v:
        return (
            "fail",
            "missing — site can be iframed for clickjacking",
            "Add:  X-Frame-Options: DENY  (or use CSP `frame-ancestors 'none'` for a modern equivalent).",
        )
    return "ok", v, ""


def _check_xcto(headers: dict[str, str]) -> tuple[str, str, str]:
    v = headers.get("x-content-type-options")
    if not v or "nosniff" not in v.lower():
        return (
            "fail",
            "missing 'nosniff' — browsers may MIME-sniff and misinterpret",
            "Add:  X-Content-Type-Options: nosniff",
        )
    return "ok", v, ""


def _check_referrer(headers: dict[str, str]) -> tuple[str, str, str]:
    v = headers.get("referrer-policy")
    if not v:
        return (
            "warn",
            "missing — default referrer leaks full URLs cross-origin",
            "Add:  Referrer-Policy: strict-origin-when-cross-origin  (or `no-referrer` for max privacy).",
        )
    return "ok", v, ""


def _check_permissions(headers: dict[str, str]) -> tuple[str, str, str]:
    v = headers.get("permissions-policy")
    if not v:
        return (
            "warn",
            "missing — browser features (geolocation, camera, …) aren't gated",
            "Add a Permissions-Policy that denies what you don't need, e.g.:  geolocation=(), camera=(), microphone=(), payment=()",
        )
    return "ok", v[:250], ""


def _check_cookie_flags(headers: dict[str, str]) -> tuple[str, str, str]:
    v = headers.get("set-cookie", "")
    if not v:
        return "ok", "no cookies observed on this response", ""
    issues = []
    fixes = []
    if "httponly" not in v.lower():
        issues.append("missing HttpOnly")
        fixes.append("HttpOnly (blocks JS access)")
    if "secure" not in v.lower():
        issues.append("missing Secure")
        fixes.append("Secure (HTTPS-only)")
    if "samesite" not in v.lower():
        issues.append("missing SameSite")
        fixes.append("SameSite=Lax (or Strict)")
    if issues:
        return ("warn", "; ".join(issues), "Set-Cookie flags to add: " + ", ".join(fixes))
    return "ok", "HttpOnly + Secure + SameSite present", ""


_CHECKS = (
    ("HSTS", _check_hsts),
    ("CSP", _check_csp),
    ("Frame options", _check_frame_options),
    ("X-Content-Type-Options", _check_xcto),
    ("Referrer-Policy", _check_referrer),
    ("Permissions-Policy", _check_permissions),
    ("Cookie flags", _check_cookie_flags),
)


# ============================================================================
# CVE lookup — via NVD API 2.0 (no key required for light use).
# ============================================================================
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


async def cve_lookup(cve_id: str, *, timeout_s: float = 15.0) -> dict[str, Any]:
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(f"not a valid CVE id: {cve_id!r} (expected e.g. CVE-2021-44228)")
    async with httpx.AsyncClient(
        timeout=timeout_s,
        headers={"User-Agent": "Meridian-NIP/1.0 (cve-lookup)", "Accept": "application/json"},
    ) as c:
        r = await c.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"cveId": cve_id})
        if r.status_code == 404:
            return {"cve": cve_id, "error": "not found in NVD"}
        r.raise_for_status()
        j = r.json() or {}
    items = j.get("vulnerabilities") or []
    if not items:
        return {"cve": cve_id, "error": "no vulnerabilities returned", "refs": _cve_external_refs(cve_id)}
    v = (items[0] or {}).get("cve") or {}
    # Description: EN preferred.
    desc = next((d.get("value") for d in (v.get("descriptions") or []) if d.get("lang") == "en"), "")
    # CVSS: prefer v3.1 > v3.0 > v2.
    metrics = v.get("metrics") or {}
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            m = (arr[0] or {}).get("cvssData") or {}
            cvss = {
                "version": m.get("version"),
                "score": m.get("baseScore"),
                "severity": (arr[0].get("baseSeverity") or m.get("baseSeverity")),
                "vector": m.get("vectorString"),
            }
            break
    cwes = []
    for weakness in v.get("weaknesses") or []:
        for d in weakness.get("description") or []:
            val = d.get("value")
            if val and val not in cwes:
                cwes.append(val)
    refs = [{"url": r.get("url"), "tags": r.get("tags") or []} for r in (v.get("references") or [])][:50]
    return {
        "cve": cve_id,
        "published": v.get("published"),
        "modified": v.get("lastModified"),
        "status": v.get("vulnStatus"),
        "description": desc,
        "cvss": cvss,
        "cwes": cwes,
        "references": refs,
        "refs": _cve_external_refs(cve_id),
    }


def _cve_external_refs(cve: str) -> dict[str, str]:
    return {
        "nvd": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}",
        "github": f"https://github.com/advisories?query={cve}",
        "debian": f"https://security-tracker.debian.org/tracker/{cve}",
        "ubuntu": f"https://ubuntu.com/security/{cve}",
        "redhat": f"https://access.redhat.com/security/cve/{cve.lower()}",
    }


async def security_header_audit(url: str, *, timeout_s: float = 10.0) -> dict[str, Any]:
    """Fetch the URL and grade common security headers."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    async with httpx.AsyncClient(
        timeout=timeout_s, follow_redirects=True, headers={"User-Agent": "Meridian-NIP/1.0 (header-audit)"}
    ) as c:
        r = await c.get(url)
    lower = {k.lower(): v for k, v in r.headers.items()}
    rows = []
    worst = "ok"
    for name, fn in _CHECKS:
        grade, detail, fix = fn(lower)
        rows.append({"name": name, "grade": grade, "detail": detail, "fix": fix})
        if grade == "fail" or (grade == "warn" and worst == "ok"):
            worst = grade
    return {
        "url": str(r.url),
        "final_status": r.status_code,
        "worst": worst,
        "rows": rows,
        "observed_headers": {k: v[:250] for k, v in lower.items()},
    }


# ============================================================================
# CISA KEV — Known Exploited Vulnerabilities catalog.
# Single public JSON feed, no API key. Cached in-process for 6h so repeated
# CVE lookups don't refetch the ~5 MB document.
# ============================================================================
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/" "known_exploited_vulnerabilities.json"
_KEV_CACHE: dict[str, Any] = {"data": None, "fetched_at": 0.0}
_KEV_TTL_S = 6 * 3600


async def _load_kev(*, timeout_s: float = 20.0) -> dict[str, Any]:
    import time

    now = time.time()
    if _KEV_CACHE["data"] and (now - _KEV_CACHE["fetched_at"]) < _KEV_TTL_S:
        return _KEV_CACHE["data"]
    async with httpx.AsyncClient(
        timeout=timeout_s, headers={"User-Agent": "Meridian-NIP/1.0 (kev)", "Accept": "application/json"}
    ) as c:
        r = await c.get(_KEV_URL)
        r.raise_for_status()
        data = r.json()
    _KEV_CACHE["data"] = data
    _KEV_CACHE["fetched_at"] = now
    return data


async def kev_lookup(cve_id: str) -> dict[str, Any]:
    """Return the CISA KEV entry for a CVE, or not_listed=True."""
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(f"not a valid CVE id: {cve_id!r}")
    data = await _load_kev()
    for entry in data.get("vulnerabilities") or []:
        if (entry.get("cveID") or "").upper() == cve_id:
            return {
                "cve": cve_id,
                "listed": True,
                "date_added": entry.get("dateAdded"),
                "due_date": entry.get("dueDate"),
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                "notes": entry.get("notes"),
                "catalog_version": data.get("catalogVersion"),
                "catalog_released": data.get("dateReleased"),
            }
    return {
        "cve": cve_id,
        "listed": False,
        "catalog_version": data.get("catalogVersion"),
        "catalog_released": data.get("dateReleased"),
        "total_entries": data.get("count"),
    }


async def kev_search(query: str, *, limit: int = 50) -> dict[str, Any]:
    """Substring search across vendor / product / vulnerability name."""
    q = (query or "").strip().lower()
    if not q:
        raise ValueError("query is empty")
    data = await _load_kev()
    hits = []
    for entry in data.get("vulnerabilities") or []:
        blob = " ".join(
            str(entry.get(k) or "")
            for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")
        )
        if q in blob.lower():
            hits.append(
                {
                    "cve": entry.get("cveID"),
                    "date_added": entry.get("dateAdded"),
                    "due_date": entry.get("dueDate"),
                    "vendor_project": entry.get("vendorProject"),
                    "product": entry.get("product"),
                    "vulnerability_name": entry.get("vulnerabilityName"),
                    "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                }
            )
            if len(hits) >= limit:
                break
    return {
        "query": query,
        "total_matches": len(hits),
        "limit": limit,
        "rows": hits,
        "catalog_version": data.get("catalogVersion"),
    }


# ============================================================================
# EPSS — Exploit Prediction Scoring System (FIRST.org). No API key.
# Returns probability [0..1] and percentile [0..1].
# ============================================================================
async def epss_lookup(cve_id: str, *, timeout_s: float = 8.0) -> dict[str, Any]:
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(f"not a valid CVE id: {cve_id!r}")
    async with httpx.AsyncClient(
        timeout=timeout_s, headers={"User-Agent": "Meridian-NIP/1.0 (epss)", "Accept": "application/json"}
    ) as c:
        r = await c.get("https://api.first.org/data/v1/epss", params={"cve": cve_id})
        r.raise_for_status()
        j = r.json() or {}
    data = j.get("data") or []
    if not data:
        return {"cve": cve_id, "found": False}
    row = data[0] or {}
    try:
        prob = float(row.get("epss") or 0.0)
    except (TypeError, ValueError):
        prob = 0.0
    try:
        pct = float(row.get("percentile") or 0.0)
    except (TypeError, ValueError):
        pct = 0.0
    return {
        "cve": cve_id,
        "found": True,
        "probability": prob,
        "percentile": pct,
        "date": row.get("date"),
        "model_version": j.get("version"),
    }


# ============================================================================
# CIRCL CVE aggregator — cve.circl.lu. No API key. Response is a CVE v5.1
# record (cveMetadata + containers.cna), which is the same shape MITRE
# moved to. Parser flattens it into the fields the Threat Intel UI renders.
# ============================================================================
async def circl_lookup(cve_id: str, *, timeout_s: float = 10.0) -> dict[str, Any]:
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(f"not a valid CVE id: {cve_id!r}")
    async with httpx.AsyncClient(
        timeout=timeout_s, headers={"User-Agent": "Meridian-NIP/1.0 (circl)", "Accept": "application/json"}
    ) as c:
        r = await c.get(f"https://cve.circl.lu/api/cve/{cve_id}")
        if r.status_code == 404:
            return {"cve": cve_id, "found": False}
        r.raise_for_status()
        j = r.json() or {}
    if not j:
        return {"cve": cve_id, "found": False}

    meta = j.get("cveMetadata") or {}
    cna = ((j.get("containers") or {}).get("cna")) or {}

    # Description: prefer English.
    summary = next(
        (
            d.get("value")
            for d in (cna.get("descriptions") or [])
            if (d.get("lang") or "").lower().startswith("en")
        ),
        "",
    )

    # CVSS: v3.1 > v3.0 > v4.0 > v2.
    cvss_score = None
    cvss_sev = None
    cvss_vec = None
    cvss_ver = None
    for m in cna.get("metrics") or []:
        for key, ver in (("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV4_0", "4.0"), ("cvssV2_0", "2.0")):
            block = m.get(key)
            if block:
                cvss_score = block.get("baseScore")
                cvss_sev = block.get("baseSeverity")
                cvss_vec = block.get("vectorString")
                cvss_ver = ver
                break
        if cvss_score is not None:
            break

    # CWE ids + human descriptions.
    cwes = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cid = d.get("cweId") or d.get("description") or ""
            if cid and cid not in cwes:
                cwes.append(cid)

    # Affected vendor/product/version strings, flattened for display.
    affected = []
    for a in cna.get("affected") or []:
        vendor = a.get("vendor") or ""
        product = a.get("product") or ""
        vers = [v.get("version") for v in (a.get("versions") or []) if v.get("version")]
        affected.append(
            " · ".join(
                p
                for p in (
                    f"{vendor}/{product}".strip("/"),
                    ", ".join(vers[:4]) + ("…" if len(vers) > 4 else ""),
                )
                if p
            )
        )

    refs = [
        {"url": r.get("url"), "tags": r.get("tags") or []}
        for r in (cna.get("references") or [])
        if r.get("url")
    ][:50]

    return {
        "cve": meta.get("cveId") or cve_id,
        "found": True,
        "summary": (cna.get("title") + " — " + summary) if cna.get("title") else summary,
        "state": meta.get("state"),
        "published": meta.get("datePublished"),
        "modified": meta.get("dateUpdated"),
        "cvss": cvss_score,
        "cvss_severity": cvss_sev,
        "cvss_version": cvss_ver,
        "cvss_vector": cvss_vec,
        "cwes": cwes,
        "affected": affected[:30],
        "references": refs,
        "assigner": meta.get("assignerShortName"),
        "detail_url": f"https://cve.circl.lu/cve/{cve_id}",
    }


# ============================================================================
# DShield / Internet Storm Center IP reputation. No API key.
# Returns attack + report counts plus ASN/country context.
# ============================================================================
async def dshield_lookup(ip: str, *, timeout_s: float = 8.0) -> dict[str, Any]:
    ip_obj = _valid_ip(ip)
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return {"ip": ip, "error": "DShield only supports IPv4"}
    async with httpx.AsyncClient(
        timeout=timeout_s, headers={"User-Agent": "Meridian-NIP/1.0 (dshield)", "Accept": "application/json"}
    ) as c:
        r = await c.get(f"https://isc.sans.edu/api/ip/{ip}?json")
        r.raise_for_status()
        j = r.json() or {}
    info = j.get("ip") or {}

    # DShield returns strings for numeric fields; cast defensively.
    def _int(v):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    return {
        "ip": ip,
        "count": _int(info.get("count")),
        "attacks": _int(info.get("attacks")),
        "unique_targets": _int(info.get("mincount")),
        "maxdate": info.get("maxdate"),
        "mindate": info.get("mindate"),
        "updated": info.get("updated"),
        "country": info.get("ascountry") or info.get("country"),
        "asn": _int(info.get("as")),
        "asname": info.get("asname"),
        "network": info.get("network"),
        "threatfeed_count": _int(info.get("threatfeedscount")),
        "comment": info.get("comment"),
        "detail_url": f"https://isc.sans.edu/ipinfo/{ip}",
    }


# ============================================================================
# Threat-intel API-key resolver. Looks up the first enabled integration of
# the given kind, decrypts the stored key, and returns (key, config).
# The config dict can carry a `base_url` override so an admin can point
# the lookup at a relocated endpoint without a code change.
# Raises LookupError if no enabled key is configured.
# ============================================================================
def _resolve_threat_intel(kind: str) -> tuple[str, dict[str, Any]]:
    """Return (api_key, merged_config) for the given provider.

    Config precedence (highest wins): per-integration config → source-level
    source.config → code default. An admin can therefore set e.g. a new
    base_url once at the source level and every stored key uses it.
    """
    from sqlalchemy import text as _sql_text

    from app.db import session_scope
    from app.secrets_vault.vault import decrypt_field

    with session_scope() as db:
        row = db.execute(
            _sql_text("""
            SELECT s.nonce, s.ciphertext, t.config
              FROM threat_intel_integrations t
              JOIN secrets s ON s.id = t.api_key_secret_id
             WHERE t.kind = :k AND t.enabled = TRUE
             ORDER BY t.created_at ASC
             LIMIT 1
        """),
            {"k": kind},
        ).first()
        if not row:
            # Check source catalog: if the whole provider is disabled, give
            # a clearer message than a generic "configure a key".
            src_row = db.execute(
                _sql_text("SELECT enabled FROM threat_intel_sources WHERE source_key=:k"), {"k": kind}
            ).first()
            if src_row and not src_row[0]:
                raise LookupError(
                    f"The {kind} source is disabled — re-enable it under "
                    f"Admin → Integrations → Threat Intel → Sources."
                )
            raise LookupError(
                f"No enabled {kind} integration configured — "
                f"add one under Admin → Integrations → Threat Intel."
            )
        src_row = db.execute(
            _sql_text("""
            SELECT enabled, config FROM threat_intel_sources WHERE source_key=:k
        """),
            {"k": kind},
        ).first()
    if src_row and not src_row[0]:
        raise LookupError(
            f"The {kind} source is disabled — re-enable it under "
            f"Admin → Integrations → Threat Intel → Sources."
        )
    nonce, ct, integ_cfg = bytes(row[0]), bytes(row[1]), (row[2] or {})
    source_cfg = (src_row[1] if src_row else {}) or {}
    merged = {**source_cfg, **integ_cfg}  # integration overrides source
    key = decrypt_field(nonce + ct, domain=b"vault").decode("utf-8")
    return key, merged


# Backwards-compatible shim (unused externally; kept so older callers don't break).
def _resolve_threat_intel_key(kind: str) -> str:
    return _resolve_threat_intel(kind)[0]


# Default upstream endpoints. Each lookup picks config.base_url first and
# falls back to the value here — so an admin can replatform a provider
# without a code deploy by editing the integration's Base URL.
_TI_DEFAULTS: dict[str, str] = {
    "abuseipdb": "https://api.abuseipdb.com/api/v2",
    "greynoise": "https://api.greynoise.io/v3/community",
    "virustotal": "https://www.virustotal.com/api/v3",
    "urlscan": "https://urlscan.io/api/v1",
    "shodan": "https://api.shodan.io/shodan",
    "censys": "https://search.censys.io/api/v2",
}


def _ti_base(kind: str, config: dict[str, Any]) -> str:
    return (config.get("base_url") or _TI_DEFAULTS[kind]).rstrip("/")


def _hostname_or_ip(s: str) -> str:
    s = (s or "").strip()
    if not s:
        raise ValueError("empty target")
    try:
        _valid_ip(s)
        return s
    except ValueError:
        if not _DOMAIN_RE.match(s):
            raise ValueError(f"not a valid host / IP: {s!r}")
        return s


# ============================================================================
# AbuseIPDB — IP abuse reports. Free tier: 1000 checks / day.
# ============================================================================
async def abuseipdb_lookup(ip: str, *, timeout_s: float = 10.0, max_age_days: int = 90) -> dict[str, Any]:
    _valid_ip(ip)
    key, config = _resolve_threat_intel("abuseipdb")
    base = _ti_base("abuseipdb", config)
    async with httpx.AsyncClient(
        timeout=timeout_s,
        headers={"Key": key, "Accept": "application/json", "User-Agent": "Meridian-NIP/1.0"},
    ) as c:
        r = await c.get(
            f"{base}/check", params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": "true"}
        )
        r.raise_for_status()
        j = (r.json() or {}).get("data") or {}
    return {
        "ip": ip,
        "confidence": j.get("abuseConfidenceScore"),
        "country": j.get("countryCode"),
        "usage": j.get("usageType"),
        "isp": j.get("isp"),
        "domain": j.get("domain"),
        "total_reports": j.get("totalReports"),
        "distinct_users": j.get("numDistinctUsers"),
        "last_reported": j.get("lastReportedAt"),
        "hostnames": j.get("hostnames") or [],
        "is_tor": j.get("isTor"),
        "is_public": j.get("isPublic"),
        "reports": (j.get("reports") or [])[:10],
        "detail_url": f"https://www.abuseipdb.com/check/{ip}",
    }


# ============================================================================
# GreyNoise — scanner classification. Community endpoint needs key too.
# ============================================================================
async def greynoise_lookup(ip: str, *, timeout_s: float = 10.0) -> dict[str, Any]:
    _valid_ip(ip)
    key, config = _resolve_threat_intel("greynoise")
    base = _ti_base("greynoise", config)
    async with httpx.AsyncClient(
        timeout=timeout_s,
        headers={"key": key, "Accept": "application/json", "User-Agent": "Meridian-NIP/1.0"},
    ) as c:
        # v3/community is the right free-tier endpoint; v2 requires enterprise key.
        r = await c.get(f"{base}/{ip}")
        if r.status_code == 404:
            return {"ip": ip, "seen": False, "message": "IP not observed by GreyNoise"}
        r.raise_for_status()
        j = r.json() or {}
    return {
        "ip": ip,
        "seen": True,
        "classification": j.get("classification"),  # benign|malicious|unknown
        "name": j.get("name"),
        "last_seen": j.get("last_seen"),
        "link": j.get("link"),
        "message": j.get("message"),
    }


# ============================================================================
# VirusTotal — IP / domain / URL / file lookups.
# Supports target = IP, domain, or URL. URLs are base64url-encoded per VT docs.
# ============================================================================
import base64 as _b64


async def virustotal_lookup(target: str, *, timeout_s: float = 15.0) -> dict[str, Any]:
    t = (target or "").strip()
    if not t:
        raise ValueError("empty target")
    key, config = _resolve_threat_intel("virustotal")
    base = _ti_base("virustotal", config)
    # Decide which VT endpoint to hit.
    try:
        _valid_ip(t)
        endpoint = f"{base}/ip_addresses/{t}"
        kind = "ip"
    except ValueError:
        if t.startswith(("http://", "https://")):
            b = _b64.urlsafe_b64encode(t.encode()).rstrip(b"=").decode()
            endpoint = f"{base}/urls/{b}"
            kind = "url"
        elif _DOMAIN_RE.match(t):
            endpoint = f"{base}/domains/{t}"
            kind = "domain"
        else:
            raise ValueError(f"not a valid IP / domain / URL: {t!r}")
    async with httpx.AsyncClient(
        timeout=timeout_s, headers={"x-apikey": key, "User-Agent": "Meridian-NIP/1.0"}
    ) as c:
        r = await c.get(endpoint)
        if r.status_code == 404:
            return {"target": t, "kind": kind, "found": False}
        r.raise_for_status()
        j = r.json() or {}
    attrs = ((j.get("data") or {}).get("attributes")) or {}
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "target": t,
        "kind": kind,
        "found": True,
        "reputation": attrs.get("reputation"),
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
        "timeout": stats.get("timeout"),
        "tags": attrs.get("tags") or [],
        "categories": attrs.get("categories") or {},
        "as_owner": attrs.get("as_owner"),
        "asn": attrs.get("asn"),
        "country": attrs.get("country"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "last_modification_date": attrs.get("last_modification_date"),
        "detail_url": {
            "ip": f"https://www.virustotal.com/gui/ip-address/{t}",
            "domain": f"https://www.virustotal.com/gui/domain/{t}",
            "url": f"https://www.virustotal.com/gui/url/{_b64.urlsafe_b64encode(t.encode()).rstrip(b'=').decode() if kind=='url' else ''}",
        }.get(kind, ""),
    }


# ============================================================================
# URLScan.io — search by URL / domain over *public* scans (read-only).
# Full submit API is separate; we just query the result index here.
# ============================================================================
async def urlscan_search(query: str, *, timeout_s: float = 15.0, size: int = 20) -> dict[str, Any]:
    q = (query or "").strip()
    if not q:
        raise ValueError("empty query")
    key, config = _resolve_threat_intel("urlscan")
    base = _ti_base("urlscan", config)
    async with httpx.AsyncClient(
        timeout=timeout_s,
        headers={"API-Key": key, "Accept": "application/json", "User-Agent": "Meridian-NIP/1.0"},
    ) as c:
        r = await c.get(f"{base}/search/", params={"q": q, "size": max(1, min(size, 100))})
        r.raise_for_status()
        j = r.json() or {}
    rows = []
    for hit in j.get("results") or []:
        page = hit.get("page") or {}
        task = hit.get("task") or {}
        rows.append(
            {
                "uuid": hit.get("_id"),
                "url": page.get("url") or task.get("url"),
                "domain": page.get("domain"),
                "ip": page.get("ip"),
                "country": page.get("country"),
                "asn": page.get("asn"),
                "server": page.get("server"),
                "status": page.get("status"),
                "time": task.get("time"),
                "verdict": (hit.get("verdicts") or {}).get("overall") or {},
                "result": hit.get("result"),
            }
        )
    return {
        "query": q,
        "total": j.get("total") or len(rows),
        "rows": rows,
    }


# ============================================================================
# Shodan — host fingerprint for an IP. Free key gets you /shodan/host/<ip>.
# ============================================================================
async def shodan_lookup(ip: str, *, timeout_s: float = 20.0) -> dict[str, Any]:
    _valid_ip(ip)
    from app.safety.limits import require_token

    require_token("shodan")
    key, config = _resolve_threat_intel("shodan")
    base = _ti_base("shodan", config)
    async with httpx.AsyncClient(timeout=timeout_s, headers={"User-Agent": "Meridian-NIP/1.0"}) as c:
        r = await c.get(f"{base}/host/{ip}", params={"key": key})
        if r.status_code == 404:
            return {"ip": ip, "found": False}
        r.raise_for_status()
        j = r.json() or {}
    services = []
    for s in (j.get("data") or [])[:50]:
        services.append(
            {
                "port": s.get("port"),
                "transport": s.get("transport"),
                "product": s.get("product"),
                "version": s.get("version"),
                "module": s.get("_shodan", {}).get("module"),
                "timestamp": s.get("timestamp"),
                "banner": (s.get("data") or "")[:400],
                "hostnames": s.get("hostnames") or [],
            }
        )
    return {
        "ip": ip,
        "found": True,
        "ports": j.get("ports") or [],
        "vulns": list(j.get("vulns") or {})[:50]
        if isinstance(j.get("vulns"), dict)
        else (j.get("vulns") or [])[:50],
        "tags": j.get("tags") or [],
        "country": j.get("country_name"),
        "city": j.get("city"),
        "org": j.get("org"),
        "isp": j.get("isp"),
        "asn": j.get("asn"),
        "os": j.get("os"),
        "hostnames": j.get("hostnames") or [],
        "last_update": j.get("last_update"),
        "services": services,
        "detail_url": f"https://www.shodan.io/host/{ip}",
    }


# ============================================================================
# Censys — host fingerprint via Search v2. Uses Personal Access Token
# (Bearer auth); free tier permits ~200 requests/month on Personal API.
# ============================================================================
async def censys_lookup(ip: str, *, timeout_s: float = 20.0) -> dict[str, Any]:
    _valid_ip(ip)
    from app.safety.limits import require_token

    require_token("censys")
    token, config = _resolve_threat_intel("censys")
    base = _ti_base("censys", config)
    async with httpx.AsyncClient(
        timeout=timeout_s,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "Meridian-NIP/1.0",
        },
    ) as c:
        r = await c.get(f"{base}/hosts/{ip}")
        if r.status_code == 404:
            return {"ip": ip, "found": False}
        r.raise_for_status()
        j = r.json() or {}
    result = j.get("result") or {}
    svcs = []
    for s in (result.get("services") or [])[:50]:
        svcs.append(
            {
                "port": s.get("port"),
                "service_name": s.get("service_name"),
                "transport": s.get("transport_protocol"),
                "extended": s.get("extended_service_name"),
                "banner_sha256": (s.get("banner_hashes_sha256") or [None])[0]
                if isinstance(s.get("banner_hashes_sha256"), list)
                else None,
                "observed_at": s.get("observed_at"),
                "product": (s.get("software") or [{}])[0].get("product") if s.get("software") else None,
                "version": (s.get("software") or [{}])[0].get("version") if s.get("software") else None,
            }
        )
    loc = result.get("location") or {}
    asys = result.get("autonomous_system") or {}
    return {
        "ip": ip,
        "found": True,
        "last_updated": result.get("last_updated_at"),
        "country": (loc.get("country") or loc.get("country_code")),
        "city": loc.get("city"),
        "asn": asys.get("asn"),
        "as_name": asys.get("name"),
        "as_country": asys.get("country_code"),
        "os": ((result.get("operating_system") or {}).get("product")),
        "services": svcs,
        "detail_url": f"https://search.censys.io/hosts/{ip}",
    }
