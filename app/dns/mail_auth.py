"""Parser-level SPF / DKIM / DMARC validators. Fetches the relevant
DNS record(s) via the existing dig sandbox OR validates a raw record
pasted by the user — same parser either way. Returns structured
findings the UI can render as graded rows (ok / warn / fail) with
fix hints. No opinion about policy — just whether the record itself
is syntactically sound and will behave as expected.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from app.dns.dig import DigRequest, run_dig


def _lint_spf_record(raw: str) -> dict[str, Any]:
    """Syntax-lint an already-fetched SPF record string. Shared by
    validate_spf (live domain lookup) and a paste-in linter so admins
    can vet a proposed record before publishing it."""
    findings: list[dict[str, str]] = []
    dns_lookups = 0
    include_targets: list[str] = []
    all_mech = None

    if not raw.startswith("v=spf1"):
        findings.append(
            {
                "grade": "fail",
                "check": "Missing version prefix",
                "detail": "Record must start with `v=spf1` to be recognised.",
                "fix": "Prefix with `v=spf1 ` (note the trailing space).",
            }
        )
        return {
            "raw_record": raw,
            "rows": findings,
            "worst": "fail",
            "dns_lookups": 0,
            "all_qualifier": None,
            "includes": [],
        }

    tokens = raw.split()[1:]
    for tok in tokens:
        mech = tok
        qualifier = "+"
        if mech and mech[0] in ("+", "-", "~", "?"):
            qualifier, mech = mech[0], mech[1:]
        if "=" in mech:
            name, value = mech.split("=", 1)
            if name not in _SPF_MODIFIERS:
                findings.append(
                    {
                        "grade": "warn",
                        "check": f"unknown modifier {name}",
                        "detail": f"{name}= is not a recognised SPF modifier.",
                        "fix": "Remove, or check for a typo of redirect=/exp=.",
                    }
                )
            continue
        name, _, value = mech.partition(":")
        if name not in _SPF_MECHANISMS:
            findings.append(
                {
                    "grade": "warn",
                    "check": f"unknown mechanism {name}",
                    "detail": f"{name} is not a recognised SPF mechanism.",
                    "fix": "Allowed: ip4, ip6, a, mx, ptr, exists, include, all.",
                }
            )
            continue
        if name == "all":
            all_mech = qualifier
        if name in ("include", "a", "mx", "exists", "ptr"):
            dns_lookups += 1
        if name == "include" and value:
            include_targets.append(value)

    if all_mech is None:
        findings.append(
            {
                "grade": "warn",
                "check": "Missing `all` mechanism",
                "detail": "No terminal `all` — receivers fall through to neutral.",
                "fix": "Add `~all` (softfail) or `-all` (reject).",
            }
        )
    elif all_mech == "+":
        findings.append(
            {
                "grade": "fail",
                "check": "+all is a footgun",
                "detail": "`+all` authorises every sender in the world.",
                "fix": "Change to `-all` or `~all`.",
            }
        )
    elif all_mech == "?":
        findings.append(
            {
                "grade": "warn",
                "check": "?all = neutral",
                "detail": "`?all` tells receivers to ignore the SPF result.",
                "fix": "Change to `~all` or `-all`.",
            }
        )
    else:
        findings.append(
            {
                "grade": "ok",
                "check": f"Terminal `{all_mech}all`",
                "detail": f"Good — {'reject' if all_mech == '-' else 'softfail'} on non-match.",
                "fix": "",
            }
        )

    if dns_lookups > 10:
        findings.append(
            {
                "grade": "fail",
                "check": "DNS-lookup cap exceeded",
                "detail": f"{dns_lookups} lookups in this record alone (cap is 10).",
                "fix": "Flatten include: chains or drop unused senders.",
            }
        )
    elif dns_lookups > 8:
        findings.append(
            {
                "grade": "warn",
                "check": "DNS-lookup count near cap",
                "detail": f"{dns_lookups} of 10 used.",
                "fix": "Audit includes; flatten the biggest chains.",
            }
        )

    worst = "ok"
    for f in findings:
        if f["grade"] == "fail" or (f["grade"] == "warn" and worst == "ok"):
            worst = f["grade"]
    return {
        "raw_record": raw,
        "rows": findings,
        "worst": worst,
        "dns_lookups": dns_lookups,
        "all_qualifier": all_mech,
        "includes": include_targets,
    }


def _lint_dkim_record(raw: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    tags = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = v.strip()

    if tags.get("v") and tags["v"] != "DKIM1":
        findings.append(
            {
                "grade": "warn",
                "check": f"v={tags['v']}",
                "detail": "DKIM version tag should be 'DKIM1'.",
                "fix": "Set v=DKIM1",
            }
        )
    k_type = tags.get("k", "rsa")
    if k_type not in ("rsa", "ed25519"):
        findings.append(
            {
                "grade": "fail",
                "check": f"k={k_type}",
                "detail": "Only rsa and ed25519 key types are valid.",
                "fix": "Re-generate with k=rsa or k=ed25519.",
            }
        )

    pubkey_b64 = tags.get("p", "").replace(" ", "")
    if not pubkey_b64:
        findings.append(
            {
                "grade": "warn",
                "check": "p= is empty",
                "detail": "Empty p= = selector revoked. Intentional?",
                "fix": "If this selector is still in use, publish the public key.",
            }
        )
    else:
        try:
            key_bytes = base64.b64decode(pubkey_b64 + "=" * (-len(pubkey_b64) % 4))
            findings.append(
                {
                    "grade": "ok",
                    "check": "p= base64 decodes",
                    "detail": f"Decoded to {len(key_bytes)} bytes.",
                    "fix": "",
                }
            )
            if k_type == "rsa":
                est_bits = len(key_bytes) * 8
                if est_bits < 1600:
                    findings.append(
                        {
                            "grade": "fail",
                            "check": "RSA key too weak",
                            "detail": f"~{est_bits}-bit. Gmail / M365 drop signatures below 1024.",
                            "fix": "Re-issue as RSA-2048 or larger.",
                        }
                    )
                elif est_bits < 2300:
                    findings.append(
                        {
                            "grade": "warn",
                            "check": "RSA key under 2048",
                            "detail": f"~{est_bits}-bit. RFC 8301 deprecates <2048.",
                            "fix": "Re-issue as RSA-2048 or move to Ed25519.",
                        }
                    )
                else:
                    findings.append(
                        {
                            "grade": "ok",
                            "check": "RSA key strength",
                            "detail": f"~{est_bits}-bit RSA — meets current guidance.",
                            "fix": "",
                        }
                    )
        except Exception as e:
            findings.append(
                {
                    "grade": "fail",
                    "check": "p= not valid base64",
                    "detail": f"{e}",
                    "fix": "Re-export the public key without line breaks or extra chars.",
                }
            )

    h_tag = tags.get("h")
    if h_tag and "sha256" not in h_tag:
        findings.append(
            {
                "grade": "warn",
                "check": f"h={h_tag}",
                "detail": "sha256 is required for modern DKIM.",
                "fix": "Include sha256 in h=.",
            }
        )
    if "y" in tags.get("t", ""):
        findings.append(
            {
                "grade": "warn",
                "check": "t=y (testing mode)",
                "detail": "Receivers should treat this selector as testing-only.",
                "fix": "Remove t=y once the key is live.",
            }
        )

    worst = "ok"
    for f in findings:
        if f["grade"] == "fail" or (f["grade"] == "warn" and worst == "ok"):
            worst = f["grade"]
    return {"raw_record": raw, "rows": findings, "worst": worst, "tags": tags}


def _lint_dmarc_record(raw: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    tags = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = v.strip()

    if tags.get("v") != "DMARC1":
        findings.append(
            {
                "grade": "fail",
                "check": "v= tag",
                "detail": "v=DMARC1 must be the first tag.",
                "fix": "Move v=DMARC1 to the start.",
            }
        )
    p = tags.get("p", "").lower()
    if p not in _DMARC_POLICY:
        findings.append(
            {
                "grade": "fail",
                "check": "p= missing/invalid",
                "detail": f"p={p!r} not in none/quarantine/reject.",
                "fix": "Set p=none (monitor), quarantine (soft), or reject (hard).",
            }
        )
    else:
        findings.append({"grade": "ok", "check": f"p={p}", "detail": "Policy valid.", "fix": ""})

    pct = tags.get("pct")
    if pct is not None:
        try:
            pn = int(pct)
            if pn < 0 or pn > 100:
                findings.append(
                    {
                        "grade": "fail",
                        "check": "pct= out of range",
                        "detail": f"pct={pct} must be 0–100.",
                        "fix": "Set pct to an integer in that range.",
                    }
                )
            elif pn < 100 and p == "reject":
                findings.append(
                    {
                        "grade": "warn",
                        "check": "pct<100 with p=reject",
                        "detail": "Partial reject: DMARC only evaluates when p=reject or quarantine.",
                        "fix": "Ramp pct up to 100 or keep p=quarantine.",
                    }
                )
        except ValueError:
            findings.append(
                {
                    "grade": "fail",
                    "check": "pct= not integer",
                    "detail": f"pct={pct!r} must be an integer.",
                    "fix": "Set pct to an integer.",
                }
            )

    for tag in ("rua", "ruf"):
        v = tags.get(tag, "")
        if not v:
            if tag == "rua":
                findings.append(
                    {
                        "grade": "warn",
                        "check": "rua missing",
                        "detail": "No aggregate-report URI — no DMARC reports.",
                        "fix": "Add rua=mailto:dmarc@example.com.",
                    }
                )
            continue
        for uri in v.split(","):
            uri = uri.strip()
            if not (uri.startswith("mailto:") or uri.startswith("https:")):
                findings.append(
                    {
                        "grade": "fail",
                        "check": f"{tag} URI format",
                        "detail": f"{tag} URI {uri!r} must start with mailto: or https:.",
                        "fix": "Prefix with mailto:.",
                    }
                )

    for name in ("adkim", "aspf"):
        v = tags.get(name)
        if v is not None and v.lower() not in _DMARC_ALIGN:
            findings.append(
                {
                    "grade": "fail",
                    "check": f"{name}= invalid",
                    "detail": f"{name}={v} must be r or s.",
                    "fix": f"Set {name}=r or {name}=s.",
                }
            )
    sp = tags.get("sp")
    if sp is not None and sp.lower() not in _DMARC_POLICY:
        findings.append(
            {
                "grade": "fail",
                "check": "sp= invalid",
                "detail": f"sp={sp!r} must be none/quarantine/reject.",
                "fix": "Set sp= to one of them.",
            }
        )

    if len(tags) < 2 and len(raw) > 20:
        findings.append(
            {
                "grade": "fail",
                "check": "Record unparsable",
                "detail": "Only one tag parsed — likely missing semicolons.",
                "fix": "Separate tags with `; `.",
            }
        )

    worst = "ok"
    for f in findings:
        if f["grade"] == "fail" or (f["grade"] == "warn" and worst == "ok"):
            worst = f["grade"]
    return {"raw_record": raw, "rows": findings, "worst": worst, "tags": tags, "policy": p}


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------
def _txt_answers(stdout: str) -> list[str]:
    """Return TXT record values with enclosing quotes stripped, chunks joined."""
    out = []
    for line in stdout.splitlines():
        s = line.strip()
        if not s or s.startswith(";"):
            continue
        # dig +short wraps TXT chunks in double-quotes and may split
        # long values into multiple "chunk1" "chunk2" segments on one
        # line. Join them.
        chunks = re.findall(r'"([^"]*)"', s)
        out.append("".join(chunks) if chunks else s)
    return out


# ===========================================================================
# SPF
# ===========================================================================
_SPF_MECHANISMS = {"all", "ip4", "ip6", "a", "mx", "ptr", "exists", "include"}
_SPF_MODIFIERS = {"redirect", "exp"}


async def validate_spf(domain: str) -> dict[str, Any]:
    """Fetch + parse SPF. Counts DNS lookups (RFC 7208 §4.6.4 cap of 10),
    follows `include:` chains, flags `+all` / `?all` footguns, reports
    the effective mechanism list."""
    r = await run_dig(DigRequest(target=domain, record_type="TXT"))
    spf_records = [t for t in _txt_answers(r.stdout) if t.startswith("v=spf1")]

    if not spf_records:
        return {
            "domain": domain,
            "found": False,
            "rows": [],
            "rows_total": 0,
            "worst": "fail",
            "summary": f"No v=spf1 record found for {domain}.",
        }

    raw = spf_records[0]
    lint = _lint_spf_record(raw)
    findings: list[dict[str, str]] = list(lint["rows"])

    if len(spf_records) > 1:
        findings.insert(
            0,
            {
                "grade": "fail",
                "check": "Single record",
                "detail": f"{len(spf_records)} SPF records found — RFC 7208 requires exactly one. Receivers will reject.",
                "fix": "Merge the separate entries into a single TXT record.",
            },
        )

    # Follow include: chains so the lookup count reflects the real
    # evaluation cost (single-record lint only counts immediate lookups).
    async def _count_include_lookups(target: str, depth: int) -> int:
        if depth >= 3:
            return 0
        r = await run_dig(DigRequest(target=target, record_type="TXT"))
        rec = next((t for t in _txt_answers(r.stdout) if t.startswith("v=spf1")), None)
        if not rec:
            return 0
        toks = rec.split()[1:]
        extra = 0
        for t in toks:
            if t and t[0] in "+-~?":
                t = t[1:]
            n, _, v = t.partition(":")
            if n in ("include", "a", "mx", "exists", "ptr"):
                extra += 1
            if n == "include" and v:
                extra += await _count_include_lookups(v, depth + 1)
        return extra

    dns_lookups = lint["dns_lookups"]
    for inc in lint["includes"]:
        dns_lookups += await _count_include_lookups(inc, 1)

    # Strip the single-record lint's dns_lookups finding (if any) so we
    # can re-issue one with the full recursive count.
    findings = [f for f in findings if "DNS-lookup" not in f.get("check", "")]
    if dns_lookups > 10:
        findings.append(
            {
                "grade": "fail",
                "check": "DNS-lookup cap exceeded",
                "detail": f"SPF evaluation requires {dns_lookups} DNS lookups — the RFC 7208 cap is 10. Receivers return permerror and your mail is DMARC-failed.",
                "fix": "Flatten one or more include: chains, or drop unused senders.",
            }
        )
    elif dns_lookups > 8:
        findings.append(
            {
                "grade": "warn",
                "check": "DNS-lookup count near cap",
                "detail": f"{dns_lookups} of 10 lookups used. Adding another `include:` is likely to tip you over.",
                "fix": "Audit includes; flatten the biggest chains.",
            }
        )
    else:
        findings.append(
            {
                "grade": "ok",
                "check": "DNS-lookup count",
                "detail": f"{dns_lookups} of 10 lookups used.",
                "fix": "",
            }
        )

    worst = "ok"
    for f in findings:
        if f["grade"] == "fail" or (f["grade"] == "warn" and worst == "ok"):
            worst = f["grade"]

    return {
        "domain": domain,
        "found": True,
        "raw_record": raw,
        "dns_lookups": dns_lookups,
        "includes": lint["includes"],
        "all_qualifier": lint["all_qualifier"],
        "rows": findings,
        "worst": worst,
    }


# ===========================================================================
# DKIM
# ===========================================================================
async def validate_dkim(domain: str, selector: str) -> dict[str, Any]:
    """Fetch `<selector>._domainkey.<domain>` TXT, parse key+flags,
    validate base64, report key bit-length."""
    host = f"{selector}._domainkey.{domain}"
    r = await run_dig(DigRequest(target=host, record_type="TXT"))
    records = [t for t in _txt_answers(r.stdout) if "v=DKIM1" in t or "k=" in t or "p=" in t]
    if not records:
        return {
            "domain": domain,
            "selector": selector,
            "host": host,
            "found": False,
            "rows": [],
            "worst": "fail",
            "summary": f"No DKIM key at {host}. Check the selector spelling.",
        }
    raw = records[0]
    lint = _lint_dkim_record(raw)
    return {
        "domain": domain,
        "selector": selector,
        "host": host,
        "found": True,
        "raw_record": raw,
        "tags": lint["tags"],
        "rows": lint["rows"],
        "worst": lint["worst"],
    }


# ===========================================================================
# DMARC
# ===========================================================================
_DMARC_TAGS_REQUIRED = {"v", "p"}
_DMARC_POLICY = {"none", "quarantine", "reject"}
_DMARC_ALIGN = {"r", "s"}


async def validate_dmarc(domain: str) -> dict[str, Any]:
    """Fetch `_dmarc.<domain>` TXT and lint the policy string."""
    host = f"_dmarc.{domain}"
    r = await run_dig(DigRequest(target=host, record_type="TXT"))
    records = [t for t in _txt_answers(r.stdout) if "v=DMARC1" in t]
    if not records:
        return {
            "domain": domain,
            "host": host,
            "found": False,
            "rows": [],
            "worst": "fail",
            "summary": f"No DMARC record at {host}. Start with `v=DMARC1; p=none; rua=mailto:...`.",
        }
    raw = records[0]
    lint = _lint_dmarc_record(raw)
    return {
        "domain": domain,
        "host": host,
        "found": True,
        "raw_record": raw,
        "tags": lint["tags"],
        "policy": lint["policy"],
        "rows": lint["rows"],
        "worst": lint["worst"],
    }
