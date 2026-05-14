"""Standalone mail-auth checkers: SPF and DKIM record parsers.

These complement the existing `mail.delivery` and `dmarc.tuning` wizards
by drilling into the *content* of SPF and DKIM TXT records, not just
"is it published". Both wizards are read-only DNS queries — they make no
authenticated calls.

SPF parser:
  * tokenise the v=spf1 record
  * follow include: / redirect= chains (one level deep)
  * count DNS-mechanism lookups (RFC 7208 §4.6.4 says >10 is invalid)
  * flag dangerous defaults (+all, ?all)
  * list resolved sender mechanisms

DKIM parser:
  * given a selector + domain, fetch <selector>._domainkey.<domain> TXT
  * parse v=DKIM1 tag soup
  * validate p= as well-formed base64 RSA / Ed25519 key
  * derive key bit length, flag weak (<2048-bit RSA)
"""

from __future__ import annotations

import base64
import re

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from app.dns.dig import DigRequest, run_dig
from app.wizards.engine import Suggestion, WizardContext, WizardStep, wizard

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# SPF mechanisms that issue a DNS query each (RFC 7208 §4.6.4 limit of 10).
_SPF_DNS_MECHANISMS = ("include:", "a", "mx", "ptr", "exists:", "redirect=")


def _txt_strings(stdout: str) -> list[str]:
    """Return TXT record contents (one per line, with surrounding quotes stripped)."""
    out: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        # dig +short returns TXTs as "abc" "def" — join the chunks.
        chunks = re.findall(r'"([^"]*)"', line)
        out.append("".join(chunks) if chunks else line)
    return out


def _count_dns_mechs(spf: str) -> int:
    n = 0
    for token in spf.split():
        t = token.lstrip("+-~?").lower()
        for m in _SPF_DNS_MECHANISMS:
            if t.startswith(m) or t == m.rstrip(":="):
                n += 1
                break
    return n


# ---------------------------------------------------------------------------
# spf.parser
# ---------------------------------------------------------------------------
@wizard("spf.parser")
async def spf_parser(ctx: WizardContext) -> list[Suggestion]:
    domain = ctx.target
    r = await run_dig(DigRequest(target=domain, record_type="TXT"))
    spf_records = [rec for rec in _txt_strings(r.stdout) if rec.startswith("v=spf1")]

    if not spf_records:
        ctx.add(WizardStep(name="SPF record", outcome="fail", message=f"No v=spf1 TXT record at {domain}."))
        return [
            Suggestion(
                priority="critical",
                title="Publish an SPF record",
                detail="Start with v=spf1 include:<provider> ~all. Move to -all once legitimate senders are enumerated.",
            )
        ]
    if len(spf_records) > 1:
        ctx.add(
            WizardStep(
                name="SPF record count",
                outcome="fail",
                message=f"{len(spf_records)} SPF records found — RFC 7208 requires exactly one. Receivers will treat this as PermError.",
                detail={"records": spf_records},
            )
        )
        return [
            Suggestion(
                priority="critical",
                title="Collapse to a single SPF record",
                detail="Merge overlapping mechanisms; remove deprecated records. Multiple v=spf1 records = automatic auth failure.",
            )
        ]

    record = spf_records[0]
    ctx.add(
        WizardStep(
            name="SPF record",
            outcome="ok",
            message=f"Single SPF record found ({len(record)} chars)",
            detail={"raw": record},
        )
    )

    tokens = record.split()
    qualifier_all = next((t for t in tokens if t.lstrip("+-~?").lower() == "all"), None)
    if qualifier_all:
        prefix = qualifier_all[0] if qualifier_all[0] in "+-~?" else "+"
        meaning = {
            "+": "pass (allows everyone — accepts forged mail)",
            "-": "hard-fail (recommended)",
            "~": "soft-fail (sandbox / spam-folder)",
            "?": "neutral (treat as if no SPF — almost as bad as +all)",
        }[prefix]
        outcome = "fail" if prefix == "+" else ("warn" if prefix == "?" else "ok")
        ctx.add(WizardStep(name=f"Final mechanism ({qualifier_all})", outcome=outcome, message=meaning))
    else:
        ctx.add(
            WizardStep(
                name="Final mechanism",
                outcome="warn",
                message="No 'all' mechanism — RFC 7208 says behaviour is implementation-defined, treat as ?all.",
            )
        )

    # DNS-lookup count, including transitive includes.
    direct = _count_dns_mechs(record)
    total = direct
    include_targets = [t.split("include:", 1)[1] for t in tokens if t.lower().startswith("include:")]
    redirect_targets = [t.split("redirect=", 1)[1] for t in tokens if t.lower().startswith("redirect=")]
    chased: dict[str, int] = {}
    for inc in include_targets + redirect_targets:
        sub = await run_dig(DigRequest(target=inc, record_type="TXT"))
        sub_recs = [s for s in _txt_strings(sub.stdout) if s.startswith("v=spf1")]
        sub_lookups = _count_dns_mechs(sub_recs[0]) if sub_recs else 0
        chased[inc] = sub_lookups
        total += sub_lookups

    ctx.add(
        WizardStep(
            name="DNS-mechanism lookup count",
            outcome="fail" if total > 10 else ("warn" if total > 8 else "ok"),
            message=f"{total} (direct={direct}, in includes/redirects={sum(chased.values())}); RFC 7208 caps at 10",
            detail={"direct": direct, "chased": chased},
        )
    )

    sug: list[Suggestion] = []
    if qualifier_all and qualifier_all.startswith("+"):
        sug.append(
            Suggestion(
                priority="critical",
                title="Replace +all with -all or ~all",
                detail="+all tells receivers every host on the internet is a legitimate sender for this domain. Switch to -all (hard fail) or ~all (soft fail) immediately.",
            )
        )
    if total > 10:
        sug.append(
            Suggestion(
                priority="critical",
                title="Reduce DNS lookups to ≤10",
                detail="Flatten includes via SPF flatteners or remove unused senders. Over the limit, every receiver short-circuits to PermError and stops evaluating.",
            )
        )
    elif total > 8:
        sug.append(
            Suggestion(
                priority="recommended",
                title="Reduce SPF lookups before hitting 10",
                detail="At 9–10 lookups you have no headroom. Adding one more provider would break SPF.",
            )
        )
    return sug


# ---------------------------------------------------------------------------
# dkim.parser
# ---------------------------------------------------------------------------
_DKIM_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")


@wizard("dkim.parser")
async def dkim_parser(ctx: WizardContext) -> list[Suggestion]:
    """Target format: "<selector>._domainkey.<domain>" or "<selector>@<domain>".

    The wizard accepts either; if the colon-free dotted form is given it's
    used as-is. The @ form is rewritten so users can type
    "google@example.com" naturally.
    """
    raw = ctx.target.strip()
    if "@" in raw:
        selector, domain = raw.split("@", 1)
        if not _DKIM_SELECTOR_RE.match(selector):
            ctx.add(
                WizardStep(
                    name="Selector",
                    outcome="fail",
                    message=f"Selector {selector!r} is not a valid DNS label.",
                )
            )
            return []
        target = f"{selector}._domainkey.{domain}"
    else:
        target = raw

    r = await run_dig(DigRequest(target=target, record_type="TXT"))
    rows = _txt_strings(r.stdout)
    dkim_rows = [row for row in rows if "v=DKIM1" in row or "p=" in row]

    if not dkim_rows:
        ctx.add(WizardStep(name="DKIM TXT record", outcome="fail", message=f"No DKIM record at {target}."))
        return [
            Suggestion(
                priority="critical",
                title="Publish the DKIM TXT record",
                detail="Your mail provider's docs will give you the v=DKIM1; k=rsa; p=… record. Until it's published, downstream receivers can't verify your DKIM signatures.",
            )
        ]

    record = dkim_rows[0]
    ctx.add(
        WizardStep(name="DKIM TXT record", outcome="ok", message=f"Found at {target}", detail={"raw": record})
    )

    tags: dict[str, str] = {}
    for piece in record.split(";"):
        piece = piece.strip()
        if "=" not in piece:
            continue
        k, v = piece.split("=", 1)
        tags[k.strip().lower()] = v.strip()

    version = tags.get("v", "")
    key_type = tags.get("k", "rsa").lower()
    pub_b64 = tags.get("p", "")
    if version and version != "DKIM1":
        ctx.add(
            WizardStep(
                name="DKIM version",
                outcome="warn",
                message=f"Unexpected v= value {version!r}; expected DKIM1.",
            )
        )
    if not pub_b64:
        ctx.add(
            WizardStep(
                name="Public key (p=)",
                outcome="fail",
                message="Empty p= tag — selector has been revoked. Senders signing with this selector will fail DKIM.",
            )
        )
        return [
            Suggestion(
                priority="critical",
                title="Restore the public key",
                detail="An empty p= explicitly signals revocation. Republish the key or rotate to a new selector.",
            )
        ]

    bits = _key_bits_or_none(pub_b64, key_type)
    bits_msg = f"{key_type.upper()} {bits}-bit" if bits else f"{key_type.upper()} (bit length undetermined)"
    if key_type == "rsa" and bits is not None and bits < 1024:
        outcome = "fail"
    elif key_type == "rsa" and bits is not None and bits < 2048:
        outcome = "warn"
    else:
        outcome = "ok"
    ctx.add(
        WizardStep(
            name="Key strength",
            outcome=outcome,
            message=bits_msg,
            detail={"key_type": key_type, "bits": bits},
        )
    )

    sug: list[Suggestion] = []
    if key_type == "rsa" and bits is not None and bits < 2048:
        sug.append(
            Suggestion(
                priority="recommended",
                title="Rotate to a 2048-bit RSA key",
                detail="Anything under 2048-bit RSA is considered weak by modern receivers. Use Ed25519 if your provider supports k=ed25519.",
            )
        )
    return sug


def _key_bits_or_none(pub_b64: str, key_type: str) -> int | None:
    try:
        der = base64.b64decode(pub_b64 + "===")  # tolerate missing padding
    except Exception:
        return None
    try:
        if key_type == "rsa":
            key = serialization.load_der_public_key(der)
            if isinstance(key, rsa.RSAPublicKey):
                return key.key_size
        elif key_type == "ed25519":
            key = serialization.load_der_public_key(der)
            if isinstance(key, ed25519.Ed25519PublicKey):
                return 256
    except (ValueError, UnsupportedAlgorithm):
        return None
    return None
