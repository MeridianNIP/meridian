"""PII redaction for audit payloads.

Scrubs likely-sensitive substrings from `payload` dicts before they hit
`audit_events.payload`. The point is defence-in-depth: a route handler
might log a request body verbatim and accidentally include a recovery
email, a bearer token, or a card number. Redaction here ensures that
even if the upstream sloppy logging happens, the audit table doesn't
become a PII reservoir.

What's redacted:

  - Email addresses           → `<email:redacted>`
  - E.164 / 10-digit phones   → `<phone:redacted>`
  - Credit-card-ish 13–19     → `<cc:redacted>` (Luhn-validated to
                                   avoid clobbering harmless long numbers)
  - Bearer / API tokens       → `<token:redacted>`
  - JWT-shaped strings        → `<jwt:redacted>`
  - Long hex/b64 secrets      → `<secret:redacted>` (>=32 chars,
                                   high-entropy heuristic)
  - Keys named password/token/secret/api_key/auth/session → value masked

Not redacted (intentional): IP addresses (we want those in audit),
usernames (operationally important), UUIDs (no PII risk), filenames.
"""

from __future__ import annotations

import re
from typing import Any

# Order matters — JWT pattern is more specific than the generic
# bearer-token pattern, so JWT runs first.

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Phones must have an actual separator (space/dash/dot/parens) or a `+`
# country-code prefix. A bare 10/12-digit run with no separators is too
# easily a UUID tail, order ID, or hash — those would generate false
# positives if redacted as phones.
_PHONE_RE = re.compile(
    r"(?<!\d)(?:"
    r"\+\d{1,3}[\s\-.]?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}"  # +1 (555) 123-4567
    r"|\(\d{3}\)\s?\d{3}[\s\-.]?\d{4}"  # (555) 123-4567
    r"|\d{3}[\s\-.]\d{3}[\s\-.]\d{4}"  # 555-123-4567 (separators required)
    r")(?!\d)"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")
_BEARER_RE = re.compile(r"\b(?:Bearer|Token)\s+[A-Za-z0-9._\-]{16,}\b", re.IGNORECASE)
_CC_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{40,}\b")

# Dict keys whose values are always masked regardless of content.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "client_secret",
        "auth_token",
        "session_token",
        "session",
        "api_key",
        "apikey",
        "x-api-key",
        "authorization",
        "totp_secret",
        "mfa_secret",
        "backup_code",
        "backup_codes",
        "private_key",
        "privkey",
        "ed25519_private",
        "recovery_email",
        "recovery_phone",  # keep these out of audit too
        "ssn",
        "tax_id",
        "passport",
    }
)


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact_string(s: str) -> str:
    if not s:
        return s
    s = _JWT_RE.sub("<jwt:redacted>", s)
    s = _BEARER_RE.sub("<token:redacted>", s)
    s = _EMAIL_RE.sub("<email:redacted>", s)

    # Credit-card pattern matches 13-19 digit runs; only redact those that
    # pass Luhn so a bare 16-digit order ID doesn't get clobbered.
    def _cc(m: re.Match) -> str:
        return "<cc:redacted>" if _luhn_ok(m.group(0)) else m.group(0)

    s = _CC_RE.sub(_cc, s)
    s = _PHONE_RE.sub("<phone:redacted>", s)
    # Hex/B64 secrets — only redact if the run is long enough AND doesn't
    # look like a UUID (UUIDs are 32 hex with dashes — already excluded by
    # \b). Anything 40+ chars in pure b64 alphabet is treated as a secret.
    s = _HEX_RE.sub(lambda m: "<secret:redacted>" if len(m.group(0)) >= 40 else m.group(0), s)
    s = _B64_RE.sub(lambda m: "<secret:redacted>" if len(m.group(0)) >= 48 else m.group(0), s)
    return s


def redact(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    """Recursively redact a JSON-like value. `key` is the parent key (so
    `password: "x"` can be masked entirely without pattern-matching)."""
    if depth > 16:
        return "<truncated:max_depth>"
    if key and key.lower() in _SENSITIVE_KEYS:
        if value is None or value == "":
            return value
        return "<redacted>"
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, dict):
        return {k: redact(v, key=k, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, key=key, depth=depth + 1) for v in value]
    return value
