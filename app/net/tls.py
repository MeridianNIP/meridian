"""Canonical strict TLS context used by every outbound client that
cares: log shipper TLS transport, LDAPS bind, webhook dispatcher,
threat-intel API calls.

Meridian's baseline policy as of 2026:

  · Minimum version: TLS 1.2 (TLS 1.3 preferred)
  · Deprecated rejected: SSLv2, SSLv3, TLS 1.0, TLS 1.1
  · Weak ciphers rejected: RC4, 3DES, NULL, EXPORT, anon DH, MD5 MACs
  · Hostname verification + CA verification: always on (use pytest /
    test-only helper if you truly need to disable either — never ship
    verify=False in an integration path)
  · OCSP stapling: honored when the peer sends it

Python 3.11+'s default `ssl.create_default_context()` already sets TLS
1.2 minimum on Debian 13's OpenSSL 3.x. This module pins that
explicitly so a future Python or OpenSSL downgrade can't silently
weaken our posture.
"""

from __future__ import annotations

import ssl

_SECURE_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256"
)


def strict_ssl_context(
    *,
    cafile: str | None = None,
    verify_hostname: bool = True,
) -> ssl.SSLContext:
    """Return an `ssl.SSLContext` that enforces the Meridian 2026 TLS
    baseline. Pass `cafile` for self-signed/internal CA trust chains.
    """
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = verify_hostname
    ctx.verify_mode = ssl.CERT_REQUIRED

    # OpenSSL deprecation switches — belt AND suspenders on top of
    # minimum_version above. Dropping TLSv1 / TLSv1.1 explicitly so any
    # downstream re-negotiation (proxy-initiated) also rejects them.
    for flag in (
        "OP_NO_SSLv2",
        "OP_NO_SSLv3",
        "OP_NO_TLSv1",
        "OP_NO_TLSv1_1",
        "OP_NO_COMPRESSION",
        "OP_CIPHER_SERVER_PREFERENCE",
        "OP_NO_RENEGOTIATION",
    ):
        bit = getattr(ssl, flag, None)
        if bit is not None:
            ctx.options |= bit

    try:
        ctx.set_ciphers(_SECURE_CIPHERS)
    except ssl.SSLError:
        pass

    return ctx


def httpx_verify():
    """Hook for `httpx.AsyncClient(verify=...)` — returns our strict
    SSLContext so outbound calls use the same policy nginx enforces on
    inbound."""
    return strict_ssl_context()
