from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass(frozen=True)
class CertInfo:
    common_name: str
    sans: list[str]
    issuer: str
    serial_hex: str
    fingerprint_sha256: str
    valid_from: datetime
    valid_until: datetime
    key_type: str
    key_size: int
    signature_alg: str
    leaf_pem: str
    days_remaining: int


def parse_pem(pem_bytes: bytes) -> CertInfo:
    """Parse a PEM-encoded certificate and return its metadata.

    Accepts either bytes or str. Raises ValueError on malformed input.
    """
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode()

    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except ValueError as e:
        raise ValueError(f"not a valid PEM certificate: {e}") from e

    cn = ""
    for attr in cert.subject:
        if attr.oid == NameOID.COMMON_NAME:
            cn = str(attr.value)
            break

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = san_ext.value
        sans = [str(v) for v in san.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        pass

    issuer_parts = [f"{a.oid._name}={a.value}" for a in cert.issuer]
    issuer = ", ".join(issuer_parts)

    fingerprint = hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest().upper()
    fp_formatted = ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type = "RSA"
        key_size = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type = f"ECDSA {pub.curve.name}"
        key_size = pub.curve.key_size
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type = "Ed25519"
        key_size = 256
    else:
        key_type = type(pub).__name__
        key_size = 0

    valid_from = cert.not_valid_before_utc
    valid_until = cert.not_valid_after_utc
    days_remaining = max(0, (valid_until - datetime.now(timezone.utc)).days)

    return CertInfo(
        common_name=cn,
        sans=sans,
        issuer=issuer,
        serial_hex=format(cert.serial_number, "x"),
        fingerprint_sha256=fp_formatted,
        valid_from=valid_from,
        valid_until=valid_until,
        key_type=key_type,
        key_size=key_size,
        signature_alg=cert.signature_algorithm_oid._name,
        leaf_pem=pem_bytes.decode(),
        days_remaining=days_remaining,
    )


def normalize_key_type(key_type: str | None, key_size: int | None) -> str | None:
    """Map parser-level key descriptions (e.g. ``"ECDSA secp256r1"``) to the
    ``cert_key_type`` Postgres enum values (``ecdsa_p256`` etc.).

    Returns ``None`` for anything we don't store in the enum — the caller
    should store None rather than crash the INSERT. Used by the watchlist
    + upload code paths.
    """
    if not key_type:
        return None
    k = key_type.lower()
    if k == "rsa" and key_size:
        if key_size >= 4096: return "rsa4096"
        if key_size >= 3072: return "rsa3072"
        if key_size >= 2048: return "rsa2048"
        return None
    if "ecdsa" in k or "ec" in k or "secp" in k:
        # Curve name encodes the bit size: secp256r1 / prime256v1 → 256.
        if "256" in k or key_size == 256: return "ecdsa_p256"
        if "384" in k or key_size == 384: return "ecdsa_p384"
        return None
    if "ed25519" in k:
        return "ed25519"
    return None
