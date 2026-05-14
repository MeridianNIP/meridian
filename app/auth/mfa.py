from __future__ import annotations

import secrets

import pyotp

from app.secrets_vault.vault import decrypt_field, encrypt_field


def generate_totp_secret() -> str:
    return pyotp.random_base32(length=32)


def provisioning_uri(username: str, secret: str, *, issuer: str = "Meridian") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    if not code or not code.isdigit() or len(code) not in (6, 8):
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def encrypt_totp_secret(secret: str) -> bytes:
    return encrypt_field(secret.encode(), domain=b"mfa")


def decrypt_totp_secret(blob: bytes) -> str:
    return decrypt_field(blob, domain=b"mfa").decode()


def generate_backup_codes(n: int = 10) -> list[str]:
    return [_format_backup_code(secrets.token_hex(5)) for _ in range(n)]


def _format_backup_code(raw_hex: str) -> str:
    # 10 chars split as 5-5 for readability
    return f"{raw_hex[:5]}-{raw_hex[5:]}"
