from __future__ import annotations

import hashlib
import os
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings, load_key


_NONCE_LEN = 12


@lru_cache(maxsize=1)
def _master_key() -> bytes:
    return load_key(get_settings().master_key_path)


def _derive(domain: bytes) -> bytes:
    # Per-domain subkey via HKDF-lite (HMAC-SHA256 extract-and-expand).
    # Keeps vault / mfa / tls-private-key isolated even under the same master.
    return hashlib.sha256(b"meridian-v1|" + domain + b"|" + _master_key()).digest()


def encrypt_field(plaintext: bytes, *, domain: bytes = b"vault") -> bytes:
    key = _derive(domain)
    nonce = os.urandom(_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=domain)
    return nonce + ct


def decrypt_field(ciphertext: bytes, *, domain: bytes = b"vault") -> bytes:
    if len(ciphertext) <= _NONCE_LEN:
        raise ValueError("ciphertext too short")
    key = _derive(domain)
    nonce, ct = ciphertext[:_NONCE_LEN], ciphertext[_NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ct, associated_data=domain)
