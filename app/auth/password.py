from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError


_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _hasher.verify(stored_hash, password)
        return True
    except (VerifyMismatchError, InvalidHash):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHash:
        return True
