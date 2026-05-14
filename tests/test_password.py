from __future__ import annotations

from app.auth.password import hash_password, needs_rehash, verify_password


def test_argon2_roundtrip():
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h)
    assert not verify_password("wrong", h)


def test_argon2_unique_salt():
    a = hash_password("same-password")
    b = hash_password("same-password")
    assert a != b
    assert verify_password("same-password", a)
    assert verify_password("same-password", b)


def test_needs_rehash_on_garbage():
    assert needs_rehash("not-a-real-argon2-hash") is True
