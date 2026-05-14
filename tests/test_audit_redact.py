"""Unit tests for app.audit.redact — verifies PII patterns don't slip
through and harmless data isn't clobbered."""
from app.audit.redact import redact, redact_string


def test_email_is_redacted():
    assert "<email:redacted>" in redact_string("contact alice@example.com")


def test_phone_is_redacted():
    assert "<phone:redacted>" in redact_string("call +1 (555) 123-4567")


def test_jwt_is_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dummy_signature_here"
    assert "<jwt:redacted>" in redact_string(f"token={jwt}")


def test_bearer_token_is_redacted():
    out = redact_string("Authorization: Bearer abc123def456ghi789jkl012")
    assert "<token:redacted>" in out


def test_valid_credit_card_is_redacted():
    # Luhn-valid test number
    out = redact_string("card 4532015112830366")
    assert "<cc:redacted>" in out


def test_random_long_digit_string_is_not_redacted_as_cc():
    # Not Luhn-valid → leave alone (might be an order ID)
    out = redact_string("order id 1234567890123456")
    assert "<cc:redacted>" not in out


def test_sensitive_keys_are_masked():
    d = {"password": "hunter2", "api_key": "abc", "username": "alice"}
    out = redact(d)
    assert out["password"] == "<redacted>"
    assert out["api_key"] == "<redacted>"
    assert out["username"] == "alice"


def test_recovery_email_is_masked_by_key():
    out = redact({"recovery_email": "rescue@example.com"})
    assert out["recovery_email"] == "<redacted>"


def test_nested_redaction():
    d = {"outer": {"password": "x", "note": "email me at foo@bar.com"}}
    out = redact(d)
    assert out["outer"]["password"] == "<redacted>"
    assert "<email:redacted>" in out["outer"]["note"]


def test_ip_addresses_are_NOT_redacted():
    # IPs are valuable in audit; make sure we don't accidentally scrub them.
    out = redact_string("source 192.168.1.42 connected")
    assert "192.168.1.42" in out


def test_uuid_is_NOT_redacted():
    out = redact_string("session 550e8400-e29b-41d4-a716-446655440000")
    assert "550e8400-e29b-41d4-a716-446655440000" in out


def test_empty_and_none_pass_through():
    assert redact(None) is None
    assert redact("") == ""
    assert redact({}) == {}
