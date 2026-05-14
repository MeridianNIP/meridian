"""Account-recovery support: security-question setup + 3-of-5 challenge
verification + one-time password reset tokens.

Recovery is INTENTIONALLY layered:

  forgotten password
      -> answer 3 of 5 security questions  (proves identity)
      -> receive a short-lived reset token (proves they also control the
         email address + that the challenge itself completed in a fresh
         session)
      -> use the token to set a new password

Just security-questions-alone is a weak authenticator; pairing with a
single-use token + aggressive rate limiting brings it up to reasonable.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
import hashlib
import re
import secrets
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.auth.password import hash_password as _argon_hash
from app.auth.password import verify_password as _argon_verify

# Questions the UI offers. Users can also write custom ones (with light
# guardrails — see validate_custom_question). Curated to mix personal-
# but-not-commonly-public facts with non-PII-exposing ones.
QUESTION_LIBRARY: tuple[str, ...] = (
    "Name of the street you grew up on",
    "Name of your first pet",
    "Name of the first school you attended",
    "Make and model of your first car",
    "Name of the town where your parents met",
    "Your favorite teacher's last name",
    "Name of the hospital you were born in",
    "Nickname your family called you as a child",
    "Model of your first mobile phone",
    "Year you moved to your current city",
    "Name of your favorite childhood book",
    "Name of a place you would like to visit",
    "Your favorite concert or live performance",
    "First concert or show you attended",
    "Maker of your first watch or wristband",
)

# Common questions we refuse as custom entries because they're trivially
# OSINT-able or effectively public info.
_WEAK_CUSTOM_PATTERNS = (
    r"mother.*maiden",
    r"father.*maiden",
    r"birth.*date|date.*birth|dob",
    r"social.*security|ssn",
    r"favorite color",
    r"favorite food",
    r"high school name",
)

_MIN_CUSTOM_LEN = 25
_MAX_CUSTOM_LEN = 150
_MIN_ANSWER_LEN = 2
_MAX_ANSWER_LEN = 200


def validate_custom_question(q: str) -> None:
    q = (q or "").strip()
    if len(q) < _MIN_CUSTOM_LEN:
        raise ValueError(f"custom questions must be at least {_MIN_CUSTOM_LEN} characters")
    if len(q) > _MAX_CUSTOM_LEN:
        raise ValueError(f"custom questions must be at most {_MAX_CUSTOM_LEN} characters")
    low = q.lower()
    for pat in _WEAK_CUSTOM_PATTERNS:
        if re.search(pat, low):
            raise ValueError(
                "this custom question is too guessable (mother's maiden name, "
                "DOB, SSN, etc.) — pick something an attacker can't OSINT "
                "from your public social profile"
            )


# Normalize before hash/verify so "Rex", " rex ", "REX", "Rex  Jr" and
# "rex jr" all compare equal. Accept case / punctuation differences is the
# whole point of the feature.
_WHITESPACE = re.compile(r"\s+")
_PUNCTUATION = re.compile(r"[^\w\s]")


def normalize_answer(raw: str) -> str:
    if raw is None:
        return ""
    s = raw.strip().lower()
    s = _PUNCTUATION.sub(" ", s)
    s = _WHITESPACE.sub(" ", s).strip()
    return s


def hash_answer(raw: str) -> str:
    norm = normalize_answer(raw)
    if len(norm) < _MIN_ANSWER_LEN:
        raise ValueError(
            f"answers must be at least {_MIN_ANSWER_LEN} characters after "
            f"normalization; got {len(norm)!r}"
        )
    if len(norm) > _MAX_ANSWER_LEN:
        raise ValueError(f"answers must be at most {_MAX_ANSWER_LEN} characters")
    # Argon2id — same tuning as passwords. Separate domain is implicit because
    # we never compare a password hash against an answer hash.
    return _argon_hash(norm)


def verify_answer(raw: str, stored_hash: str) -> bool:
    try:
        return _argon_verify(normalize_answer(raw), stored_hash)
    except Exception:
        return False


# -----------------------------------------------------------------------------
# DB helpers — thin wrappers so routes don't write raw SQL.
# -----------------------------------------------------------------------------
def is_enrolled(db: OrmSession, user_id: uuid.UUID) -> bool:
    r = db.execute(
        text("SELECT count(*) FROM user_recovery_questions WHERE user_id = :u"),
        {"u": user_id},
    ).scalar_one()
    return int(r) == 5


def list_questions(db: OrmSession, user_id: uuid.UUID) -> list[dict]:
    rows = db.execute(
        text("""
            SELECT position, question_text, updated_at
              FROM user_recovery_questions
             WHERE user_id = :u
             ORDER BY position
        """),
        {"u": user_id},
    ).fetchall()
    return [
        {"position": int(r[0]), "question": r[1], "updated_at": r[2].isoformat() if r[2] else None}
        for r in rows
    ]


def save_questions(db: OrmSession, user_id: uuid.UUID, items: Iterable[tuple[str, str]]) -> None:
    """items: sequence of (question_text, raw_answer) exactly 5 long."""
    items = list(items)
    if len(items) != 5:
        raise ValueError("account recovery requires exactly 5 questions")
    seen_q: set[str] = set()
    seen_a: set[str] = set()
    for q, a in items:
        if not q or not q.strip():
            raise ValueError("question text cannot be empty")
        if q in QUESTION_LIBRARY:
            pass  # library questions skip the length check
        else:
            validate_custom_question(q)
        qn = q.strip().lower()
        if qn in seen_q:
            raise ValueError(f"duplicate question: {q!r}")
        seen_q.add(qn)
        an = normalize_answer(a)
        if an in seen_a:
            raise ValueError("two questions have the same answer — pick different answers")
        seen_a.add(an)

    # Wipe + write. Simple; setup is rare enough that optimizing diff writes
    # isn't worth the complexity.
    db.execute(text("DELETE FROM user_recovery_questions WHERE user_id = :u"), {"u": user_id})
    for i, (q, a) in enumerate(items, start=1):
        db.execute(
            text("""
                INSERT INTO user_recovery_questions
                    (user_id, position, question_text, answer_hash)
                VALUES (:u, :p, :q, :h)
            """),
            {"u": user_id, "p": i, "q": q.strip(), "h": hash_answer(a)},
        )


def pick_challenge(db: OrmSession, user_id: uuid.UUID) -> list[dict]:
    """Return 3 random positions + question texts. Callers must store the
    positions server-side (we don't trust the client to return the same 3)."""
    rows = db.execute(
        text("""
            SELECT position, question_text
              FROM user_recovery_questions
             WHERE user_id = :u
             ORDER BY random()
             LIMIT 3
        """),
        {"u": user_id},
    ).fetchall()
    return [{"position": int(r[0]), "question": r[1]} for r in rows]


def verify_challenge(db: OrmSession, user_id: uuid.UUID, answers: dict[int, str]) -> bool:
    """answers: {position: raw_answer}. All supplied positions must hash-match."""
    if not answers:
        return False
    rows = db.execute(
        text("""
            SELECT position, answer_hash
              FROM user_recovery_questions
             WHERE user_id = :u AND position = ANY(:positions)
        """),
        {"u": user_id, "positions": list(answers.keys())},
    ).fetchall()
    stored = {int(r[0]): r[1] for r in rows}
    if len(stored) != len(answers):
        return False
    for pos, raw in answers.items():
        h = stored.get(int(pos))
        if not h or not verify_answer(raw, h):
            return False
    return True


# -----------------------------------------------------------------------------
# Rate limiting.
# -----------------------------------------------------------------------------
def recent_failures(db: OrmSession, user_id: uuid.UUID, window_min: int = 15) -> int:
    cutoff = datetime.now(UTC) - timedelta(minutes=window_min)
    return int(
        db.execute(
            text("""
            SELECT count(*) FROM user_recovery_attempts
             WHERE user_id = :u AND outcome = 'fail' AND attempted_at >= :c
        """),
            {"u": user_id, "c": cutoff},
        ).scalar_one()
    )


def record_attempt(db: OrmSession, user_id: uuid.UUID, *, outcome: str, ip: str | None = None) -> None:
    db.execute(
        text("""
            INSERT INTO user_recovery_attempts (user_id, ip, outcome)
            VALUES (:u, :ip, :o)
        """),
        {"u": user_id, "ip": ip, "o": outcome},
    )


# -----------------------------------------------------------------------------
# Password-reset tokens (one-time, 30-minute validity).
# -----------------------------------------------------------------------------
RESET_TOKEN_TTL_MIN = 30


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint_reset_token(
    db: OrmSession, user_id: uuid.UUID, *, ip: str | None = None, user_agent: str | None = None
) -> str:
    token = secrets.token_urlsafe(32)
    db.execute(
        text("""
            INSERT INTO password_reset_tokens
                (token_hash, user_id, expires_at, ip, user_agent)
            VALUES (:h, :u, :e, :ip, :ua)
        """),
        {
            "h": _hash_token(token),
            "u": user_id,
            "e": datetime.now(UTC) + timedelta(minutes=RESET_TOKEN_TTL_MIN),
            "ip": ip,
            "ua": user_agent,
        },
    )
    return token


def consume_reset_token(db: OrmSession, token: str) -> uuid.UUID | None:
    """Returns the user_id if the token is valid + unused + unexpired and
    marks it used in the same transaction. Returns None otherwise."""
    row = db.execute(
        text("""
            SELECT user_id, expires_at, used_at
              FROM password_reset_tokens
             WHERE token_hash = :h
        """),
        {"h": _hash_token(token)},
    ).fetchone()
    if row is None:
        return None
    user_id, expires_at, used_at = row
    now = datetime.now(UTC)
    if used_at is not None:
        return None
    if expires_at <= now:
        return None
    db.execute(
        text("UPDATE password_reset_tokens SET used_at = :n WHERE token_hash = :h"),
        {"n": now, "h": _hash_token(token)},
    )
    return user_id
