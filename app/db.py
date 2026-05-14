from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings, load_key


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(
            settings.db_dsn,
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,
            future=True,
        )

        @event.listens_for(_engine, "connect")
        def _set_hmac_key(dbapi_conn, conn_record):
            # Pin the row-HMAC key for this connection so fn_row_hmac() can
            # read it via current_setting('meridian.row_hmac_key'). This lets
            # tamper-evident triggers run without code needing to pass keys.
            try:
                key_hex = load_key(settings.row_hmac_key_path).hex()
            except RuntimeError:
                return
            cur = dbapi_conn.cursor()
            cur.execute("SELECT set_config('meridian.row_hmac_key', %s, false)", (key_hex,))
            cur.close()

    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    SessionLocal = get_sessionmaker()
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def fastapi_dep_db() -> Iterator[Session]:
    with session_scope() as s:
        yield s
