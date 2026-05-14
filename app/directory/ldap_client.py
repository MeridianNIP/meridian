from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import ssl
from typing import Any
import uuid

from ldap3 import Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.models.directory import DirectoryIntegration
from app.secrets_vault.vault import decrypt_field

# Attribute lists we request by default. Trimming keeps LDAP responses small.
_USER_ATTRS = [
    "sAMAccountName",
    "userPrincipalName",
    "cn",
    "displayName",
    "mail",
    "givenName",
    "sn",
    "title",
    "department",
    "company",
    "manager",
    "telephoneNumber",
    "mobile",
    "physicalDeliveryOfficeName",
    "memberOf",
    "userAccountControl",
    "pwdLastSet",
    "accountExpires",
    "lastLogonTimestamp",
    "whenCreated",
    "whenChanged",
    "distinguishedName",
    "objectSid",
    "objectGUID",
]

_GROUP_ATTRS = [
    "cn",
    "sAMAccountName",
    "displayName",
    "description",
    "member",
    "managedBy",
    "groupType",
    "distinguishedName",
    "whenCreated",
]


# userAccountControl flag decoding — the most commonly-checked bits.
_UAC_FLAGS = {
    0x0002: "disabled",
    0x0010: "locked_out",
    0x0020: "password_notrequired",
    0x0040: "password_cant_change",
    0x0200: "normal_account",
    0x10000: "dont_expire_password",
    0x40000: "smartcard_required",
    0x80000: "trusted_for_delegation",
    0x800000: "password_expired",
}


@dataclass(frozen=True)
class TestResult:
    ok: bool
    latency_ms: int
    server: str
    error: str | None = None


def _decode_uac(uac_val: int | None) -> list[str]:
    if not uac_val:
        return []
    return [name for bit, name in _UAC_FLAGS.items() if uac_val & bit]


def _decode_filetime(ft: int | None) -> datetime | None:
    # AD stores timestamps as 100ns intervals since 1601-01-01. 0 and MAX-INT
    # both mean "never".
    if ft in (None, 0, 0x7FFFFFFFFFFFFFFF):
        return None
    seconds = ft / 10_000_000 - 11_644_473_600
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _serialize_entry(entry: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for attr, val in entry.entry_attributes_as_dict.items():
        if isinstance(val, list) and len(val) == 1:
            val = val[0]
        if isinstance(val, bytes):
            val = val.hex()
        if hasattr(val, "isoformat"):
            val = val.isoformat()
        out[attr] = val
    if "userAccountControl" in out:
        try:
            out["_uac_flags"] = _decode_uac(int(out["userAccountControl"]))
        except (TypeError, ValueError):
            pass
    if "accountExpires" in out:
        out["_account_expires"] = (
            _decode_filetime(int(out["accountExpires"])).isoformat()
            if isinstance(out["accountExpires"], (int, str)) and _decode_filetime(int(out["accountExpires"]))
            else None
        )
    out["dn"] = getattr(entry, "entry_dn", None) or out.get("distinguishedName")
    return out


class LDAPClient:
    """Thin wrapper around ldap3. One instance per integration.

    Not designed for a long-lived connection pool yet — one connection per
    request is fine for the volume Meridian operates at (single-digit QPS).
    """

    def __init__(self, integ: DirectoryIntegration, bind_password: str | None):
        self.integ = integ
        self.bind_password = bind_password
        self.server = Server(
            integ.primary_uri,
            use_ssl=integ.primary_uri and integ.primary_uri.startswith("ldaps://"),
            # Pin LDAPS to TLS 1.2+ with cert verification. ldap3's Tls()
            # takes a version enum; PROTOCOL_TLS_CLIENT negotiates the
            # best the server supports without allowing TLS 1.0/1.1.
            tls=Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS_CLIENT,
                ca_certs_file=integ.ca_cert_path,
            )
            if integ.ca_cert_path
            else Tls(
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS_CLIENT,
            ),
            get_info="ALL",
        )

    def _connect(self) -> Connection:
        conn = Connection(
            self.server,
            user=self.integ.bind_account,
            password=self.bind_password,
            authentication="SIMPLE",
            receive_timeout=self.integ.query_timeout_s,
            auto_bind=True,
            raise_exceptions=True,
        )
        return conn

    def test(self) -> TestResult:
        import time

        started = time.monotonic()
        try:
            with self._connect() as conn:
                ok = conn.bound
            return TestResult(
                ok=ok,
                latency_ms=int((time.monotonic() - started) * 1000),
                server=self.integ.primary_uri or "",
            )
        except LDAPException as e:
            return TestResult(
                ok=False,
                latency_ms=int((time.monotonic() - started) * 1000),
                server=self.integ.primary_uri or "",
                error=f"{type(e).__name__}: {e}",
            )

    def search_user(self, query: str, *, limit: int = 25) -> list[dict]:
        # Match against common identity attributes. Escape parentheses / backslashes
        # to avoid filter injection.
        safe = query.translate(
            str.maketrans({"(": r"\28", ")": r"\29", "\\": r"\5c", "*": r"\2a", "\x00": r"\00"})
        )
        filt = (
            f"(&(objectClass=user)(!(objectClass=computer))"
            f"(|(sAMAccountName=*{safe}*)"
            f"(userPrincipalName=*{safe}*)"
            f"(mail=*{safe}*)"
            f"(displayName=*{safe}*)"
            f"(cn=*{safe}*)))"
        )
        with self._connect() as conn:
            conn.search(
                search_base=self.integ.base_dn,
                search_filter=filt,
                attributes=_USER_ATTRS,
                size_limit=limit,
            )
            return [_serialize_entry(e) for e in conn.entries]

    def authenticate_user(self, username: str, password: str) -> dict | None:
        """Bind as the user (with their password) to prove identity.

        Two-step flow:
        1. Service bind (using the integration's bind account) to find
           the user's DN + memberOf. Filter matches sAMAccountName,
           userPrincipalName, or mail so users can log in with any of
           the common AD identifiers.
        2. Fresh bind using the user's DN + submitted password to
           confirm the credential. On failure returns None; on success
           returns the dict of attributes (including memberOf).

        Empty password short-circuits to None — some LDAP servers treat
        an empty credential as an anonymous bind, which we MUST NOT
        treat as authenticated.
        """
        if not password:
            return None
        safe = (username or "").translate(
            str.maketrans(
                {
                    "(": r"\28",
                    ")": r"\29",
                    "\\": r"\5c",
                    "*": r"\2a",
                    "\x00": r"\00",
                }
            )
        )
        filt = (
            f"(&(objectClass=user)(!(objectClass=computer))"
            f"(|(sAMAccountName={safe})"
            f"(userPrincipalName={safe})"
            f"(mail={safe})))"
        )
        with self._connect() as svc_conn:
            svc_conn.search(
                search_base=self.integ.base_dn,
                search_filter=filt,
                attributes=list(_USER_ATTRS) + ["memberOf"],
                size_limit=2,
            )
            if not svc_conn.entries:
                return None
            entry = svc_conn.entries[0]
            user_dn = getattr(entry, "entry_dn", None)
            if not user_dn:
                return None

        # Second bind, as the user themselves, to verify the password.
        try:
            user_conn = Connection(
                self.server,
                user=user_dn,
                password=password,
                authentication="SIMPLE",
                receive_timeout=self.integ.query_timeout_s,
                auto_bind=True,
                raise_exceptions=True,
            )
            bound = user_conn.bound
            user_conn.unbind()
        except LDAPException:
            return None
        if not bound:
            return None

        out = _serialize_entry(entry)
        # memberOf is multi-valued; ensure we surface a list regardless.
        m = getattr(entry, "memberOf", None)
        if m is not None:
            try:
                out["memberOf"] = [str(v) for v in m.values]
            except Exception:
                out["memberOf"] = [str(m)]
        else:
            out["memberOf"] = []
        out["dn"] = user_dn
        return out

    def get_user_by_dn(self, dn: str) -> dict | None:
        with self._connect() as conn:
            conn.search(
                search_base=dn,
                search_filter="(objectClass=user)",
                attributes=_USER_ATTRS,
                size_limit=1,
                search_scope="BASE",
            )
            if not conn.entries:
                return None
            return _serialize_entry(conn.entries[0])

    def search_group(self, query: str, *, limit: int = 25) -> list[dict]:
        safe = query.translate(
            str.maketrans({"(": r"\28", ")": r"\29", "\\": r"\5c", "*": r"\2a", "\x00": r"\00"})
        )
        filt = (
            f"(&(objectClass=group)"
            f"(|(sAMAccountName=*{safe}*)"
            f"(cn=*{safe}*)"
            f"(displayName=*{safe}*)))"
        )
        with self._connect() as conn:
            conn.search(
                search_base=self.integ.base_dn,
                search_filter=filt,
                attributes=_GROUP_ATTRS,
                size_limit=limit,
            )
            return [_serialize_entry(e) for e in conn.entries]

    def get_group_by_dn(self, dn: str) -> dict | None:
        with self._connect() as conn:
            conn.search(
                search_base=dn,
                search_filter="(objectClass=group)",
                attributes=_GROUP_ATTRS,
                size_limit=1,
                search_scope="BASE",
            )
            if not conn.entries:
                return None
            return _serialize_entry(conn.entries[0])


def load_bind_password(db: OrmSession, bind_secret_id: uuid.UUID | None) -> str | None:
    if bind_secret_id is None:
        return None
    row = db.execute(
        text("""
        SELECT ciphertext, nonce FROM secrets WHERE id = :id
    """),
        {"id": bind_secret_id},
    ).first()
    if row is None:
        return None
    # secrets table splits nonce (bytea) + ciphertext (bytea); our vault
    # helper expects them concatenated nonce||ct.
    return decrypt_field(bytes(row.nonce) + bytes(row.ciphertext), domain=b"vault").decode()


def client_for(db: OrmSession, integ: DirectoryIntegration) -> LDAPClient:
    pw = load_bind_password(db, integ.bind_secret_id)
    return LDAPClient(integ, pw)
