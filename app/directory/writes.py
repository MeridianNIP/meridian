from __future__ import annotations

from ldap3 import MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException

from app.directory.ldap_client import LDAPClient

# AD userAccountControl bit definitions relevant to these operations.
_UAC_ACCOUNTDISABLE = 0x0002
_UAC_LOCKOUT = 0x0010


class DirectoryWriteError(Exception):
    pass


def unlock_account(client: LDAPClient, dn: str) -> dict:
    """Clear the account lockout by writing lockoutTime=0 (AD-specific).

    Note: userAccountControl is NOT the canonical place for the lockout bit on
    modern AD — lockoutTime carries that state. Setting it to 0 unlocks.
    """
    try:
        with client._connect() as conn:
            ok = conn.modify(dn, {"lockoutTime": [(MODIFY_REPLACE, ["0"])]})
            if not ok:
                raise DirectoryWriteError(f"LDAP modify failed: {conn.result}")
            return {"ok": True, "dn": dn, "op": "unlock", "result": conn.result}
    except LDAPException as e:
        raise DirectoryWriteError(f"{type(e).__name__}: {e}") from e


def disable_account(client: LDAPClient, dn: str) -> dict:
    """Set the ACCOUNTDISABLE bit in userAccountControl."""
    try:
        with client._connect() as conn:
            conn.search(dn, "(objectClass=user)", attributes=["userAccountControl"], search_scope="BASE")
            if not conn.entries:
                raise DirectoryWriteError("user not found")
            current = int(conn.entries[0].userAccountControl.value or 0)
            new_uac = current | _UAC_ACCOUNTDISABLE
            ok = conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [str(new_uac)])]})
            if not ok:
                raise DirectoryWriteError(f"LDAP modify failed: {conn.result}")
            return {"ok": True, "dn": dn, "op": "disable", "uac_before": current, "uac_after": new_uac}
    except LDAPException as e:
        raise DirectoryWriteError(f"{type(e).__name__}: {e}") from e


def reset_password(client: LDAPClient, dn: str, new_password: str, *, force_change: bool = True) -> dict:
    """Reset an AD user's password. Requires LDAPS (AD refuses password ops
    over plain LDAP) and appropriate delegated rights on the bind account.

    AD expects `unicodePwd` as UTF-16LE with surrounding double-quotes.
    """
    if not client.server.ssl:
        raise DirectoryWriteError("password reset requires LDAPS")
    if len(new_password) < 12:
        raise DirectoryWriteError("password must be at least 12 chars")
    encoded = ('"' + new_password + '"').encode("utf-16-le")
    try:
        with client._connect() as conn:
            modifications: dict = {
                "unicodePwd": [(MODIFY_REPLACE, [encoded])],
            }
            if force_change:
                # pwdLastSet=0 forces "User must change password at next logon"
                modifications["pwdLastSet"] = [(MODIFY_REPLACE, ["0"])]
            ok = conn.modify(dn, modifications)
            if not ok:
                raise DirectoryWriteError(f"LDAP modify failed: {conn.result}")
            return {"ok": True, "dn": dn, "op": "reset_password", "force_change_at_next_logon": force_change}
    except LDAPException as e:
        raise DirectoryWriteError(f"{type(e).__name__}: {e}") from e
