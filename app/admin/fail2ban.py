"""Thin wrapper around `fail2ban-client`.

All mutation paths — unban, add/remove ignoreip — go through `sudo -n`
against a narrow sudoers drop-in (see config/sudoers.d/meridian-fail2ban).
Read paths (status, list jails, list banned) don't need sudo on a Debian
default install but we sudo them anyway for consistency; fall back to
unprivileged invocation so it still works if the drop-in is missing.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import subprocess

_BIN = "/usr/bin/fail2ban-client"


def _run(args: list[str], *, privileged: bool = False, timeout_s: float = 6.0) -> tuple[int, str, str]:
    cmd = ["sudo", "-n", _BIN, *args] if privileged else [_BIN, *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s, check=False)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "fail2ban-client not installed"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def _validate_ip(ip: str) -> str:
    """Raise ValueError if `ip` isn't a plain IPv4 / IPv6 address or CIDR."""
    s = ip.strip()
    try:
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
    except ValueError as e:
        raise ValueError(f"invalid IP/CIDR: {s!r}") from e
    # Belt-and-suspenders — reject anything with shell metacharacters even
    # though subprocess.run with a list avoids the shell entirely.
    if re.search(r"[^0-9a-fA-F:./]", s):
        raise ValueError(f"invalid IP: {s!r}")
    return s


def _validate_jail(jail: str) -> str:
    s = jail.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", s):
        raise ValueError(f"invalid jail name: {jail!r}")
    return s


@dataclass
class JailStatus:
    name: str
    currently_failed: int
    total_failed: int
    currently_banned: int
    total_banned: int
    banned_ips: list[str]
    journal_matches: str | None = None


def list_jails() -> list[str]:
    rc, out, _ = _run(["status"], privileged=True)
    if rc != 0:
        rc, out, _ = _run(["status"], privileged=False)
    if rc != 0:
        return []
    m = re.search(r"Jail list:\s*(.*)", out)
    if not m:
        return []
    return [j.strip() for j in m.group(1).split(",") if j.strip()]


def jail_status(jail: str) -> JailStatus | None:
    jail = _validate_jail(jail)
    rc, out, _ = _run(["status", jail], privileged=True)
    if rc != 0:
        rc, out, _ = _run(["status", jail], privileged=False)
    if rc != 0:
        return None

    def _int_after(label: str) -> int:
        m = re.search(rf"{re.escape(label)}:\s*(\d+)", out)
        return int(m.group(1)) if m else 0

    banned_ips: list[str] = []
    m = re.search(r"Banned IP list:\s*(.*)", out)
    if m:
        banned_ips = [ip for ip in m.group(1).split() if ip]

    jm = re.search(r"Journal matches:\s*(.*)", out)

    return JailStatus(
        name=jail,
        currently_failed=_int_after("Currently failed"),
        total_failed=_int_after("Total failed"),
        currently_banned=_int_after("Currently banned"),
        total_banned=_int_after("Total banned"),
        banned_ips=banned_ips,
        journal_matches=jm.group(1).strip() if jm else None,
    )


def unban(jail: str, ip: str) -> tuple[bool, str]:
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    rc, out, err = _run(["set", jail, "unbanip", ip], privileged=True, timeout_s=10)
    return (rc == 0), (out or err).strip()


def add_ignore(jail: str, ip: str) -> tuple[bool, str]:
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    rc, out, err = _run(["set", jail, "addignoreip", ip], privileged=True, timeout_s=10)
    return (rc == 0), (out or err).strip()


def del_ignore(jail: str, ip: str) -> tuple[bool, str]:
    jail = _validate_jail(jail)
    ip = _validate_ip(ip)
    rc, out, err = _run(["set", jail, "delignoreip", ip], privileged=True, timeout_s=10)
    return (rc == 0), (out or err).strip()


def ignore_list(jail: str) -> list[str]:
    """Return the current ignoreip list for a jail. Depending on fail2ban
    version, `fail2ban-client get <jail> ignoreip` emits either:

        These IP addresses/networks are ignored:
        |- 127.0.0.1/8
        |- ::1
        `- 192.168.50.196

    or a Python-style `['127.0.0.1/8', '::1', '192.168.50.196']`. Parse
    both and return a clean list of IP/CIDR strings."""
    jail = _validate_jail(jail)
    rc, out, _ = _run(["get", jail, "ignoreip"], privileged=True)
    if rc != 0:
        rc, out, _ = _run(["get", jail, "ignoreip"], privileged=False)
    if rc != 0:
        return []
    body = out.strip()

    # Python-list style (older fail2ban-client).
    if body.startswith("[") and body.endswith("]"):
        return [p.strip(" '\"") for p in body[1:-1].split(",") if p.strip(" '\"")]

    # Tree-style (modern fail2ban-client). Strip the leader glyphs off
    # each data line and drop the human-readable header.
    entries: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or "These IP addresses" in line:
            continue
        # Strip any combination of tree leader chars: | ` - and whitespace.
        cleaned = line.lstrip("|` -").strip()
        if cleaned:
            entries.append(cleaned)
    return entries


_PERSIST_PATH = "/etc/fail2ban/jail.d/meridian-portal-overrides.conf"


def persist_ignore_add(ip: str) -> tuple[bool, str]:
    """Append `ip` to the persistent ignoreip list in
    `_PERSIST_PATH` and reload fail2ban so the change takes effect
    immediately. Idempotent: if `ip` is already present, this is a
    no-op.

    The file is owned by the meridian user (install.sh sets that up),
    so writes succeed without sudo. The reload itself uses sudo via the
    fail2ban-client sudoers drop-in.
    """
    ip = _validate_ip(ip)
    try:
        body = open(_PERSIST_PATH).read()
    except FileNotFoundError:
        body = "[DEFAULT]\nignoreip = 127.0.0.1/8 ::1\n"
    new_body, mutated = _ignoreip_mutate(body, ip, op="add")
    if not mutated:
        return True, "already present"
    try:
        # Direct in-place rewrite. The directory /etc/fail2ban/jail.d/ is
        # root-owned, so we can't tempfile-rename atomically without sudo.
        # The file itself is meridian-owned; fail2ban only re-reads it at
        # reload (which we trigger ourselves right after), so a momentary
        # half-written state can't be observed.
        with open(_PERSIST_PATH, "w") as fh:
            fh.write(new_body)
    except OSError as e:
        return False, f"write failed: {e}"
    rc, out, err = _run(["reload"], privileged=True, timeout_s=15)
    return (rc == 0), (out or err).strip()


def persist_ignore_remove(ip: str) -> tuple[bool, str]:
    """Remove `ip` from the persistent ignoreip list and reload."""
    ip = _validate_ip(ip)
    try:
        body = open(_PERSIST_PATH).read()
    except FileNotFoundError:
        return True, "no overrides file"
    new_body, mutated = _ignoreip_mutate(body, ip, op="del")
    if not mutated:
        return True, "not in list"
    try:
        with open(_PERSIST_PATH, "w") as fh:
            fh.write(new_body)
    except OSError as e:
        return False, f"write failed: {e}"
    rc, out, err = _run(["reload"], privileged=True, timeout_s=15)
    return (rc == 0), (out or err).strip()


def persist_ignore_list() -> list[str]:
    """Read the persisted ignoreip entries (excluding the loopback
    defaults so the UI shows only operator-added IPs)."""
    try:
        body = open(_PERSIST_PATH).read()
    except FileNotFoundError:
        return []
    entries = _ignoreip_parse(body)
    return [e for e in entries if e not in ("127.0.0.1/8", "::1")]


def _ignoreip_parse(body: str) -> list[str]:
    for line in body.splitlines():
        s = line.strip()
        if s.lower().startswith("ignoreip"):
            _, _, rhs = s.partition("=")
            return [tok for tok in rhs.split() if tok]
    return []


def _ignoreip_mutate(body: str, ip: str, *, op: str) -> tuple[str, bool]:
    out_lines = []
    mutated = False
    found_section = False
    found_key = False
    for line in body.splitlines():
        if line.strip().lower() == "[default]":
            found_section = True
            out_lines.append(line)
            continue
        s = line.strip()
        if s.lower().startswith("ignoreip") and found_section and not found_key:
            found_key = True
            _, _, rhs = s.partition("=")
            tokens = [t for t in rhs.split() if t]
            if op == "add":
                if ip not in tokens:
                    tokens.append(ip)
                    mutated = True
            elif op == "del":
                if ip in tokens:
                    tokens = [t for t in tokens if t != ip]
                    mutated = True
            out_lines.append(f"ignoreip = {' '.join(tokens)}")
            continue
        out_lines.append(line)
    if not found_section:
        # No [DEFAULT] section present — append a fresh one.
        out_lines.append("[DEFAULT]")
        out_lines.append(f"ignoreip = 127.0.0.1/8 ::1 {ip}" if op == "add" else "ignoreip = 127.0.0.1/8 ::1")
        mutated = op == "add"
    elif not found_key:
        out_lines.append(f"ignoreip = 127.0.0.1/8 ::1 {ip}" if op == "add" else "ignoreip = 127.0.0.1/8 ::1")
        mutated = op == "add"
    return "\n".join(out_lines) + "\n", mutated


def snapshot() -> dict:
    """All jails at once — what the admin panel card calls."""
    jails = list_jails()
    out = []
    for j in jails:
        st = jail_status(j)
        if st is None:
            continue
        out.append(
            {
                "name": st.name,
                "currently_failed": st.currently_failed,
                "total_failed": st.total_failed,
                "currently_banned": st.currently_banned,
                "total_banned": st.total_banned,
                "banned_ips": st.banned_ips,
                "ignore_list": ignore_list(j),
            }
        )
    return {"jails": out, "persisted_ignore": persist_ignore_list()}
