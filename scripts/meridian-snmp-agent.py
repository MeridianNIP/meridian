#!/usr/bin/env python3
"""Meridian NIP SNMP pass_persist extension.

snmpd invokes this script once per agent restart and keeps it running;
every poll request snmpd writes `get <oid>\n` or `getnext <oid>\n` on
stdin, we respond with three lines: the matched OID, the SMI type, and
the value (or `NONE\n` if we don't serve that OID).

Metrics are read live from Postgres + /proc + /sys on every poll so
they're always fresh. Keep the per-poll cost cheap — this runs on the
monitoring tool's cadence (typically 30–60s).
"""
from __future__ import annotations

import os
import re
import sys
import time
from typing import Callable

# Enterprise arc: 1.3.6.1.4.1.60022 (MERIDIAN-NIP-MIB)
BASE = "1.3.6.1.4.1.60022"


# ---------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------
def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def _uptime_secs() -> int:
    try:
        return int(float(_read("/proc/uptime").split()[0]))
    except (ValueError, IndexError):
        return 0


def _loadavg_x100() -> int:
    try:
        return int(float(_read("/proc/loadavg").split()[0]) * 100)
    except (ValueError, IndexError):
        return 0


def _meminfo() -> dict:
    out = {}
    for ln in _read("/proc/meminfo").splitlines():
        k, _, v = ln.partition(":")
        out[k.strip()] = int((v.strip().split() or ["0"])[0])
    return out


def _mem_used_pct() -> int:
    m = _meminfo()
    total = m.get("MemTotal", 1)
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    return max(0, min(100, int(100 * (total - avail) / total)))


def _disk_used_pct(mount: str = "/") -> int:
    try:
        s = os.statvfs(mount)
        total = s.f_blocks * s.f_frsize
        used = (s.f_blocks - s.f_bavail) * s.f_frsize
        return 0 if total == 0 else int(100 * used / total)
    except OSError:
        return 0


def _svc_is_active_code(unit: str) -> int:
    """0=active, 1=inactive, 2=failed, 3=unknown."""
    r = os.popen(f"/usr/bin/systemctl is-active {unit} 2>/dev/null").read().strip()
    return {"active": 0, "inactive": 1, "failed": 2}.get(r, 3)


def _pg_scalar(sql: str, default=None):
    """Run a scalar query against the Meridian DB via psql (no driver required)."""
    try:
        import subprocess
        r = subprocess.run(
            ["sudo", "-u", "postgres", "-n", "/usr/bin/psql", "-d", "meridian",
             "-tAc", sql],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0:
            v = (r.stdout or "").strip()
            if v == "" or v.lower() == "null":
                return default
            return v
    except Exception:  # noqa: BLE001
        pass
    return default


def _nic_list():
    """Return rows of (idx, name, operstate, mtu, rx_bytes, tx_bytes,
    rx_pkts, tx_pkts) from /sys/class/net. Skips `lo`."""
    out = []
    base = "/sys/class/net"
    try:
        names = sorted(os.listdir(base))
    except OSError:
        return out
    idx = 0
    for name in names:
        if name == "lo":
            continue
        idx += 1
        p = f"{base}/{name}"
        out.append((
            idx, name,
            _read(f"{p}/operstate") or "unknown",
            int(_read(f"{p}/mtu") or 0),
            int(_read(f"{p}/statistics/rx_bytes") or 0),
            int(_read(f"{p}/statistics/tx_bytes") or 0),
            int(_read(f"{p}/statistics/rx_packets") or 0),
            int(_read(f"{p}/statistics/tx_packets") or 0),
        ))
    return out


# ---------------------------------------------------------------------------
# OID → (type, getter) map
# ---------------------------------------------------------------------------
def _version() -> str:
    return _read("/opt/meridian/VERSION") or "unknown"


def _svc_code(unit: str) -> Callable[[], int]:
    return lambda: _svc_is_active_code(unit)


_SCALARS: dict[str, tuple[str, Callable]] = {
    # meridianCore (1)
    f"{BASE}.1.1.0": ("Counter64",    lambda: int(time.time() -
        os.path.getmtime("/proc/1/cmdline")) if os.path.exists("/proc/1/cmdline") else 0),
    f"{BASE}.1.2.0": ("STRING",       _version),
    f"{BASE}.1.3.0": ("Gauge32",      lambda: int(_pg_scalar(
        "SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now();", 0) or 0)),
    f"{BASE}.1.4.0": ("INTEGER",      lambda: 1 if _pg_scalar(
        "SELECT count(*) FROM license WHERE status='active';", 0) not in (None, "0", 0) else 0),
    # meridianServices (2)
    f"{BASE}.2.1.0": ("INTEGER",      _svc_code("postgresql.service")),
    f"{BASE}.2.2.0": ("INTEGER",      _svc_code("nginx.service")),
    f"{BASE}.2.3.0": ("INTEGER",      lambda: min(
        _svc_is_active_code("bind9.service"),
        _svc_is_active_code("named.service"))),
    f"{BASE}.2.4.0": ("INTEGER",      _svc_code("meridian-app.service")),
    f"{BASE}.2.5.0": ("INTEGER",      _svc_code("meridian-celery.service")),
    f"{BASE}.2.6.0": ("INTEGER",      _svc_code("meridian-beat.service")),
    f"{BASE}.2.7.0": ("INTEGER",      lambda: min(
        _svc_is_active_code("redis-server.service"),
        _svc_is_active_code("valkey-server.service"))),
    # meridianHost (3)
    f"{BASE}.3.1.0": ("Counter64",    _uptime_secs),
    f"{BASE}.3.2.0": ("Gauge32",      _loadavg_x100),
    f"{BASE}.3.3.0": ("Gauge32",      _mem_used_pct),
    f"{BASE}.3.4.0": ("Gauge32",      _disk_used_pct),
    # meridianMonitors (4)
    f"{BASE}.4.1.0": ("Gauge32",      lambda: int(_pg_scalar(
        "SELECT count(*) FROM monitors WHERE enabled AND last_status='ok';", 0) or 0)),
    f"{BASE}.4.2.0": ("Gauge32",      lambda: int(_pg_scalar(
        "SELECT count(*) FROM monitors WHERE enabled AND last_status IN ('warn','down','unknown');", 0) or 0)),
    f"{BASE}.4.3.0": ("Gauge32",      lambda: int(_pg_scalar(
        "SELECT count(*) FROM monitor_incidents WHERE closed_at IS NULL;", 0) or 0)),
    # meridianCerts (5)
    f"{BASE}.5.1.0": ("Gauge32",      lambda: int(_pg_scalar(
        "SELECT count(*) FROM certificates WHERE revoked_at IS NULL;", 0) or 0)),
    f"{BASE}.5.2.0": ("INTEGER",      lambda: int(_pg_scalar(
        "SELECT COALESCE(min(extract(day FROM valid_until - now())::int), -1) "
        "FROM certificates WHERE revoked_at IS NULL AND valid_until IS NOT NULL;", -1) or -1)),
    f"{BASE}.5.3.0": ("Gauge32",      lambda: int(_pg_scalar(
        "SELECT count(*) FROM certificates WHERE revoked_at IS NULL AND valid_until < now() + interval '30 days';", 0) or 0)),
    # meridianAudit (6)
    f"{BASE}.6.1.0": ("INTEGER",      lambda: 1 if _pg_scalar(
        "SELECT COALESCE(max(mismatches),-1) FROM db_integrity_scans;", -1) == "0" else 0),
    f"{BASE}.6.2.0": ("Counter64",    lambda: int(_pg_scalar(
        "SELECT COALESCE(extract(epoch FROM now() - max(started_at))::bigint, 0) FROM db_integrity_scans;", 0) or 0)),
}


# Host NIC table (3.5): scalars built dynamically per NIC row
def _nic_oids() -> dict[str, tuple[str, Callable]]:
    """Flatten the per-NIC table into OIDs under 3.5.1.{col}.{idx}."""
    out: dict[str, tuple[str, Callable]] = {}
    for idx, name, operstate, mtu, rx, tx, rxp, txp in _nic_list():
        out[f"{BASE}.3.5.1.1.{idx}"] = ("INTEGER", (lambda v=idx: v))
        out[f"{BASE}.3.5.1.2.{idx}"] = ("STRING",  (lambda v=name: v))
        out[f"{BASE}.3.5.1.3.{idx}"] = ("STRING",  (lambda v=operstate: v))
        out[f"{BASE}.3.5.1.4.{idx}"] = ("INTEGER", (lambda v=mtu: v))
        out[f"{BASE}.3.5.1.5.{idx}"] = ("Counter64", (lambda v=rx: v))
        out[f"{BASE}.3.5.1.6.{idx}"] = ("Counter64", (lambda v=tx: v))
        out[f"{BASE}.3.5.1.7.{idx}"] = ("Counter64", (lambda v=rxp: v))
        out[f"{BASE}.3.5.1.8.{idx}"] = ("Counter64", (lambda v=txp: v))
    return out


def _all_oids() -> dict[str, tuple[str, Callable]]:
    """Combine static scalars with NIC table entries."""
    return {**_SCALARS, **_nic_oids()}


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.split(".") if p.isdigit())


def _next_oid(oid: str) -> str | None:
    """Find the next OID lexicographically for GETNEXT walks."""
    oids = _all_oids()
    sorted_oids = sorted(oids.keys(), key=_oid_key)
    target = _oid_key(oid)
    for candidate in sorted_oids:
        if _oid_key(candidate) > target:
            return candidate
    return None


def _emit(oid: str, typ: str, val) -> None:
    sys.stdout.write(oid + "\n")
    sys.stdout.write(typ + "\n")
    sys.stdout.write(str(val) + "\n")
    sys.stdout.flush()


def _emit_none() -> None:
    sys.stdout.write("NONE\n")
    sys.stdout.flush()


def main() -> None:
    while True:
        line = sys.stdin.readline()
        if not line:
            return
        line = line.strip()
        if line == "PING":
            sys.stdout.write("PONG\n"); sys.stdout.flush(); continue
        if line == "get":
            oid = sys.stdin.readline().strip()
            oids = _all_oids()
            if oid in oids:
                typ, getter = oids[oid]
                try:
                    _emit(oid, typ, getter())
                except Exception:  # noqa: BLE001
                    _emit_none()
            else:
                _emit_none()
        elif line == "getnext":
            oid = sys.stdin.readline().strip()
            nxt = _next_oid(oid)
            if nxt is None:
                _emit_none()
            else:
                oids = _all_oids()
                typ, getter = oids[nxt]
                try:
                    _emit(nxt, typ, getter())
                except Exception:  # noqa: BLE001
                    _emit_none()
        else:
            # Unknown verb — ignore politely.
            pass


if __name__ == "__main__":
    main()
