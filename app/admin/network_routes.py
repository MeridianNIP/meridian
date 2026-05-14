"""Admin Panel → Network Configuration.

Single-page HTTP surface for the network-config singleton:

    GET  /api/v1/admin/network               — current settings + last apply state
    PUT  /api/v1/admin/network               — save draft (does NOT apply)
    POST /api/v1/admin/network/apply         — render + reload services
    GET  /api/v1/admin/network/history       — last 50 applies (who/when/outcome)

Apply goes through `sudo -n /opt/meridian/scripts/apply-network-config.sh all`
(or per-section) — the portal never edits systemd files directly.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.db import fastapi_dep_db
from app.models.network_config import NetworkConfig, NetworkConfigHistory
from app.models.user import User


router = APIRouter(prefix="/admin/network", tags=["admin-network"])


CONFIG_FILE = Path("/etc/meridian/network-config.json")
APPLY_SCRIPT = "/opt/meridian/scripts/apply-network-config.sh"


# --- Pydantic shapes (also doubles as the UI contract) -------------------
class IpSection(BaseModel):
    mode: str = Field("dhcp", pattern=r"^(dhcp|static)$")
    iface: str | None = None
    address_cidr: str | None = Field(None, max_length=64)
    gateway: str | None = Field(None, max_length=64)
    mtu: int | None = Field(None, ge=576, le=9000)


class DnsSection(BaseModel):
    servers: list[str] = Field(default_factory=list, max_length=8)
    search: list[str] = Field(default_factory=list, max_length=16)


class NtpSection(BaseModel):
    servers: list[str] = Field(default_factory=list, max_length=8)
    fallback: list[str] = Field(default_factory=list, max_length=4)


class ProxySection(BaseModel):
    http_url: str | None = Field(None, max_length=512)
    https_url: str | None = Field(None, max_length=512)
    no_proxy: str | None = Field(None, max_length=1024)


class NetworkSettings(BaseModel):
    ip: IpSection = Field(default_factory=IpSection)
    dns: DnsSection = Field(default_factory=DnsSection)
    ntp: NtpSection = Field(default_factory=NtpSection)
    proxy: ProxySection = Field(default_factory=ProxySection)


def _load() -> NetworkConfig:
    return NetworkConfig(id=1, settings={})


@router.get("")
async def get_config(
    user: User = Depends(require_permission("admin.system.network")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    cfg = db.get(NetworkConfig, 1)
    if cfg is None:
        cfg = NetworkConfig(id=1, settings={})
        db.add(cfg)
        db.flush()
    return {
        "settings": cfg.settings or {},
        "applied_at": cfg.applied_at.isoformat() if cfg.applied_at else None,
        "applied_by": str(cfg.applied_by) if cfg.applied_by else None,
        "apply_status": cfg.apply_status,
        "apply_detail": cfg.apply_detail,
    }


@router.get("/system")
async def get_system_state(
    user: User = Depends(require_permission("admin.system.network")),
) -> dict:
    """Introspect the running system and return whatever's actually
    configured RIGHT NOW — independent of what the portal has saved.
    Returns a list of every non-loopback interface plus DNS/NTP/proxy.
    The UI uses this to populate the interface dropdown and to show
    'live system state' next to a saved draft."""
    import json
    import re

    def _run(cmd: list[str], timeout_s: float = 4.0) -> str:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
            return r.stdout if r.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    # --- IP / routing — all interfaces ------------------------------------
    interfaces: list[dict[str, Any]] = []
    addr_json = _run(["ip", "-j", "addr", "show"])  # IPv4 + IPv6
    route_json = _run(["ip", "-j", "-4", "route", "show", "default"])

    # Map iface -> default gateway (whichever default route picks it).
    gw_for: dict[str, str] = {}
    try:
        for r in json.loads(route_json or "[]"):
            if r.get("dst") == "default":
                gw_for.setdefault(r.get("dev"), r.get("gateway") or "")
    except (ValueError, KeyError):
        pass

    try:
        for entry in json.loads(addr_json or "[]"):
            name = entry.get("ifname")
            if name == "lo" or not name:
                continue
            ipv4 = next((ai for ai in entry.get("addr_info") or []
                         if ai.get("family") == "inet"), None)
            iface = {
                "iface": name,
                "operstate": entry.get("operstate"),
                "mac": entry.get("address"),
                "mtu": entry.get("mtu"),
                "address_cidr": (f"{ipv4['local']}/{ipv4['prefixlen']}" if ipv4 else None),
                "mode": ("dhcp" if (ipv4 and ipv4.get("dynamic"))
                         else ("static" if ipv4 else "down")),
                "gateway": gw_for.get(name) or None,
            }
            interfaces.append(iface)
    except (ValueError, KeyError):
        pass

    # Sort: the iface with a default route first, then "up" before "down",
    # then alphabetically. Operator's "primary" NIC ends up at the top.
    primary_name = next(iter(gw_for), None)
    interfaces.sort(key=lambda i: (
        0 if i["iface"] == primary_name else 1,
        0 if i.get("operstate") == "UP" else 1,
        i["iface"],
    ))

    # `ip` (singular) preserves the old shape for back-compat — it's the
    # primary interface (whatever has the default route, or first).
    ip = (interfaces[0] if interfaces else {
        "iface": None, "address_cidr": None, "gateway": None,
        "mtu": None, "mode": "dhcp",
    }).copy()
    ip.pop("operstate", None); ip.pop("mac", None)

    # --- DNS / search domains --------------------------------------------
    dns_servers: list[str] = []
    dns_search: list[str] = []
    rc_status = _run(["resolvectl", "status"])
    if rc_status:
        # Look at the "Global" / "Link N (iface)" section. We'll just take
        # every "DNS Servers:" / "DNS Domain:" line we see.
        cur_servers: list[str] = []
        cur_search: list[str] = []
        for line in rc_status.splitlines():
            m = re.match(r"\s*(?:Current\s+)?DNS Server[s]?:\s*(.*)", line)
            if m:
                cur_servers += [s for s in m.group(1).split() if s]
            m = re.match(r"\s*DNS Domain:\s*(.*)", line)
            if m:
                cur_search += [s for s in m.group(1).split() if s]
        dns_servers = list(dict.fromkeys(cur_servers))
        dns_search = list(dict.fromkeys(cur_search))
    if not dns_servers:
        # Fall back to /etc/resolv.conf.
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                line = line.strip()
                if line.startswith("nameserver "):
                    dns_servers.append(line.split(None, 1)[1])
                elif line.startswith("search "):
                    dns_search += line.split()[1:]
        except OSError:
            pass

    # --- NTP --------------------------------------------------------------
    ntp_servers: list[str] = []
    ntp_fallback: list[str] = []
    for confd in (Path("/etc/systemd/timesyncd.conf.d"), Path("/etc/systemd/timesyncd.conf")):
        try:
            paths = (sorted(confd.glob("*.conf")) if confd.is_dir() else
                     ([confd] if confd.is_file() else []))
            for p in paths:
                for line in p.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("NTP="):
                        ntp_servers += line[4:].split()
                    elif line.startswith("FallbackNTP="):
                        ntp_fallback += line[12:].split()
        except OSError:
            pass

    # --- Proxy ------------------------------------------------------------
    proxy = {"http_url": None, "https_url": None, "no_proxy": None}
    try:
        for line in Path("/etc/meridian/proxy.env").read_text().splitlines():
            line = line.strip()
            if line.startswith("HTTP_PROXY="):  proxy["http_url"]  = line.split("=", 1)[1]
            if line.startswith("HTTPS_PROXY="): proxy["https_url"] = line.split("=", 1)[1]
            if line.startswith("NO_PROXY="):    proxy["no_proxy"]  = line.split("=", 1)[1]
    except OSError:
        pass

    return {
        "ip":    ip,
        "interfaces": interfaces,
        "dns":   {"servers": dns_servers, "search": dns_search},
        "ntp":   {"servers": ntp_servers, "fallback": ntp_fallback},
        "proxy": proxy,
    }


@router.put("")
async def save_config(
    request: Request, body: NetworkSettings,
    user: User = Depends(require_permission("admin.system.network")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    """Persist the draft settings without applying them — the UI calls
    this on every card change so the settings survive a refresh."""
    cfg = db.get(NetworkConfig, 1)
    if cfg is None:
        cfg = NetworkConfig(id=1, settings={})
        db.add(cfg)
    cfg.settings = body.model_dump(mode="json")
    db.flush()
    audit(db, user_id=user.id, action="admin.network.save",
          target_type="network_config", target_key="singleton",
          payload={"sections": list(cfg.settings.keys())},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"))
    return {"ok": True, "settings": cfg.settings}


class ApplyIn(BaseModel):
    section: str = Field("all", pattern=r"^(ip|dns|ntp|proxy|all)$")


@router.post("/apply")
async def apply_config(
    request: Request, body: ApplyIn,
    user: User = Depends(require_permission("admin.system.network")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    cfg = db.get(NetworkConfig, 1)
    if cfg is None or not cfg.settings:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "no saved settings — save first")

    # Write the config to /etc/meridian/network-config.json so the apply
    # script can render it. The directory + file must be meridian-writable.
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CONFIG_FILE.with_suffix(".json.new")
        tmp.write_text(json.dumps(cfg.settings, indent=2))
        tmp.replace(CONFIG_FILE)
    except OSError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            f"could not stage config: {e}")

    try:
        r = subprocess.run(
            ["sudo", "-n", APPLY_SCRIPT, body.section],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        r_rc, r_out, r_err = 124, "", "apply script timed out"
    else:
        r_rc, r_out, r_err = r.returncode, r.stdout, r.stderr

    now = datetime.now(timezone.utc)
    detail: dict[str, Any] = {
        "section": body.section,
        "rc": r_rc,
        "output": ((r_out or "") + (r_err or ""))[:2000],
    }
    ok = (r_rc == 0)
    cfg.applied_at = now
    cfg.applied_by = user.id
    cfg.apply_status = "ok" if ok else "failed"
    cfg.apply_detail = detail
    db.add(NetworkConfigHistory(
        applied_at=now, applied_by=user.id,
        settings=cfg.settings, apply_status=cfg.apply_status, apply_detail=detail,
    ))
    audit(db, user_id=user.id, action="admin.network.apply",
          target_type="network_config", target_key=body.section,
          payload={"status": cfg.apply_status, "rc": r_rc},
          ip=client_ip(request), user_agent=request.headers.get("user-agent"),
          outcome="ok" if ok else "error")
    return {
        "ok": ok,
        "status": cfg.apply_status,
        "detail": detail,
        "applied_at": now.isoformat(),
    }


@router.get("/history")
async def history(
    limit: int = 50,
    user: User = Depends(require_permission("admin.system.network")),
    db: OrmSession = Depends(fastapi_dep_db),
) -> dict:
    limit = max(1, min(500, limit))
    rows = db.execute(
        select(NetworkConfigHistory).order_by(desc(NetworkConfigHistory.applied_at)).limit(limit)
    ).scalars().all()
    return {
        "history": [
            {
                "id": r.id,
                "applied_at": r.applied_at.isoformat(),
                "applied_by": str(r.applied_by) if r.applied_by else None,
                "apply_status": r.apply_status,
                "apply_detail": r.apply_detail,
                "settings": r.settings,
            }
            for r in rows
        ],
    }
