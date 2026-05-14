"""SSH connection layer for network devices.

Wraps netmiko so the rest of the codebase can stay oblivious of which library
we're using and so we can plug in alternatives (plain paramiko, scrapli,
vendor SDK) per-kind later without touching the backup/diff logic.

netmiko is imported lazily — dev environments without it can still import
this module; the error only fires when an actual fetch is attempted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


# device_kind enum values → netmiko device_type strings.
# Linux-backend entries (pfSense, OPNsense, Synology, etc.) all use
# "linux" since they ship a stock OpenSSH and the backup just runs a
# kind-specific shell pipeline (see DEVICE_COMMANDS below).
_NETMIKO_MAP: dict[str, str] = {
    # Cisco
    "cisco_ios":         "cisco_ios",
    "cisco_iosxe":       "cisco_xe",
    "cisco_iosxr":       "cisco_xr",
    "cisco_nxos":        "cisco_nxos",
    "cisco_asa":         "cisco_asa",
    "cisco_wlc":         "cisco_wlc_ssh",
    "cisco_s300":        "cisco_s300",
    # Other enterprise
    "juniper_junos":     "juniper_junos",
    "arista_eos":        "arista_eos",
    "palo_alto":         "paloalto_panos",
    "fortinet":          "fortinet",
    "huawei":            "huawei",
    "aruba_aoscx":       "aruba_aoscx",
    "aruba_os":          "aruba_os",
    "hp_procurve":       "hp_procurve",
    "hp_comware":        "hp_comware",
    "dell_os10":         "dell_os10",
    "dell_force10":      "dell_force10",
    "dell_powerconnect": "dell_powerconnect",
    "extreme_exos":      "extreme_exos",
    "brocade_fastiron":  "brocade_fastiron",
    # Load balancer / ADC
    "f5_tmsh":           "f5_tmsh",
    "citrix_netscaler":  "netscaler",
    # Firewalls
    "sonicwall":         "sonicwall",
    "pfsense":           "linux",
    "opnsense":          "linux",
    "sophos":            "linux",
    # SoHo / open-source
    "mikrotik":          "mikrotik_routeros",
    "ubiquiti_edge":     "ubiquiti_edge",
    "ubiquiti_unifi":    "linux",
    "vyos":              "vyos",
    # NAS
    "synology":          "linux",
    "qnap":              "linux",
    # Generic
    "generic_ssh":       "linux",
}


# Default command + banner-strip regex per device kind. The regex strips lines
# that change every time (timestamps, uptime, session IDs) so a cosmetic
# refresh doesn't create a spurious snapshot.
@dataclass(frozen=True)
class DeviceProfile:
    show_command: str
    strip_patterns: tuple[str, ...] = ()
    # default timeout for the SSH "send_command" operation, seconds
    read_timeout_s: float = 30.0


DEVICE_COMMANDS: dict[str, DeviceProfile] = {
    "cisco_ios": DeviceProfile(
        show_command="show running-config",
        strip_patterns=(r"^Building configuration.*$", r"^Current configuration : .*$",
                        r"^! Last configuration change at .*$",
                        r"^! NVRAM config last updated at .*$",
                        r"^ntp clock-period \d+$"),
    ),
    "cisco_iosxr": DeviceProfile(
        show_command="show running-config",
        strip_patterns=(r"^Building configuration.*$", r"^!! Last configuration change at .*$",
                        r"^!! IOS XR Configuration version = .*$"),
    ),
    "cisco_nxos": DeviceProfile(
        show_command="show running-config",
        strip_patterns=(r"^!Command: show running-config.*$",
                        r"^!Running configuration last done at.*$",
                        r"^!Time: .*$", r"^!Startup config saved at.*$"),
    ),
    "cisco_asa": DeviceProfile(
        show_command="more system:running-config",
        strip_patterns=(r"^: Saved$", r"^: Serial Number: .*$",
                        r"^: Hardware: .*$", r"^: Written by .*$"),
    ),
    "juniper_junos": DeviceProfile(
        show_command="show configuration | display set | no-more",
        strip_patterns=(r"^## Last commit: .*$",),
    ),
    "arista_eos": DeviceProfile(
        show_command="show running-config",
        strip_patterns=(r"^! device: .*$", r"^! boot system .*$"),
    ),
    "palo_alto": DeviceProfile(
        show_command="show config running",
        read_timeout_s=60.0,
    ),
    "fortinet": DeviceProfile(
        show_command="show full-configuration",
        strip_patterns=(r"^#conf-file-ver=.*$", r"^#buildno=.*$", r"^#global_vdom=.*$"),
        read_timeout_s=60.0,
    ),
    "mikrotik": DeviceProfile(
        show_command="/export terse",
        strip_patterns=(r"^# .* by RouterOS .*$",),
    ),
    "generic_ssh": DeviceProfile(
        show_command="cat /etc/network/interfaces 2>/dev/null; iptables-save 2>/dev/null",
    ),
    # Cisco family additions
    "cisco_iosxe": DeviceProfile(
        show_command="show running-config",
        strip_patterns=(r"^Building configuration.*$", r"^Current configuration : .*$",
                        r"^! Last configuration change at .*$"),
    ),
    "cisco_wlc": DeviceProfile(
        show_command="show run-config commands",
        read_timeout_s=60.0,
    ),
    "cisco_s300": DeviceProfile(show_command="show running-config"),
    # Aruba / HP
    "aruba_aoscx": DeviceProfile(
        show_command="show running-config",
        strip_patterns=(r"^!.*timestamp.*$",),
    ),
    "aruba_os": DeviceProfile(show_command="show running-config"),
    "hp_procurve": DeviceProfile(show_command="show running-config"),
    "hp_comware": DeviceProfile(
        show_command="display current-configuration",
        strip_patterns=(r"^# .* Comware Software, Version .*$",),
    ),
    # Dell
    "dell_os10": DeviceProfile(show_command="show running-configuration"),
    "dell_force10": DeviceProfile(show_command="show running-config"),
    "dell_powerconnect": DeviceProfile(show_command="show running-config"),
    # Other enterprise
    "huawei": DeviceProfile(show_command="display current-configuration"),
    "extreme_exos": DeviceProfile(
        show_command="show configuration",
        strip_patterns=(r"^# .* configuration generated .*$",),
    ),
    "brocade_fastiron": DeviceProfile(show_command="show running-config"),
    # ADC
    "f5_tmsh": DeviceProfile(
        show_command="list /sys running-config",
        read_timeout_s=120.0,
    ),
    "citrix_netscaler": DeviceProfile(show_command="show running-config"),
    # Firewalls / SoHo
    "sonicwall": DeviceProfile(show_command="export current-config cli"),
    "pfsense": DeviceProfile(
        show_command="cat /cf/conf/config.xml",
        strip_patterns=(r"^\s*<revision>.*</revision>$",),
        read_timeout_s=60.0,
    ),
    "opnsense": DeviceProfile(
        show_command="cat /conf/config.xml",
        strip_patterns=(r"^\s*<revision>.*</revision>$",),
        read_timeout_s=60.0,
    ),
    "sophos": DeviceProfile(
        show_command="system diagnostic show config",
        read_timeout_s=60.0,
    ),
    # SoHo + open-source
    "ubiquiti_edge": DeviceProfile(
        show_command="show configuration",
        strip_patterns=(r"^# Last login: .*$",),
    ),
    "ubiquiti_unifi": DeviceProfile(
        show_command="cat /etc/config/system.cfg 2>/dev/null || mca-dump",
        read_timeout_s=60.0,
    ),
    "vyos": DeviceProfile(show_command="show configuration commands"),
    # NAS
    "synology": DeviceProfile(
        show_command="cat /etc/synoinfo.conf; cat /etc/sysconfig/network 2>/dev/null",
    ),
    "qnap": DeviceProfile(
        show_command="cat /etc/config/uLinux.conf 2>/dev/null",
    ),
}


def _strip(text: str, patterns: tuple[str, ...]) -> str:
    if not patterns:
        return text
    compiled = [re.compile(p, re.MULTILINE) for p in patterns]
    out = text
    for c in compiled:
        out = c.sub("", out)
    # Collapse the blank lines created by stripping so the diff-vs-prev stays
    # legible — but keep the rest of the formatting intact.
    return re.sub(r"\n{3,}", "\n\n", out)


def _resolve_kind(kind: str) -> tuple[str, DeviceProfile]:
    if kind not in _NETMIKO_MAP:
        raise ValueError(f"unsupported device kind: {kind!r}")
    return _NETMIKO_MAP[kind], DEVICE_COMMANDS[kind]


def fetch_running_config(
    *,
    kind: str,
    host: str,
    port: int = 22,
    username: str | None = None,
    password: str | None = None,
    enable_password: str | None = None,
    conn_timeout_s: float = 15.0,
    read_timeout_s: float | None = None,
    overrides: dict | None = None,
) -> str:
    """Open an SSH session, grab the running config, return it stripped.

    Raises ValueError for unsupported kinds; re-raises netmiko exceptions as-is
    so the caller can distinguish auth failure from timeout from unreachable.
    """
    device_type, profile = _resolve_kind(kind)

    # Lazy import so `import app.devices` works on a machine without netmiko
    # installed (e.g. local dev box running only the web tier for a UI check).
    try:
        from netmiko import ConnectHandler
    except ImportError as e:
        raise RuntimeError(
            "netmiko is not installed — device config backup needs it. "
            "Install with: pip install netmiko"
        ) from e

    command = (overrides or {}).get("show_command") or profile.show_command
    effective_read_timeout = read_timeout_s or profile.read_timeout_s

    params: dict = {
        "device_type": device_type,
        "host": host,
        "port": port,
        "conn_timeout": conn_timeout_s,
        "banner_timeout": conn_timeout_s,
        "fast_cli": False,
    }
    if username:
        params["username"] = username
    if password:
        params["password"] = password
    if enable_password:
        params["secret"] = enable_password

    conn = ConnectHandler(**params)
    try:
        if enable_password and device_type.startswith("cisco"):
            conn.enable()
        raw = conn.send_command(command, read_timeout=effective_read_timeout)
    finally:
        try:
            conn.disconnect()
        except Exception:  # noqa: BLE001
            pass

    if not isinstance(raw, str) or not raw.strip():
        raise RuntimeError("empty response from device — command may have errored silently")
    return _strip(raw, profile.strip_patterns)
