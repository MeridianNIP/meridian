from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.sandbox.runner import run


# Linux IFNAMSIZ is 16 — 15 printable + NUL. This regex matches any legal ifname,
# plus the tcpdump pseudo-interface "any". Reject everything else at the app layer.
_IFACE_RE = re.compile(r"^(?:any|[A-Za-z0-9._-]{1,15})$")

# BPF filter expression — tcpdump parses this itself (no shell), but we still reject
# shell metacharacters at the app layer so our sandbox reject-list doesn't trip.
_BAD_BPF_CHARS = re.compile(r"[`$;|<>\n\r\\]")

# Cap the capture duration so a forgotten session can't fill disk. Admins who need
# longer captures should chain shorter ones or use a host-level tool.
MAX_DURATION_S = 120
MAX_PACKETS = 100_000
MAX_SNAPLEN = 65535
DEFAULT_SNAPLEN = 262      # enough for ethernet + IP + TCP + a few dozen bytes of payload


@dataclass(frozen=True)
class CaptureResult:
    capture_id: str
    interface: str
    bpf_filter: str
    duration_s: int
    max_packets: int
    snaplen: int
    path: Path
    size_bytes: int
    packets_captured: int | None
    packets_dropped: int | None
    returncode: int
    stderr_tail: str


def _validate(iface: str, bpf: str, duration_s: int, max_packets: int, snaplen: int) -> None:
    if not _IFACE_RE.match(iface):
        raise ValueError(f"interface name is not a legal Linux ifname: {iface!r}")
    if bpf and _BAD_BPF_CHARS.search(bpf):
        raise ValueError("BPF filter contains characters that look like shell metacharacters")
    if len(bpf) > 512:
        raise ValueError("BPF filter is too long (512 char limit)")
    if not (1 <= duration_s <= MAX_DURATION_S):
        raise ValueError(f"duration must be 1..{MAX_DURATION_S} seconds")
    if not (1 <= max_packets <= MAX_PACKETS):
        raise ValueError(f"max_packets must be 1..{MAX_PACKETS}")
    if not (64 <= snaplen <= MAX_SNAPLEN):
        raise ValueError(f"snaplen must be 64..{MAX_SNAPLEN}")


def _pcap_root() -> Path:
    root = get_settings().data_root / "pcaps"
    root.mkdir(parents=True, exist_ok=True)
    return root


_PKT_LINE = re.compile(r"(\d+)\s+packets?\s+(captured|received by filter|dropped by kernel)", re.I)


def _parse_tcpdump_stderr(stderr: str) -> tuple[int | None, int | None]:
    captured: int | None = None
    dropped: int | None = None
    for line in stderr.splitlines():
        m = _PKT_LINE.search(line)
        if not m:
            continue
        n, kind = int(m.group(1)), m.group(2).lower()
        if "captured" in kind:
            captured = n
        elif "dropped" in kind:
            dropped = n
    return captured, dropped


async def capture(
    *,
    owner_id: uuid.UUID,
    interface: str = "any",
    bpf_filter: str = "",
    duration_s: int = 10,
    max_packets: int = 5000,
    snaplen: int = DEFAULT_SNAPLEN,
) -> CaptureResult:
    """Run a bounded tcpdump capture and return the path to the resulting .pcap.

    The capture stops on whichever fires first: duration window elapses, packet
    count reached, or sandbox kill (safety margin). Requires CAP_NET_RAW on the
    tcpdump binary — the AppArmor profile and systemd unit grant this.
    """
    _validate(interface, bpf_filter, duration_s, max_packets, snaplen)
    capture_id = uuid.uuid4().hex
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest_dir = _pcap_root() / str(owner_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{ts}-{capture_id}.pcap"

    args: list[str] = [
        "-i", interface,
        "-w", str(dest),
        "-s", str(snaplen),
        "-c", str(max_packets),
        "-G", str(duration_s),
        "-W", "1",          # one rotation, then exit
        "-n",               # no name resolution
        "-q",               # quieter stderr
        "-Z", "root",       # don't try to drop privs to unknown user inside sandbox
    ]
    if bpf_filter.strip():
        args += bpf_filter.strip().split()

    result = await run(
        "tcpdump", args,
        timeout_s=float(duration_s + 10),   # safety net beyond -G
        max_output=64 * 1024,               # stderr only; file has the data
    )

    captured, dropped = _parse_tcpdump_stderr(result.stderr)
    size = dest.stat().st_size if dest.exists() else 0

    return CaptureResult(
        capture_id=capture_id,
        interface=interface,
        bpf_filter=bpf_filter,
        duration_s=duration_s,
        max_packets=max_packets,
        snaplen=snaplen,
        path=dest,
        size_bytes=size,
        packets_captured=captured,
        packets_dropped=dropped,
        returncode=result.returncode,
        stderr_tail="\n".join(result.stderr.strip().splitlines()[-8:]),
    )
