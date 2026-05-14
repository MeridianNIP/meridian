from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
import shlex
import shutil
import signal


class SandboxError(Exception):
    """Raised when a command is rejected before it can run (bad allowlist / args)."""


@dataclass(frozen=True)
class SandboxResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    truncated: bool
    timed_out: bool


# Allowlist of binaries the sandbox may invoke. Paths are discovered from $PATH
# at startup so Debian/Ubuntu differences (e.g. /usr/bin vs /usr/sbin/traceroute)
# don't need a code change. Anything missing is dropped; callers will get a
# "binary not in allowlist" error — clearer than running the wrong thing.
_ALLOWED_NAMES = (
    "dig",
    "host",
    "nslookup",
    "whois",
    "ping",
    "ping6",
    "traceroute",
    "tracepath",
    "mtr",
    "nmap",
    "curl",
    "openssl",
    "snmpwalk",
    "snmpget",
    "tcpdump",
)
ALLOWED_BINARIES: dict[str, Path] = {name: Path(_p) for name in _ALLOWED_NAMES if (_p := shutil.which(name))}


MAX_STDOUT_BYTES = 1 * 1024 * 1024  # 1 MiB per run; more than any legitimate tool output
DEFAULT_TIMEOUT_S = 30.0


def _reject_shell_metachars(args: Iterable[str]) -> None:
    bad = {"`", "$(", "&&", "||", ";", ">", "<", "|", "\n"}
    for a in args:
        for token in bad:
            if token in a:
                raise SandboxError(f"rejected argument (shell metacharacter): {a!r}")


async def run(
    binary: str,
    args: list[str],
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    env: dict[str, str] | None = None,
    stdin: bytes | None = None,
    max_output: int = MAX_STDOUT_BYTES,
) -> SandboxResult:
    """Execute a whitelisted binary with timeout + output cap.

    Never invokes a shell. Arguments pass as-is (after reject-list) into execve.
    """
    path = ALLOWED_BINARIES.get(binary)
    if path is None:
        raise SandboxError(f"binary not in allowlist: {binary!r}")
    if not path.exists():
        raise SandboxError(f"binary missing on disk: {path}")
    _reject_shell_metachars(args)

    safe_env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if env:
        safe_env.update(env)

    argv: tuple[str, ...] = (str(path), *args)
    loop = asyncio.get_event_loop()
    start = loop.time()

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=safe_env,
        # Start in its own session so we can SIGKILL the whole process group
        # on timeout, in case the child spawns children.
        start_new_session=True,
    )

    timed_out = False
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(input=stdin), timeout=timeout_s)
    except TimeoutError:
        timed_out = True
        try:
            import os

            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        stdout_b, stderr_b = await proc.communicate()

    duration_ms = int((loop.time() - start) * 1000)
    truncated = len(stdout_b) > max_output
    stdout = stdout_b[:max_output].decode(errors="replace")
    stderr = stderr_b[:max_output].decode(errors="replace")

    return SandboxResult(
        argv=argv,
        returncode=-9 if timed_out else (proc.returncode or 0),
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        truncated=truncated,
        timed_out=timed_out,
    )


def format_command(argv: tuple[str, ...]) -> str:
    return " ".join(shlex.quote(a) for a in argv)
