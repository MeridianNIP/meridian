"""Live system health checks + bounded repair actions.

Everything here is read-mostly or tightly scoped. Repairs that touch prod state
require the `admin.system.repair` permission; the two-person gate on that
permission means a second admin must approve via the normal approvals flow
before a destructive repair commits.

Design note: these checks duplicate a subset of `scripts/health_check.sh` on
purpose — the bash script is the boot-time source of truth (callable with no
Python stack), the Python version here powers the admin UI without shelling
out on every click.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import os
from pathlib import Path
import shutil
import subprocess

from cryptography import x509
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.config import get_settings


# ============================================================================
# Check framework
# ============================================================================
@dataclass(frozen=True)
class Check:
    name: str
    category: str  # 'service' | 'resource' | 'cert' | 'db' | 'key' | 'integrity' | 'tls'
    ok: bool
    severity: str  # 'ok' | 'warn' | 'fail'
    detail: str
    hint: str | None = None
    repair: str | None = None  # key the UI passes to POST /admin/health/repair
    # If True, the periodic auto-repair job is allowed to invoke `repair`
    # without an operator clicking. Set to False for anything destructive
    # (rebaseline, key rotation, retention cleanup) — those always need
    # a human in the loop.
    auto_repair: bool = False


# ============================================================================
# systemd / service checks
# ============================================================================
_MANAGED_SERVICES = [
    "postgresql.service",
    "nginx.service",
    # Debian 12 ships bind9.service; Debian 13 ships named.service.
    "bind9.service",
    "named.service",
    "meridian-app.service",
    "meridian-celery.service",
    "meridian-beat.service",
    "fail2ban.service",
    # Debian 12 ships redis-server; Debian 13 ships valkey-server.
    "redis-server.service",
    "valkey-server.service",
]

# Services that must be running for Meridian to function at all — any
# of these inactive means the portal is partially broken (postgres,
# DNS, web server, app, broker, beat, worker).
_REQUIRED_SERVICES = {
    "postgresql.service",
    "nginx.service",
    "bind9.service",
    "named.service",
    "meridian-app.service",
    "meridian-celery.service",
    "meridian-beat.service",
    "redis-server.service",
    "valkey-server.service",
}

# Optional services — nice-to-have, Meridian still serves requests
# without them. Inactive = warn (amber), not a failure.
_OPTIONAL_SERVICES = {"fail2ban.service"}


def _systemctl(verb: str, unit: str, timeout_s: float = 5.0) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            ["systemctl", verb, unit],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def _service_check(unit: str) -> Check | None:
    # Check LoadState up front — if the unit file doesn't exist on this host
    # (redis-server on Debian 13, named on Debian 12, etc.), hide the row.
    try:
        ls = subprocess.run(
            ["systemctl", "show", unit, "--property=LoadState", "--value"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if ls.stdout.strip() == "not-found":
            return None
    except (OSError, subprocess.TimeoutExpired):
        pass

    rc, active, _ = _systemctl("is-active", unit)
    if rc == 127:
        return Check(
            name=unit,
            category="service",
            ok=False,
            severity="fail",
            detail="systemctl unavailable",
            hint="is systemd running?",
        )

    # systemd `is-active` states: active, reloading, inactive, failed,
    # activating, deactivating. Severity depends on whether the unit
    # is required or optional:
    #   REQUIRED + active             → ok (green)
    #   REQUIRED + transient state    → warn (amber) — still coming up
    #   REQUIRED + inactive/failed    → fail (red)   — Meridian is broken
    #   OPTIONAL + active             → ok (green)
    #   OPTIONAL + anything else      → warn (amber) — won't break the portal
    ok = active == "active"
    is_transient = active in ("reloading", "activating", "deactivating")
    is_required = unit in _REQUIRED_SERVICES
    if ok:
        severity = "ok"
    elif is_transient:
        severity = "warn"
    elif is_required:
        severity = "fail"
    else:
        severity = "warn"
    return Check(
        name=unit,
        category="service",
        ok=ok,
        severity=severity,
        detail=active or "unknown",
        hint=(f"systemctl status {unit}" if not ok else None),
        repair=f"service:restart:{unit}" if not ok else None,
        # Restarting a stopped required daemon is the most common
        # 3am page and is idempotent. Optional services (fail2ban)
        # stay manual so a deliberately-stopped service doesn't
        # get auto-revived against operator intent.
        auto_repair=(not ok and is_required and not is_transient),
    )


# ============================================================================
# Resource checks
# ============================================================================
def _disk_check() -> Check:
    st = shutil.disk_usage("/")
    pct = int((st.used / st.total) * 100) if st.total else 0
    if pct < 85:
        return Check(name="disk / usage", category="resource", ok=True, severity="ok", detail=f"{pct}% used")
    if pct < 95:
        return Check(
            name="disk / usage",
            category="resource",
            ok=True,
            severity="warn",
            detail=f"{pct}% used",
            hint="purge retention or extend volume",
        )
    return Check(
        name="disk / usage",
        category="resource",
        ok=False,
        severity="fail",
        detail=f"{pct}% used — CRITICAL",
        hint="run retention cleanup or extend the volume NOW",
        repair="retention:run",
    )


def _memory_check() -> Check:
    try:
        with open("/proc/meminfo") as f:
            info = dict(
                (k.strip(), int(v.strip().split()[0]))
                for k, v in (line.split(":", 1) for line in f if ":" in line)
            )
    except OSError:
        return Check(
            name="memory", category="resource", ok=True, severity="warn", detail="/proc/meminfo unreadable"
        )
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", 0)
    if total <= 0:
        return Check(name="memory", category="resource", ok=True, severity="warn", detail="cannot compute")
    used_pct = int(((total - available) / total) * 100)
    sev = "ok" if used_pct < 85 else "warn" if used_pct < 95 else "fail"
    return Check(
        name="memory",
        category="resource",
        ok=(sev != "fail"),
        severity=sev,
        detail=f"{used_pct}% used ({(total - available) // 1024} MB of {total // 1024} MB)",
    )


# ============================================================================
# Cert expiry
# ============================================================================
def _cert_check() -> Check | None:
    s = get_settings()
    domain = s.portal_domain
    if not domain or domain == "localhost":
        return None
    cert_path = Path(f"/etc/letsencrypt/live/{domain}/cert.pem")
    if not cert_path.is_file():
        return Check(
            name=f"cert: {domain}",
            category="cert",
            ok=True,
            severity="warn",
            detail="no letsencrypt cert (self-signed portal?)",
        )
    try:
        data = cert_path.read_bytes()
        cert = x509.load_pem_x509_certificate(data)
        days = (cert.not_valid_after_utc - datetime.now(UTC)).days
    except Exception as e:
        return Check(
            name=f"cert: {domain}", category="cert", ok=False, severity="fail", detail=f"parse error: {e}"
        )
    if days > 30:
        return Check(
            name=f"cert: {domain}", category="cert", ok=True, severity="ok", detail=f"{days} days remaining"
        )
    if days > 7:
        return Check(
            name=f"cert: {domain}",
            category="cert",
            ok=True,
            severity="warn",
            detail=f"{days} days — renew within the week",
            hint="certbot renew",
            repair="cert:renew",
        )
    if days > 0:
        return Check(
            name=f"cert: {domain}",
            category="cert",
            ok=False,
            severity="fail",
            detail=f"{days} days — RENEW NOW",
            hint="certbot renew --force-renewal",
            repair="cert:renew",
        )
    return Check(
        name=f"cert: {domain}",
        category="cert",
        ok=False,
        severity="fail",
        detail="EXPIRED",
        repair="cert:renew",
    )


# ============================================================================
# DB + keys
# ============================================================================
def _db_check(db: OrmSession) -> Check:
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        return Check(
            name="postgres reachable",
            category="db",
            ok=False,
            severity="fail",
            detail=str(e)[:200],
            hint="systemctl status postgresql",
            repair="service:restart:postgresql.service",
        )
    return Check(name="postgres reachable", category="db", ok=True, severity="ok", detail="SELECT 1 passed")


def _key_check(path: Path, label: str) -> Check:
    if not path.is_file():
        return Check(
            name=label,
            category="key",
            ok=False,
            severity="fail",
            detail=f"missing: {path}",
            hint="install.sh should have placed this; re-run setup if lost",
        )
    mode = oct(path.stat().st_mode & 0o777)[-3:]
    if mode != "400":
        return Check(
            name=label,
            category="key",
            ok=True,
            severity="warn",
            detail=f"perms {mode} (want 400)",
            repair=f"key:chmod:{path}",
            # Idempotent + safe — just narrows the mode bits.
            auto_repair=True,
        )
    return Check(name=label, category="key", ok=True, severity="ok", detail="0400")


# ============================================================================
# TLS audit — shells out to scripts/audit-tls.sh and consumes its JSON
# ============================================================================
def _tls_check() -> Check | None:
    """Probe the portal's HTTPS endpoint via scripts/audit-tls.sh.
    Reports protocol mix, cert validity, OCSP stapling, HSTS. Uses the
    configured portal_domain — skips if it's still localhost (pre-install)."""
    import json

    s = get_settings()
    host = s.portal_domain
    if not host or host == "localhost":
        return None
    script = Path(s.install_root) / "scripts" / "audit-tls.sh"
    if not script.is_file():
        return Check(
            name=f"TLS audit: {host}",
            category="tls",
            ok=True,
            severity="warn",
            detail=f"{script} not found — deploy expected script/audit-tls.sh",
        )
    try:
        r = subprocess.run(
            ["bash", str(script), "--host", host, "--port", "443"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Check(
            name=f"TLS audit: {host}",
            category="tls",
            ok=False,
            severity="fail",
            detail="audit script timed out",
        )
    except Exception as e:
        return Check(
            name=f"TLS audit: {host}",
            category="tls",
            ok=False,
            severity="fail",
            detail=f"{type(e).__name__}: {e}",
        )
    try:
        data = json.loads(r.stdout)
    except Exception:
        return Check(
            name=f"TLS audit: {host}",
            category="tls",
            ok=False,
            severity="fail",
            detail=f"unparseable output: {(r.stderr or r.stdout or '')[:160]}",
        )
    if not data.get("ok"):
        return Check(
            name=f"TLS audit: {host}",
            category="tls",
            ok=False,
            severity="fail",
            detail=data.get("error", "audit failed"),
        )
    grade = data.get("grade", "ok")
    sev = {"ok": "ok", "warn": "warn", "fail": "fail"}.get(grade, "warn")
    issues = data.get("issues") or []
    if issues:
        detail = "; ".join(issues[:4])
    else:
        days = data.get("days_left")
        protos = data.get("protocols", {})
        detail = (
            f"{days}d left · TLS "
            f"{'1.3' if protos.get('tls13') == 'ok' else '1.2'}"
            f" · {data.get('signature_algorithm','?')}"
        )
    # Map the worst issue to a one-click repair action. Each repair writes
    # the appropriate nginx directive to /etc/meridian/nginx-overrides/
    # and reloads nginx — no shell, no file editing.
    repair_key: str | None = None
    hint = "Full detail in the TLS audit card below."
    if any("OCSP" in i for i in issues):
        repair_key = "tls:enable_ocsp_stapling"
        hint = "Click Repair to enable OCSP stapling + reload nginx."
    elif any("HSTS" in i for i in issues):
        repair_key = "tls:enable_hsts"
        hint = "Click Repair to add the HSTS header + reload nginx."
    elif any("TLS 1.0" in i or "TLS 1.1" in i for i in issues):
        repair_key = "tls:disable_legacy_tls"
        hint = "Click Repair to pin nginx to TLS 1.2+ and reload."
    elif any("expires" in i.lower() for i in issues):
        repair_key = "cert:renew"
        hint = "Click Repair to renew the certificate."

    return Check(
        name=f"TLS audit: {host}",
        category="tls",
        ok=(grade != "fail"),
        severity=sev,
        detail=detail,
        hint=hint,
        repair=repair_key,
    )


# ============================================================================
# Integrity (HMAC row-hash chain)
# ============================================================================
def _integrity_check(db: OrmSession) -> Check:
    row = db.execute(
        text("""
        SELECT started_at, completed_at, mismatches, status
          FROM db_integrity_scans
         ORDER BY started_at DESC LIMIT 1
    """)
    ).first()
    if row is None:
        return Check(
            name="integrity scan",
            category="integrity",
            ok=True,
            severity="warn",
            detail="never run — click repair to run now",
            repair="integrity:rescan",
        )
    started, completed, mismatches, status = row
    age_h = int((datetime.now(UTC) - started).total_seconds() // 3600) if started else None
    if mismatches and mismatches > 0:
        return Check(
            name="integrity scan",
            category="integrity",
            ok=False,
            severity="fail",
            detail=f"{mismatches} tamper-evident row mismatch(es) — last scan {age_h}h ago",
            hint="investigate — rows may have been modified outside the app",
            repair="integrity:rescan",
        )
    if status == "error":
        return Check(
            name="integrity scan",
            category="integrity",
            ok=False,
            severity="fail",
            detail=f"last scan errored {age_h}h ago",
            repair="integrity:rescan",
        )
    if age_h is not None and age_h > 48:
        return Check(
            name="integrity scan",
            category="integrity",
            ok=True,
            severity="warn",
            detail=f"last clean scan was {age_h}h ago",
            repair="integrity:rescan",
        )
    return Check(
        name="integrity scan", category="integrity", ok=True, severity="ok", detail=f"last clean {age_h}h ago"
    )


# ============================================================================
# Aggregate
# ============================================================================
def run_all(db: OrmSession) -> list[Check]:
    checks: list[Check] = []
    for unit in _MANAGED_SERVICES:
        c = _service_check(unit)
        if c is not None:
            checks.append(c)

    checks.append(_db_check(db))
    checks.append(_disk_check())
    checks.append(_memory_check())

    cert = _cert_check()
    if cert is not None:
        checks.append(cert)

    tls = _tls_check()
    if tls is not None:
        checks.append(tls)

    s = get_settings()
    checks.append(_key_check(s.master_key_path, "master.key"))
    checks.append(_key_check(s.row_hmac_key_path, "row_hmac.key"))

    checks.append(_integrity_check(db))
    return checks


# ============================================================================
# Repair actions
# ============================================================================
_REPAIR_ALLOWLIST_SERVICES = {
    "nginx.service",
    "bind9.service",
    "meridian-app.service",
    "meridian-celery.service",
    "meridian-beat.service",
    "fail2ban.service",
    "redis-server.service",
    "valkey-server.service",
    "postgresql.service",
}


@dataclass(frozen=True)
class RepairResult:
    action: str
    ok: bool
    detail: str
    output: str = ""


def _sudo_systemctl(verb: str, unit: str, *, timeout_s: float = 20.0) -> tuple[int, str, str]:
    """Restart / start / stop a managed unit via the sudoers drop-in
    `/etc/sudoers.d/meridian-services` installed by install.sh. The
    meridian user has NOPASSWD access to exactly the allowlisted
    verbs + units; nothing else is granted."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", verb, unit],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def _repair_service_restart(arg: str) -> RepairResult:
    unit = arg
    if unit not in _REPAIR_ALLOWLIST_SERVICES:
        return RepairResult(
            action=f"service:restart:{unit}", ok=False, detail=f"service not in repair allowlist: {unit}"
        )
    # The portal runs as `meridian` (non-root), so systemctl restart
    # requires a sudoers drop-in. If sudo returns "a password is
    # required" or similar, we surface that message so the operator
    # knows what to fix rather than silently failing.
    rc, out, err = _sudo_systemctl("restart", unit)
    if rc != 0:
        hint = (
            "sudoers entry missing?"
            if "password is required" in err.lower() or "access denied" in err.lower()
            else ""
        )
        return RepairResult(
            action=f"service:restart:{unit}",
            ok=False,
            detail=f"restart exited {rc}" + (f" ({hint})" if hint else ""),
            output=(err or out)[:400],
        )
    rc2, active, _ = _systemctl("is-active", unit)
    return RepairResult(
        action=f"service:restart:{unit}", ok=(active == "active"), detail=f"now {active}", output=""
    )


def _repair_bind_reload() -> RepairResult:
    if not shutil.which("rndc"):
        return RepairResult(action="bind:reload", ok=False, detail="rndc not found on PATH")
    try:
        r = subprocess.run(["rndc", "reload"], capture_output=True, text=True, timeout=15, check=False)
        return RepairResult(
            action="bind:reload",
            ok=(r.returncode == 0),
            detail="rndc reload returned " + str(r.returncode),
            output=((r.stdout or "") + (r.stderr or ""))[:400],
        )
    except (OSError, subprocess.SubprocessError) as e:
        return RepairResult(action="bind:reload", ok=False, detail=str(e))


def _repair_permissions_reseed(db: OrmSession) -> RepairResult:
    """Re-run the permissions seed so any role_permissions drift is corrected."""
    try:
        perms = db.execute(text("SELECT key FROM permissions")).scalars().all()
        # Super admin should always hold every permission. Re-insert missing ones.
        existing = (
            db.execute(
                text("""
            SELECT permission FROM role_permissions WHERE role = 'super_admin'
        """)
            )
            .scalars()
            .all()
        )
        missing = sorted(set(perms) - set(existing))
        for p in missing:
            db.execute(
                text("""
                INSERT INTO role_permissions (role, permission)
                VALUES ('super_admin', :p) ON CONFLICT DO NOTHING
            """),
                {"p": p},
            )
        db.commit()
        return RepairResult(
            action="permissions:reseed",
            ok=True,
            detail=f"added {len(missing)} missing super_admin grant(s)",
            output=", ".join(missing[:20]),
        )
    except Exception as e:
        return RepairResult(action="permissions:reseed", ok=False, detail=str(e)[:400])


def _repair_key_chmod(path: str) -> RepairResult:
    s = get_settings()
    allowed = {str(s.master_key_path), str(s.row_hmac_key_path)}
    if path not in allowed:
        return RepairResult(action=f"key:chmod:{path}", ok=False, detail="path not in allowlist")
    try:
        os.chmod(path, 0o400)
        return RepairResult(action=f"key:chmod:{path}", ok=True, detail="set to 0400")
    except OSError as e:
        return RepairResult(action=f"key:chmod:{path}", ok=False, detail=str(e))


def _repair_integrity_rescan() -> RepairResult:
    from app.jobs.integrity import scan as integrity_scan

    try:
        async_result = integrity_scan.delay()
        return RepairResult(action="integrity:rescan", ok=True, detail="queued", output=async_result.id)
    except Exception as e:
        return RepairResult(action="integrity:rescan", ok=False, detail=f"celery broker unavailable: {e}")


def _repair_retention_run() -> RepairResult:
    from app.jobs.retention import audit_cleanup

    try:
        async_result = audit_cleanup.delay()
        return RepairResult(
            action="retention:run", ok=True, detail="audit retention cleanup queued", output=async_result.id
        )
    except Exception as e:
        return RepairResult(action="retention:run", ok=False, detail=f"celery broker unavailable: {e}")


def _repair_cert_renew() -> RepairResult:
    if not shutil.which("certbot"):
        return RepairResult(action="cert:renew", ok=False, detail="certbot not on PATH")
    # certbot needs writable dirs + root-owned config. Short-circuit with a
    # useful message on hosts that never ran certbot (self-signed / airgapped)
    # instead of the obscure "Read-only file system: /var/log/letsencrypt".
    import os

    if not os.path.isdir("/etc/letsencrypt/live"):
        return RepairResult(
            action="cert:renew",
            ok=False,
            detail="no Let's Encrypt certs registered on this host",
            output="This install appears to use self-signed or Cloudflare-origin "
            "certs — certbot renew is a no-op here. Re-run install.sh with "
            "SSL_METHOD=letsencrypt if you want ACME-managed certs.",
        )
    try:
        # certbot needs root: writes to /etc/letsencrypt, grabs
        # /var/log/letsencrypt/.certbot.lock, may bind 80/tcp for
        # http-01. Use the meridian-certbot sudoers drop-in.
        r = subprocess.run(
            ["sudo", "-n", "/usr/bin/certbot", "renew", "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return RepairResult(
            action="cert:renew",
            ok=(r.returncode == 0),
            detail=f"certbot exited {r.returncode}",
            output=((r.stdout or "") + (r.stderr or ""))[:600],
        )
    except (OSError, subprocess.SubprocessError) as e:
        return RepairResult(action="cert:renew", ok=False, detail=str(e))


# ---------------------------------------------------------------------------
# TLS hardening repairs — all write to /etc/meridian/nginx-overrides/<file>,
# which the portal site config includes from the server { } block. The
# meridian user owns that directory; sudoers allows nginx -t + systemctl
# reload nginx.service so the portal can apply changes without shelling out.
# ---------------------------------------------------------------------------
_TLS_OVERRIDE_DIR = "/etc/meridian/nginx-overrides"


def _nginx_reload() -> tuple[bool, str]:
    """Test the nginx config, then reload on success. Returns (ok, output)."""
    try:
        t = subprocess.run(
            ["sudo", "-n", "/usr/sbin/nginx", "-t"], capture_output=True, text=True, timeout=10, check=False
        )
        if t.returncode != 0:
            return False, f"nginx -t failed:\n{(t.stderr or t.stdout)[:400]}"
        r = subprocess.run(
            ["sudo", "-n", "/bin/systemctl", "reload", "nginx.service"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return (r.returncode == 0), ((r.stdout or "") + (r.stderr or ""))[:200]
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)


def _tls_write_override(filename: str, directives: str) -> tuple[bool, str]:
    """Atomically write an nginx-overrides snippet. Returns (ok, detail)."""
    target = Path(_TLS_OVERRIDE_DIR) / filename
    if not Path(_TLS_OVERRIDE_DIR).is_dir():
        return False, (
            f"{_TLS_OVERRIDE_DIR} does not exist — run the "
            "one-time nginx-overrides bootstrap (see docs/admin/recovery.md)"
        )
    try:
        tmp = target.with_suffix(target.suffix + ".new")
        tmp.write_text(directives)
        tmp.replace(target)
        return True, f"wrote {target}"
    except OSError as e:
        return False, f"write failed: {e}"


def _repair_tls_enable_ocsp_stapling() -> RepairResult:
    ok, detail = _tls_write_override(
        "ocsp-stapling.conf",
        "# Portal-managed · Admin Panel → System Health\n"
        "ssl_stapling on;\n"
        "ssl_stapling_verify on;\n"
        "resolver 1.1.1.1 9.9.9.9 valid=300s;\n"
        "resolver_timeout 5s;\n",
    )
    if not ok:
        return RepairResult(action="tls:enable_ocsp_stapling", ok=False, detail=detail)
    reload_ok, reload_out = _nginx_reload()
    return RepairResult(
        action="tls:enable_ocsp_stapling",
        ok=reload_ok,
        detail=(
            "OCSP stapling enabled + nginx reloaded"
            if reload_ok
            else f"directive written but nginx reload failed: {reload_out}"
        ),
        output=reload_out,
    )


def _repair_tls_enable_hsts() -> RepairResult:
    ok, detail = _tls_write_override(
        "hsts.conf",
        "# Portal-managed · Admin Panel → System Health\n"
        "add_header Strict-Transport-Security "
        '"max-age=63072000; includeSubDomains" always;\n',
    )
    if not ok:
        return RepairResult(action="tls:enable_hsts", ok=False, detail=detail)
    reload_ok, reload_out = _nginx_reload()
    return RepairResult(
        action="tls:enable_hsts",
        ok=reload_ok,
        detail=(
            "HSTS header enabled + nginx reloaded"
            if reload_ok
            else f"directive written but nginx reload failed: {reload_out}"
        ),
        output=reload_out,
    )


def _repair_tls_disable_legacy_tls() -> RepairResult:
    ok, detail = _tls_write_override(
        "protocols.conf",
        "# Portal-managed · Admin Panel → System Health\n"
        "ssl_protocols TLSv1.2 TLSv1.3;\n"
        "ssl_prefer_server_ciphers off;\n",
    )
    if not ok:
        return RepairResult(action="tls:disable_legacy_tls", ok=False, detail=detail)
    reload_ok, reload_out = _nginx_reload()
    return RepairResult(
        action="tls:disable_legacy_tls",
        ok=reload_ok,
        detail=(
            "Legacy TLS disabled (TLS 1.2+ only) + nginx reloaded"
            if reload_ok
            else f"directive written but nginx reload failed: {reload_out}"
        ),
        output=reload_out,
    )


def _repair_integrity_rebaseline() -> RepairResult:
    """Re-compute row_hash for every row in every tamper-evident table
    using the CURRENT canonicalize algorithm, regardless of what's
    already stored. Used after a legitimate code change to the
    canonicalize() function itself (e.g. when a new column is added to
    an audited table). After rebaselining, subsequent rows get the new
    algorithm's hash at insert time, and the scan chain is valid again.

    Destructive: overwrites every row_hash on every tamper-evident table.
    Requires `admin.system.repair` + respects_cab=TRUE via the approvals
    layer (the action is flagged destructive on the client).
    """
    from app.audit.logger import record as audit
    from app.db import session_scope
    from app.integrity.hmac_chain import (
        TAMPER_EVIDENT_TABLES,
        canonicalize,
        row_hash,
    )
    from app.jobs.integrity import _CANONICAL_COLUMNS

    tables_done: list[dict] = []
    with session_scope() as db:
        for table in TAMPER_EVIDENT_TABLES:
            cols = _CANONICAL_COLUMNS.get(table)
            if cols is None:
                continue
            order_col = "id" if "id" in cols else "ts"
            col_list = ", ".join(cols)
            rows = db.execute(text(f"SELECT {col_list} FROM {table} ORDER BY {order_col}")).fetchall()

            prev_hash = None
            n = 0
            pk_col = "id" if "id" in cols else None
            for r in rows:
                values = dict(zip(cols, r, strict=False))
                canonical_values = {k: v for k, v in values.items() if k != "id"}
                new_hash = row_hash(canonicalize(canonical_values), prev_hash)
                if pk_col is not None:
                    db.execute(
                        text(f"UPDATE {table} SET row_hash = :h WHERE {pk_col} = :pk"),
                        {"h": new_hash, "pk": values[pk_col]},
                    )
                    n += 1
                prev_hash = new_hash
            tables_done.append({"table": table, "rows": n})
        db.commit()

        audit(
            db,
            action="integrity.rebaseline",
            payload={"tables": tables_done, "total_rows": sum(t["rows"] for t in tables_done)},
            outcome="warn",
        )  # always notable in audit

    total = sum(t["rows"] for t in tables_done)
    return RepairResult(
        action="integrity:rebaseline",
        ok=True,
        detail=f"re-hashed {total} row(s) across {len(tables_done)} table(s)",
        output=", ".join(f"{t['table']}:{t['rows']}" for t in tables_done),
    )


_REPAIR_DISPATCH: dict[str, Callable[[], RepairResult] | Callable[[str], RepairResult]] = {
    "bind:reload": lambda: _repair_bind_reload(),
    "integrity:rescan": lambda: _repair_integrity_rescan(),
    "integrity:rebaseline": lambda: _repair_integrity_rebaseline(),
    "retention:run": lambda: _repair_retention_run(),
    "cert:renew": lambda: _repair_cert_renew(),
    "tls:enable_ocsp_stapling": lambda: _repair_tls_enable_ocsp_stapling(),
    "tls:enable_hsts": lambda: _repair_tls_enable_hsts(),
    "tls:disable_legacy_tls": lambda: _repair_tls_disable_legacy_tls(),
}


def repair(action: str, db: OrmSession) -> RepairResult:
    """Dispatch a repair action. `action` is a colon-separated key issued by run_all."""
    if action in _REPAIR_DISPATCH:
        return _REPAIR_DISPATCH[action]()
    if action.startswith("service:restart:"):
        return _repair_service_restart(action.split(":", 2)[2])
    if action.startswith("key:chmod:"):
        return _repair_key_chmod(action.split(":", 2)[2])
    if action == "permissions:reseed":
        return _repair_permissions_reseed(db)
    return RepairResult(action=action, ok=False, detail="unknown repair action")


# Repair actions the UI can present as buttons regardless of whether a check failed.
PROACTIVE_REPAIRS: list[dict[str, str]] = [
    {"key": "bind:reload", "label": "Reload BIND zones", "scope": "non-destructive"},
    {"key": "integrity:rescan", "label": "Re-run integrity scan", "scope": "non-destructive"},
    {
        "key": "integrity:rebaseline",
        "label": "Rebaseline integrity chain",
        "scope": "destructive · two-person",
    },
    {"key": "retention:run", "label": "Run audit retention cleanup", "scope": "destructive · two-person"},
    {"key": "permissions:reseed", "label": "Re-seed super_admin grants", "scope": "idempotent"},
    {"key": "cert:renew", "label": "certbot renew", "scope": "non-destructive"},
    {"key": "tls:enable_ocsp_stapling", "label": "Enable OCSP stapling", "scope": "non-destructive"},
    {"key": "tls:enable_hsts", "label": "Enable HSTS header", "scope": "non-destructive"},
    {"key": "tls:disable_legacy_tls", "label": "Pin nginx to TLS 1.2+", "scope": "non-destructive"},
]
