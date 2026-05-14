from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.audit.logger import record as audit
from app.celery_app import celery_app
from app.certs.watchlist import fetch_remote_cert
from app.db import session_scope
from app.models.cert import Certificate

_THRESHOLDS = (30, 14, 7, 3, 1)


@celery_app.task(name="meridian.jobs.cert.expiry_check")
def expiry_check() -> dict[str, Any]:
    """Refresh every monitored cert + emit escalation events at threshold crossings."""
    now = datetime.now(UTC)
    fired: list[dict[str, Any]] = []

    # Per-cert channel routing — populated as each refresh lands.
    cert_channels: dict[str, list] = {}
    fp_changes: list[dict[str, Any]] = []

    def _host_for(cert: Certificate) -> str:
        cn = cert.common_name or ""
        if cn and not cn.startswith("*"):
            return cn
        for san in cert.sans or []:
            if san and not san.startswith("*"):
                return san
        return cn[2:] if cn.startswith("*.") else cn

    async def _refresh(c: Certificate) -> None:
        host = _host_for(c)
        try:
            info = await fetch_remote_cert(host, 443)
        except Exception as e:
            c.last_renew_status = f"fetch_failed ({host}): {e}"
            return
        old_fp = c.fingerprint_sha256
        c.valid_until = info.valid_until
        c.fingerprint_sha256 = info.fingerprint_sha256
        c.issuer = info.issuer
        c.leaf_pem = info.leaf_pem
        if old_fp and old_fp != info.fingerprint_sha256:
            fp_changes.append(
                {
                    "cn": c.common_name,
                    "old_fp": old_fp,
                    "new_fp": info.fingerprint_sha256,
                    "channels": list(c.notify_channels or []),
                }
            )

    with session_scope() as db:
        monitored = (
            db.execute(select(Certificate).where(Certificate.cert_type == "monitored")).scalars().all()
        )
        if monitored:
            # Bound concurrency — without this, a portfolio of 1000 monitored
            # certs would open 1000 simultaneous TLS connections every sweep,
            # which is a DDoS-against-self at worst and a noisy thunderclap
            # against the cert hosts at minimum.
            from app.safety.limits import CERT_REFRESH_CONCURRENCY, bounded_gather

            asyncio.run(
                bounded_gather(
                    (_refresh(c) for c in monitored),
                    max_workers=CERT_REFRESH_CONCURRENCY,
                )
            )

        for c in monitored:
            cert_channels[c.common_name] = list(c.notify_channels or [])
            if c.valid_until is None:
                continue
            days = max(0, (c.valid_until - now).days)
            for t in _THRESHOLDS:
                if days == t:
                    audit(
                        db,
                        action="cert.expiry.threshold",
                        target_type="cert",
                        target_key=c.common_name,
                        payload={"days_remaining": days, "threshold": t},
                    )
                    fired.append(
                        {
                            "cn": c.common_name,
                            "threshold": t,
                            "days": days,
                            "channels": list(c.notify_channels or []),
                        }
                    )
                    break

        # Fingerprint-change alerts — route through each cert's own channels
        # so an unexpected rotation goes to the asset owner, not a global list.
        for ev in fp_changes:
            try:
                from app.notifications.dispatcher import dispatch

                dispatch(
                    db,
                    event_kind="cert.fingerprint_changed",
                    subject=f"[Meridian] cert fingerprint changed: {ev['cn']}",
                    body=(
                        f"Common name: {ev['cn']}\n"
                        f"Old fingerprint: {ev['old_fp']}\n"
                        f"New fingerprint: {ev['new_fp']}\n"
                        f"If a rotation wasn't expected, this may indicate a "
                        f"MITM, unplanned re-issue, or hijack."
                    ),
                    payload={"cn": ev["cn"], "old_fp": ev["old_fp"], "new_fp": ev["new_fp"]},
                    channel_ids=ev["channels"] or None,
                )
            except Exception:
                pass

        if fired:
            # Per-cert routing: group fired events by the channel set they
            # should go to, so a cert with its own notify_channels doesn't
            # also spam the global default list.
            from collections import defaultdict

            by_channels: dict[tuple, list] = defaultdict(list)
            for e in fired:
                key = tuple(sorted(str(c) for c in e.get("channels") or []))
                by_channels[key].append(e)
            try:
                from app.notifications.dispatcher import dispatch

                for key, group in by_channels.items():
                    subject = f"{len(group)} certificate(s) near expiry"
                    body = "\n".join(
                        f"{e['cn']} · {e['days']} day(s) · threshold {e['threshold']}" for e in group
                    )
                    dispatch(
                        db,
                        event_kind="cert.expiring",
                        subject=subject,
                        body=body,
                        payload={
                            "fired": [
                                {"cn": e["cn"], "days": e["days"], "threshold": e["threshold"]} for e in group
                            ]
                        },
                        channel_ids=list(key) or None,
                    )
            except Exception:
                pass
            try:
                from app.webhooks.dispatcher import fanout

                subject = f"{len(fired)} certificate(s) near expiry"
                body = "\n".join(
                    f"{e['cn']} · {e['days']} day(s) · threshold {e['threshold']}" for e in fired
                )
                fanout(
                    db,
                    event="cert.expiring",
                    subject=subject,
                    body=body,
                    payload={
                        "fired": [
                            {"cn": e["cn"], "days": e["days"], "threshold": e["threshold"]} for e in fired
                        ]
                    },
                )
            except Exception:
                pass

        return {"checked": len(monitored), "fired": fired, "fingerprint_changes": len(fp_changes)}


# ============================================================================
# auto_renew — renewable ACME certs within renew threshold, one-shot notify
# for manual certs
# ============================================================================
_DEFAULT_RENEW_WINDOW_DAYS = 30


@celery_app.task(name="meridian.jobs.cert.auto_renew")
def auto_renew() -> dict[str, Any]:
    """Walk certificates with auto_renew=TRUE and attempt renewal.

    The portal's own cert uses certbot (wrapped in admin/health repair). This
    task handles the broader renewal loop: for each auto-renew cert, if we're
    inside the renew window, invoke certbot with the stored challenge method;
    for cert_type='internal' without ACME, emit a notification so ops renews
    out-of-band.
    """

    now = datetime.now(UTC)
    window = timedelta(days=_DEFAULT_RENEW_WINDOW_DAYS)
    attempted: list[dict[str, Any]] = []
    manual_due: list[dict[str, Any]] = []

    with session_scope() as db:
        candidates = db.execute(select(Certificate).where(Certificate.auto_renew.is_(True))).scalars().all()

        for c in candidates:
            if c.valid_until is None:
                continue
            remaining = c.valid_until - now
            if remaining > window:
                continue

            if c.cert_type == "portal" and c.challenge_type in ("http_01", "dns_01", "tls_alpn_01"):
                rc, stderr_tail = _certbot_renew(c.common_name)
                status = "ok" if rc == 0 else "failed"
                c.last_renew_status = status + (f": {stderr_tail}" if stderr_tail else "")
                c.last_renew_at = now
                attempted.append(
                    {"cn": c.common_name, "status": status, "rc": rc, "stderr_tail": stderr_tail}
                )
                audit(
                    db,
                    action="cert.auto_renew",
                    target_type="cert",
                    target_key=c.common_name,
                    payload={
                        "days_remaining": remaining.days,
                        "rc": rc,
                        "status": status,
                        "stderr_tail": stderr_tail,
                    },
                    outcome="ok" if rc == 0 else "error",
                )
            else:
                manual_due.append(
                    {"cn": c.common_name, "days_remaining": remaining.days, "cert_type": c.cert_type}
                )

        if manual_due:
            try:
                from app.notifications.dispatcher import dispatch

                dispatch(
                    db,
                    event_kind="cert.renew_manual",
                    subject=f"{len(manual_due)} cert(s) need manual renewal",
                    body="\n".join(
                        f"{m['cn']} · {m['days_remaining']} day(s) · {m['cert_type']}" for m in manual_due
                    ),
                    payload={"certs": manual_due},
                )
            except Exception:
                pass

    return {"candidates": len(attempted) + len(manual_due), "attempted": attempted, "manual_due": manual_due}


def _certbot_renew(domain: str) -> tuple[int, str]:
    import shutil
    import subprocess

    if not shutil.which("certbot"):
        return (127, "certbot not on PATH")
    try:
        r = subprocess.run(
            ["certbot", "renew", "--cert-name", domain, "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-3:]
        return (r.returncode, " · ".join(tail)[:400])
    except (OSError, subprocess.SubprocessError) as e:
        return (127, f"{type(e).__name__}: {e}")
