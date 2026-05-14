"""SSL / TLS wizard — deep cert inspection."""

from __future__ import annotations

from datetime import UTC, datetime

from app.certs.watchlist import fetch_remote_cert
from app.wizards.engine import Suggestion, WizardContext, WizardStep, wizard


def _parse_host_port(target: str) -> tuple[str, int]:
    if ":" in target:
        host, _, port = target.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, 443
    return target, 443


@wizard("ssl.deep_inspect")
async def ssl_deep_inspect(ctx: WizardContext) -> list[Suggestion]:
    host, port = _parse_host_port(ctx.target)

    try:
        info = await fetch_remote_cert(host, port, timeout_s=8.0)
    except Exception as e:
        ctx.add(
            WizardStep(
                name="TLS handshake",
                outcome="fail",
                message=f"Could not retrieve certificate from {host}:{port} — {e}",
            )
        )
        return [
            Suggestion(
                priority="critical",
                title="Handshake failed",
                detail="The endpoint did not complete a TLS handshake. Check firewall, SNI, port, or cert presence.",
            )
        ]

    ctx.add(
        WizardStep(name="TLS handshake", outcome="ok", message=f"Handshake succeeded against {host}:{port}")
    )

    # Hostname match
    sans = list(info.sans or [])
    hostname_ok = host in sans or any(san.startswith("*.") and host.endswith(san[1:]) for san in sans)
    if not hostname_ok and info.common_name:
        hostname_ok = host == info.common_name or (
            info.common_name.startswith("*.") and host.endswith(info.common_name[1:])
        )
    ctx.add(
        WizardStep(
            name="Hostname matches certificate",
            outcome="ok" if hostname_ok else "fail",
            message=("Hostname covered by SAN/CN" if hostname_ok else f"Hostname {host} not in SAN list"),
            detail={"cn": info.common_name, "san": sans[:10]},
        )
    )

    # Expiry
    now = datetime.now(UTC)
    valid_until = info.valid_until
    if valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=UTC)
    days = (valid_until - now).days
    sev = "ok" if days > 30 else "warn" if days > 7 else "fail"
    ctx.add(
        WizardStep(
            name="Expiry window",
            outcome=sev,
            message=f"{days} days until expiry ({valid_until.isoformat()})",
        )
    )

    # Issuer
    ctx.add(
        WizardStep(
            name="Issuer",
            outcome="info",
            message=f"{info.issuer or 'unknown'} · serial {info.serial_hex[:16] + '…' if info.serial_hex and len(info.serial_hex) > 16 else info.serial_hex}",
        )
    )

    # Key
    ctx.add(
        WizardStep(
            name="Key material",
            outcome="info",
            message=f"{info.key_type or 'unknown'} · {info.key_size or '?'}-bit · sig {info.signature_alg}",
        )
    )

    # Fingerprint (useful for pinning comparisons)
    ctx.add(
        WizardStep(
            name="SHA-256 fingerprint",
            outcome="info",
            message=info.fingerprint_sha256,
        )
    )

    # Self-signed heuristic — CertInfo doesn't keep the full subject DN,
    # so compare the issuer string against the parsed common_name as the
    # closest cheap proxy. A real CT-log lookup would be more robust but
    # requires a network round-trip we don't want on the fast path.
    if info.issuer and info.common_name and info.common_name in info.issuer:
        parts = [p.strip() for p in info.issuer.split(",")]
        if any(p.startswith("CN=") and p[3:] == info.common_name for p in parts):
            ctx.add(
                WizardStep(
                    name="Self-signed check",
                    outcome="warn",
                    message="Issuer CN equals subject CN — likely self-signed. Browsers won't trust this.",
                )
            )

    sug: list[Suggestion] = []
    if days <= 30:
        sug.append(
            Suggestion(
                priority="critical" if days <= 7 else "recommended",
                title=f"Certificate expires in {days} days",
                detail="Renew before users see warnings. ACME renewals typically start at 30 days.",
                tool_deeplink="/ui/certificates",
            )
        )
    if not hostname_ok:
        sug.append(
            Suggestion(
                priority="critical",
                title="Hostname mismatch",
                detail="Clients will refuse to trust this endpoint for this hostname. Reissue the cert with the right SANs.",
            )
        )
    return sug
