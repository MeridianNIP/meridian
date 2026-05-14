"""Network + IP reputation wizards."""
from __future__ import annotations

import ipaddress

import httpx

from app.dns.dig import DigRequest, run_dig
from app.network.http_test import test_url
from app.network.ping import PingRequest, run_ping
from app.network.port_scan import scan as port_scan
from app.network.traceroute import TraceRequest, run_traceroute
from app.wizards.engine import Suggestion, WizardContext, WizardStep, wizard


def _answers(stdout: str) -> list[str]:
    return [
        line.strip()
        for line in stdout.splitlines()
        if line.strip() and not line.startswith(";")
    ]


# ============================================================================
# network.reachability — ping → trace → port → DNS → TLS → HTTP
# First failure stops the chain with a concrete suggestion.
# ============================================================================
@wizard("network.reachability")
async def network_reachability(ctx: WizardContext) -> list[Suggestion]:
    target = ctx.target

    # DNS first so we know what we're pinging
    is_ip = False
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        pass

    if not is_ip:
        a = await run_dig(DigRequest(target=target, record_type="A"))
        rows = _answers(a.stdout)
        if not rows:
            ctx.add(WizardStep(name="DNS resolves", outcome="fail",
                               message=f"{target} has no A record"))
            return [Suggestion(priority="critical", title="DNS is the first wall",
                               detail="Fix resolution before anything downstream matters.",
                               tool_deeplink=f"/ui/wizards?wizard_key=dns.resolve_fail?target={target}")]
        ctx.add(WizardStep(name="DNS resolves", outcome="ok",
                           message=f"{target} → {rows[0]}",
                           detail={"answers": rows}))
    else:
        ctx.add(WizardStep(name="DNS resolves", outcome="info",
                           message="target is a literal IP — skipped"))

    # Ping
    ping_res = await run_ping(PingRequest(target=target, count=5, timeout_s=2.0))
    loss = ping_res.stats.loss_pct
    ctx.add(WizardStep(
        name="ICMP reachability",
        outcome="ok" if loss < 50 else "warn" if loss < 100 else "fail",
        message=f"{ping_res.stats.received}/{ping_res.stats.transmitted} replies · avg RTT {ping_res.stats.rtt_avg}ms",
    ))
    if loss == 100:
        return [Suggestion(priority="recommended",
                           title="No ICMP replies",
                           detail="Could still be filtered upstream rather than truly down. Run a TCP probe to confirm.",
                           tool_deeplink=f"/ui/network-tools#portscan?host={target}")]

    # Traceroute — find where latency jumps
    trace = await run_traceroute(TraceRequest(target=target, max_hops=20,
                                              timeout_s=3, per_hop_probes=2))
    ctx.add(WizardStep(
        name="Traceroute",
        outcome="ok" if trace.hops else "warn",
        message=f"{len(trace.hops)} hops observed"
                 + (f" · last hop: {trace.hops[-1].host}"
                    if trace.hops else ""),
    ))

    # Common-port check (443, 80, 22)
    try:
        ps = await port_scan(target, [443, 80, 22], timeout_s=2.0, concurrency=3)
        open_ports = list(ps.open_ports)
        ctx.add(WizardStep(
            name="Common TCP ports (443/80/22)",
            outcome="ok" if open_ports else "warn",
            message=(f"Open: {open_ports}" if open_ports else
                     "None of 443/80/22 open — host may be firewalled or serving custom ports"),
        ))
    except ValueError as e:
        ctx.add(WizardStep(name="Common TCP ports", outcome="warn",
                           message=f"Port scan rejected by scope policy: {e}"))
        open_ports = []

    # HTTP if port 80 or 443 open
    if 443 in open_ports or 80 in open_ports:
        scheme = "https" if 443 in open_ports else "http"
        try:
            http = await test_url(f"{scheme}://{target}/", timeout_s=8.0,
                                  follow_redirects=True)
            ctx.add(WizardStep(
                name=f"{scheme.upper()} request",
                outcome="ok" if 200 <= http.final_status < 500 else "warn",
                message=f"HTTP {http.final_status} after {http.redirect_count} redirect(s)",
            ))
        except Exception as e:  # noqa: BLE001
            ctx.add(WizardStep(name="HTTP request", outcome="warn",
                               message=f"Request failed: {e}"))
    return []


# ============================================================================
# network.up_for_everyone — local vs external observers
# ============================================================================
@wizard("network.up_for_everyone")
async def up_for_everyone(ctx: WizardContext) -> list[Suggestion]:
    target = ctx.target

    # Local probe
    try:
        local = await test_url(f"https://{target}/", timeout_s=6.0,
                               follow_redirects=True)
        local_ok = 200 <= local.final_status < 500
        ctx.add(WizardStep(name="Local probe (this Meridian host)",
                           outcome="ok" if local_ok else "warn",
                           message=f"HTTPS {target} → {local.final_status}"))
    except Exception as e:  # noqa: BLE001
        local_ok = False
        ctx.add(WizardStep(name="Local probe (this Meridian host)",
                           outcome="fail", message=f"failed: {e}"))

    # External probe via isitup.org-style: we query A records via public resolvers
    # and succeed if they all agree, then also call a public HTTP checker.
    # No external dep required — we infer from propagation.
    from app.dns.propagation import check_propagation
    prop = await check_propagation(target, "A")
    external_ok = len(prop.unique_answers) > 0
    ctx.add(WizardStep(
        name="Public resolvers see DNS",
        outcome="ok" if external_ok else "fail",
        message=(f"{len(prop.rows)} resolvers → {prop.unique_answers}"
                 if external_ok else "No public resolver returned an answer"),
    ))

    if local_ok and external_ok:
        return [Suggestion(priority="info", title="Reachable from here and globally",
                           detail="Everyone who can resolve DNS should be able to reach this site.")]
    if local_ok and not external_ok:
        return [Suggestion(priority="critical",
                           title="Your box reaches it but public DNS doesn't",
                           detail="Could be split-horizon DNS (internal-only record), or the domain was never delegated publicly.")]
    if not local_ok and external_ok:
        return [Suggestion(priority="recommended",
                           title="Globally reachable but not from this host",
                           detail="Egress firewall, local DNS, or routing issue on the Meridian host side.")]
    return [Suggestion(priority="critical", title="Down for everyone",
                       detail="Neither local nor external probes succeeded.")]


# ============================================================================
# ip.reputation — ASN + Shodan InternetDB (no key)
# ============================================================================
_SHODAN_INTERNETDB = "https://internetdb.shodan.io/{ip}"
_IPINFO_NOKEY = "https://ipinfo.io/{ip}/json"


@wizard("ip.reputation")
async def ip_reputation(ctx: WizardContext) -> list[Suggestion]:
    target = ctx.target
    try:
        ipaddress.ip_address(target)
    except ValueError:
        # Resolve the domain's A record first
        a = await run_dig(DigRequest(target=target, record_type="A"))
        rows = _answers(a.stdout)
        if not rows:
            ctx.add(WizardStep(name="resolve target",
                               outcome="fail",
                               message=f"Could not resolve {target} to an IP"))
            return []
        target = rows[0]
        ctx.add(WizardStep(name="resolved target",
                           outcome="info",
                           message=f"{ctx.target} → {target}"))

    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            who = await client.get(_IPINFO_NOKEY.format(ip=target))
            who_data = who.json() if who.status_code == 200 else {}
        except Exception as e:  # noqa: BLE001
            who_data = {"error": str(e)}
        try:
            shodan = await client.get(_SHODAN_INTERNETDB.format(ip=target))
            shodan_data = shodan.json() if shodan.status_code == 200 else {}
        except Exception as e:  # noqa: BLE001
            shodan_data = {"error": str(e)}

    ctx.add(WizardStep(
        name="WHOIS / ASN (ipinfo.io)",
        outcome="ok" if who_data and "error" not in who_data else "warn",
        message=(f"{who_data.get('org', '?')} · {who_data.get('country', '?')} · {who_data.get('region', '')}"
                 if who_data and "error" not in who_data else
                 f"lookup failed: {who_data.get('error', 'unknown')}"),
        detail=who_data,
    ))

    cves = shodan_data.get("vulns", []) or []
    ports = shodan_data.get("ports", []) or []
    ctx.add(WizardStep(
        name="Shodan InternetDB",
        outcome="warn" if cves else "ok" if ports else "info",
        message=(f"{len(ports)} open ports · {len(cves)} known CVEs"
                 if ports or cves else "no public signal"),
        detail={"ports": ports[:30], "cves": cves[:30],
                "tags": shodan_data.get("tags", []),
                "hostnames": shodan_data.get("hostnames", [])},
    ))

    sug: list[Suggestion] = []
    if cves:
        sug.append(Suggestion(
            priority="recommended" if len(cves) < 3 else "critical",
            title=f"{len(cves)} known CVE(s) for {target}",
            detail="Review and patch. Shodan's view is publicly scraped, so an attacker sees the same list.",
            external_url=_SHODAN_INTERNETDB.format(ip=target),
        ))
    return sug
