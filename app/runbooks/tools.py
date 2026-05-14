"""Tool registry for runbook steps.

Each entry declares:
    key                — stable identifier stored in `runbooks.steps[].tool`
    label              — human label for the builder UI
    category           — grouping label for the builder
    required_permission— permission the caller must hold; checked by the engine
                         before execute() is called. If missing, the step is
                         marked outcome='denied' without running.
    params_schema      — list of field descriptors for the UI form builder.
                         Each is {name, label, type: 'text'|'int'|'bool'|'enum',
                         default, required, options?}.
    execute            — async callable(params, ctx) → ResultDict. The engine
                         decides pass/fail from result['outcome'].

ResultDict shape:
    {
        "outcome": "ok" | "warn" | "fail" | "info",
        "summary": "one-line human summary for the runbook run log",
        "detail": { ... }   # arbitrary structured payload
    }
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import ipaddress
from typing import Any

from sqlalchemy.orm import Session as OrmSession

from app.models.user import User


@dataclass
class ToolParam:
    name: str
    label: str
    type: str  # 'text'|'int'|'bool'|'enum'|'textarea'
    default: Any = None
    required: bool = False
    options: list[str] | None = None
    hint: str | None = None


@dataclass
class ToolSpec:
    key: str
    label: str
    category: str
    description: str
    required_permission: str
    params: list[ToolParam] = field(default_factory=list)
    execute: Callable[..., Awaitable[dict[str, Any]]] | None = None


_TOOLS: dict[str, ToolSpec] = {}


def register(spec: ToolSpec) -> None:
    _TOOLS[spec.key] = spec


def get(key: str) -> ToolSpec | None:
    return _TOOLS.get(key)


def catalog() -> list[ToolSpec]:
    return sorted(_TOOLS.values(), key=lambda t: (t.category, t.label))


# ============================================================================
# Tool implementations
# ============================================================================
async def _tool_dig(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.dns.dig import DigRequest, run_dig

    res = await run_dig(
        DigRequest(
            target=params["target"],
            record_type=params.get("record_type", "A"),
            resolver=params.get("resolver") or None,
        )
    )
    rows = [l for l in res.stdout.splitlines() if l.strip() and not l.startswith(";")]
    return {
        "outcome": "ok" if rows else "warn",
        "summary": f"{len(rows)} answer(s)" if rows else "no answers",
        "detail": {"command": res.command, "rows": rows[:20], "returncode": res.returncode},
    }


async def _tool_propagation(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.dns.propagation import check_propagation

    rep = await check_propagation(params["target"], params.get("record_type", "A"))
    ok = sum(1 for r in rep.rows if r.ok)
    return {
        "outcome": "ok" if ok and not rep.divergence else "warn" if rep.divergence else "fail",
        "summary": f"{ok}/{len(rep.rows)} resolvers" + (" · diverge" if rep.divergence else " · agree"),
        "detail": {
            "unique_answers": list(rep.unique_answers),
            "ok_count": ok,
            "total": len(rep.rows),
            "divergence": rep.divergence,
        },
    }


async def _tool_ping(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.network.ping import PingRequest, run_ping

    res = await run_ping(
        PingRequest(
            target=params["target"],
            count=int(params.get("count", 5)),
            timeout_s=float(params.get("timeout_s", 2.0)),
        ),
        scope=scope if scope in ("internal", "external") else None,
    )
    loss = res.stats.loss_pct
    sev = "ok" if loss < 50 else "warn" if loss < 100 else "fail"
    return {
        "outcome": sev,
        "summary": f"{res.stats.received}/{res.stats.transmitted} · avg {res.stats.rtt_avg} ms · loss {loss}%",
        "detail": {
            "rtt_avg": res.stats.rtt_avg,
            "rtt_min": res.stats.rtt_min,
            "rtt_max": res.stats.rtt_max,
            "jitter": res.stats.jitter,
            "loss_pct": loss,
        },
    }


async def _tool_traceroute(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.network.traceroute import TraceRequest, run_traceroute

    res = await run_traceroute(
        TraceRequest(
            target=params["target"],
            max_hops=int(params.get("max_hops", 20)),
            timeout_s=int(params.get("timeout_s", 3)),
            per_hop_probes=int(params.get("per_hop_probes", 2)),
        ),
        scope=scope if scope in ("internal", "external") else None,
    )
    return {
        "outcome": "ok" if res.hops else "warn",
        "summary": f"{len(res.hops)} hops" + (f" · last: {res.hops[-1].host}" if res.hops else ""),
        "detail": {
            "hops": [{"ttl": h.ttl, "host": h.host, "ip": h.ip, "rtts_ms": list(h.rtts_ms)} for h in res.hops]
        },
    }


async def _tool_http(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.network.http_test import test_url

    try:
        res = await test_url(
            params["url"],
            method=params.get("method", "GET"),
            timeout_s=float(params.get("timeout_s", 10.0)),
            follow_redirects=bool(params.get("follow_redirects", True)),
        )
    except Exception as e:
        return {"outcome": "fail", "summary": f"request error: {e}", "detail": {"error": str(e)}}
    sev = "ok" if 200 <= res.final_status < 400 else "warn" if res.final_status < 500 else "fail"
    return {
        "outcome": sev,
        "summary": f"HTTP {res.final_status} · {res.redirect_count} redirect(s) · {res.total_ms} ms",
        "detail": {
            "final_url": res.final_url,
            "final_status": res.final_status,
            "total_ms": res.total_ms,
            "redirect_count": res.redirect_count,
        },
    }


async def _tool_port_scan(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.network.port_scan import parse_port_spec, scan

    port_list = parse_port_spec(params["ports"])
    res = await scan(
        params["target"],
        port_list,
        timeout_s=float(params.get("timeout_s", 2.0)),
        concurrency=int(params.get("concurrency", 32)),
        scope=scope if scope in ("internal", "external") else None,
    )
    sev = "ok" if res.open_ports else "warn"
    return {
        "outcome": sev,
        "summary": f"{len(res.open_ports)}/{res.ports_scanned} open · {res.duration_ms} ms",
        "detail": {"open_ports": list(res.open_ports), "ports_scanned": res.ports_scanned},
    }


async def _tool_zone_health(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.dns.zone_health import check_zone

    rep = await check_zone(params["target"])
    return {
        "outcome": rep.worst if rep.worst in ("ok", "warn", "fail") else "info",
        "summary": f"{len(rep.findings)} finding(s) · worst {rep.worst}",
        "detail": {
            "worst": rep.worst,
            "findings": [
                {"severity": f.severity, "check": f.check, "message": f.message} for f in rep.findings
            ],
        },
    }


async def _tool_dnssec(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.dns.dnssec import walk_chain

    rep = await walk_chain(params["target"])
    return {
        "outcome": rep.worst if rep.worst in ("ok", "warn", "fail") else "info",
        "summary": f"chain {len(rep.chain)} · AD {rep.ad_flag} · worst {rep.worst}",
        "detail": {
            "ad_flag": rep.ad_flag,
            "chain": [
                {
                    "zone": s.zone,
                    "outcome": s.outcome,
                    "has_ds": s.has_ds,
                    "has_dnskey": s.has_dnskey,
                    "algorithms": s.algorithms,
                    "message": s.message,
                }
                for s in rep.chain
            ],
        },
    }


async def _tool_axfr(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.dns.axfr import axfr_audit

    rep = await axfr_audit(params["target"])
    sev = "fail" if rep.any_exposed else "ok"
    return {
        "outcome": sev,
        "summary": (
            "AXFR exposed on at least one NS"
            if rep.any_exposed
            else f"{len(rep.rows)} NS tested, all refused"
        ),
        "detail": {
            "any_exposed": rep.any_exposed,
            "rows": [{"ns": r.nameserver, "exposed": r.exposed, "detail": r.detail} for r in rep.rows],
        },
    }


async def _tool_wizard(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    from app.wizards.engine import run_wizard

    try:
        res = await run_wizard(
            wizard_key=params["wizard_key"],
            target=params["target"],
            user=user,
            db=db,
        )
    except ValueError as e:
        return {"outcome": "fail", "summary": f"unknown wizard: {e}", "detail": {"error": str(e)}}
    return {
        "outcome": res["outcome"] if res["outcome"] in ("ok", "warn", "fail") else "info",
        "summary": f"wizard {params['wizard_key']} → {res['outcome']} · {len(res['steps'])} steps",
        "detail": {
            "run_id": res["run_id"],
            "outcome": res["outcome"],
            "step_count": len(res["steps"]),
            "suggestions": res["suggestions"],
        },
    }


async def _tool_sleep(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    seconds = max(0.0, min(60.0, float(params.get("seconds", 1.0))))
    await asyncio.sleep(seconds)
    return {"outcome": "ok", "summary": f"slept {seconds} s", "detail": {"seconds": seconds}}


async def _tool_assert_ip(params: dict, *, user: User, db: OrmSession, scope: str | None) -> dict:
    """Resolve a domain and assert the A record matches expected_ip. Useful as a
    gate inside runbooks that should abort on unexpected DNS state."""
    from app.dns.dig import DigRequest, run_dig

    expected = params["expected_ip"].strip()
    try:
        ipaddress.ip_address(expected)
    except ValueError:
        return {
            "outcome": "fail",
            "summary": f"expected_ip is not an IP: {expected}",
            "detail": {"expected": expected},
        }
    res = await run_dig(DigRequest(target=params["target"], record_type="A"))
    rows = [l.strip() for l in res.stdout.splitlines() if l.strip() and not l.startswith(";")]
    match = expected in rows
    return {
        "outcome": "ok" if match else "fail",
        "summary": f"{params['target']} → {rows} · expected {expected}",
        "detail": {"answers": rows, "expected": expected, "match": match},
    }


# ----------------------------------------------------------------------------
# Registration
# ----------------------------------------------------------------------------
register(
    ToolSpec(
        key="dig",
        label="DNS dig",
        category="DNS",
        description="Single DNS lookup via BIND9 (uses system or custom resolver).",
        required_permission="dns.sandbox",
        params=[
            ToolParam("target", "Target", "text", required=True),
            ToolParam(
                "record_type",
                "Record type",
                "enum",
                default="A",
                options=["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "SRV", "PTR"],
            ),
            ToolParam("resolver", "Resolver (blank = system)", "text"),
        ],
        execute=_tool_dig,
    )
)

register(
    ToolSpec(
        key="propagation",
        label="Global propagation",
        category="DNS",
        description="Query 16 public resolvers in parallel, flag divergence.",
        required_permission="dns.propagation",
        params=[
            ToolParam("target", "Target", "text", required=True),
            ToolParam("record_type", "Record type", "enum", default="A", options=["A", "AAAA", "MX", "TXT"]),
        ],
        execute=_tool_propagation,
    )
)

register(
    ToolSpec(
        key="zone_health",
        label="Zone health check",
        category="DNS",
        description="SOA consistency, delegation, lame NS detection.",
        required_permission="dns.sandbox",
        params=[ToolParam("target", "Zone", "text", required=True)],
        execute=_tool_zone_health,
    )
)

register(
    ToolSpec(
        key="dnssec",
        label="DNSSEC chain walker",
        category="DNS",
        description="Walks root → TLD → zone chain, reports any break.",
        required_permission="dns.sandbox",
        params=[ToolParam("target", "Domain", "text", required=True)],
        execute=_tool_dnssec,
    )
)

register(
    ToolSpec(
        key="axfr",
        label="AXFR audit",
        category="DNS",
        description="Attempt zone transfer against each authoritative NS.",
        required_permission="dns.sandbox",
        params=[ToolParam("target", "Zone", "text", required=True)],
        execute=_tool_axfr,
    )
)

register(
    ToolSpec(
        key="ping",
        label="Ping",
        category="Network",
        description="ICMP echo with loss/RTT stats. Scope guardrails apply.",
        required_permission="network.ping",
        params=[
            ToolParam("target", "Target", "text", required=True),
            ToolParam("count", "Count", "int", default=5),
            ToolParam("timeout_s", "Timeout (s)", "int", default=2),
        ],
        execute=_tool_ping,
    )
)

register(
    ToolSpec(
        key="traceroute",
        label="Traceroute",
        category="Network",
        description="UDP/ICMP hop discovery with per-hop RTTs.",
        required_permission="network.ping",
        params=[
            ToolParam("target", "Target", "text", required=True),
            ToolParam("max_hops", "Max hops", "int", default=20),
            ToolParam("per_hop_probes", "Probes per hop", "int", default=2),
        ],
        execute=_tool_traceroute,
    )
)

register(
    ToolSpec(
        key="http",
        label="HTTP test",
        category="Network",
        description="One HTTP request with redirect chain + timing.",
        required_permission="dns.sandbox",
        params=[
            ToolParam("url", "URL", "text", required=True),
            ToolParam("method", "Method", "enum", default="GET", options=["GET", "HEAD", "POST"]),
            ToolParam("timeout_s", "Timeout (s)", "int", default=10),
            ToolParam("follow_redirects", "Follow redirects", "bool", default=True),
        ],
        execute=_tool_http,
    )
)

register(
    ToolSpec(
        key="port_scan",
        label="Port scan",
        category="Network",
        description="Async TCP-connect against a port spec (e.g. 22,80,443,8000-8010).",
        required_permission="network.ping",
        params=[
            ToolParam("target", "Host", "text", required=True),
            ToolParam("ports", "Ports", "text", default="22,80,443", required=True),
            ToolParam("timeout_s", "Timeout (s)", "int", default=2),
            ToolParam("concurrency", "Concurrency", "int", default=32),
        ],
        execute=_tool_port_scan,
    )
)

register(
    ToolSpec(
        key="wizard",
        label="Run wizard",
        category="Workflow",
        description="Invoke a registered wizard by key (e.g. dns.resolve_fail).",
        required_permission="dns.sandbox",
        params=[
            ToolParam(
                "wizard_key",
                "Wizard key",
                "text",
                required=True,
                hint="dns.resolve_fail, mail.delivery, ssl.deep_inspect, …",
            ),
            ToolParam("target", "Target", "text", required=True),
        ],
        execute=_tool_wizard,
    )
)

register(
    ToolSpec(
        key="assert_ip",
        label="Assert A record",
        category="Workflow",
        description="Resolve a name and require the answer to include expected_ip.",
        required_permission="dns.sandbox",
        params=[
            ToolParam("target", "Name", "text", required=True),
            ToolParam("expected_ip", "Expected IP", "text", required=True),
        ],
        execute=_tool_assert_ip,
    )
)

register(
    ToolSpec(
        key="sleep",
        label="Sleep",
        category="Workflow",
        description="Pause for N seconds (max 60). Useful between DNS change + propagation.",
        required_permission="dns.sandbox",
        params=[ToolParam("seconds", "Seconds", "int", default=5)],
        execute=_tool_sleep,
    )
)
