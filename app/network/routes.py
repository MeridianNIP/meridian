from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from app.audit.logger import record as audit
from app.auth.deps import client_ip, require_permission
from app.config import get_settings
from app.db import session_scope
from app.network.ping import PingRequest, PingResult, run_ping
from app.network.scope import enforce as enforce_scope
from app.network import subnet_calc
from app.models.user import User


router = APIRouter(prefix="/network", tags=["network"])


@router.get("/interfaces")
async def list_interfaces(
    user: User = Depends(require_permission("network.diagnostics")),
) -> dict:
    """List the host's network interfaces so the Packet Capture UI can
    offer a live dropdown. Read fresh from the kernel each call so a
    hot-plugged NIC or a renamed interface shows up without a restart."""
    import os
    ifaces: list[dict] = []
    try:
        import socket
        # Walk /sys/class/net -- that's the kernel's live view. Tops out
        # at the current moment; next call re-reads.
        base = "/sys/class/net"
        for name in sorted(os.listdir(base)):
            if name == "lo":
                continue
            path = os.path.join(base, name)
            op = "unknown"
            try:
                with open(os.path.join(path, "operstate")) as f:
                    op = f.read().strip() or "unknown"
            except OSError:
                pass
            mac = None
            try:
                with open(os.path.join(path, "address")) as f:
                    mac = f.read().strip() or None
            except OSError:
                pass
            mtu = None
            try:
                with open(os.path.join(path, "mtu")) as f:
                    mtu = int(f.read().strip())
            except (OSError, ValueError):
                pass
            ifaces.append({"name": name, "state": op, "mac": mac, "mtu": mtu})
    except OSError:
        pass
    # The sentinel "any" captures on every interface at once (libpcap
    # convention); always offer it.
    return {"interfaces": ifaces, "any_sentinel": "any"}


class PingInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    count: int = 10
    interval_s: float = 1.0
    timeout_s: float = 2.0
    packet_size: int = 56
    use_ipv6: bool = False


@router.post("/ping", response_model=PingResult)
async def ping(
    request: Request,
    body: PingInput,
    user: User = Depends(require_permission("network.ping")),
) -> PingResult:
    scope = get_settings().scope_of_use
    try:
        with session_scope() as db:
            enforce_scope(db, body.target, scope)
        result = await run_ping(
            PingRequest(
                target=body.target,
                count=body.count,
                interval_s=body.interval_s,
                timeout_s=body.timeout_s,
                packet_size=body.packet_size,
                use_ipv6=body.use_ipv6,
            ),
            scope=scope if scope in ("internal", "external") else None,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    with session_scope() as db:
        audit(db, user_id=user.id, action="network.ping",
              target_type="host", target_key=body.target,
              payload={
                  "count": body.count,
                  "loss_pct": result.stats.loss_pct,
                  "rtt_avg": result.stats.rtt_avg,
                  "jitter": result.stats.jitter,
                  "returncode": result.returncode,
              },
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))
    return result


class TraceInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=253)
    max_hops: int = 30
    timeout_s: int = 3
    per_hop_probes: int = 3
    use_icmp: bool = False


@router.post("/traceroute")
async def traceroute(
    request: Request,
    body: TraceInput,
    user: User = Depends(require_permission("network.ping")),
) -> dict:
    from app.network.traceroute import TraceRequest, run_traceroute
    scope = get_settings().scope_of_use
    try:
        with session_scope() as db:
            enforce_scope(db, body.target, scope)
        result = await run_traceroute(
            TraceRequest(
                target=body.target, max_hops=body.max_hops,
                timeout_s=body.timeout_s, per_hop_probes=body.per_hop_probes,
                use_icmp=body.use_icmp,
            ),
            scope=scope if scope in ("internal", "external") else None,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    with session_scope() as db:
        audit(db, user_id=user.id, action="network.traceroute",
              target_type="host", target_key=body.target,
              payload={"max_hops": body.max_hops, "hops_seen": len(result.hops),
                       "returncode": result.returncode},
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))
    return {
        "command": result.command,
        "stdout": result.stdout,
        "returncode": result.returncode,
        "hops": [
            {"ttl": h.ttl, "host": h.host, "ip": h.ip, "rtts_ms": list(h.rtts_ms)}
            for h in result.hops
        ],
    }


class HttpTestInput(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    method: str = "GET"
    timeout_s: float = 15.0
    follow_redirects: bool = True
    extra_headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


@router.post("/http-test")
async def http_test(
    request: Request,
    body: HttpTestInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.http_test import test_url
    try:
        result = await test_url(
            body.url, method=body.method, timeout_s=body.timeout_s,
            follow_redirects=body.follow_redirects,
            extra_headers=body.extra_headers, body=body.body,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"request failed: {e}")

    with session_scope() as db:
        audit(db, user_id=user.id, action="network.http_test",
              target_type="url", target_key=body.url,
              payload={"method": body.method, "final_status": result.final_status,
                       "total_ms": result.total_ms,
                       "redirects": result.redirect_count},
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))
    return {
        "final_url": result.final_url,
        "final_status": result.final_status,
        "total_ms": result.total_ms,
        "redirect_count": result.redirect_count,
        "chain": [
            {"url": s.url, "status": s.status, "reason": s.reason, "duration_ms": s.duration_ms}
            for s in result.chain
        ],
        "response_headers": result.response_headers,
        "content_type": result.content_type,
        "content_length": result.content_length,
        "body_preview": result.body_preview,
    }


class PortScanInput(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    ports: str = Field(..., min_length=1, max_length=512)
    timeout_s: float = Field(2.0, ge=0.25, le=15.0)
    concurrency: int = Field(64, ge=1, le=256)


@router.post("/port-scan")
async def port_scan(
    request: Request,
    body: PortScanInput,
    user: User = Depends(require_permission("network.ping")),
) -> dict:
    from app.network.port_scan import parse_port_spec, scan
    scope = get_settings().scope_of_use
    try:
        with session_scope() as db:
            enforce_scope(db, body.host, scope)
        port_list = parse_port_spec(body.ports)
        result = await scan(
            body.host, port_list,
            timeout_s=body.timeout_s, concurrency=body.concurrency,
            scope=scope if scope in ("internal", "external") else None,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    with session_scope() as db:
        audit(db, user_id=user.id, action="network.port_scan",
              target_type="host", target_key=body.host,
              payload={"ports_scanned": result.ports_scanned,
                       "open_count": len(result.open_ports),
                       "duration_ms": result.duration_ms},
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))
    return {
        "host": result.host,
        "ports_scanned": result.ports_scanned,
        "open_ports": list(result.open_ports),
        "duration_ms": result.duration_ms,
        "results": [
            {"port": r.port, "state": r.state,
             "latency_ms": r.latency_ms, "error": r.error}
            for r in result.results
        ],
    }


class PcapInput(BaseModel):
    interface: str = Field("any", min_length=1, max_length=15)
    bpf_filter: str = Field("", max_length=512)
    duration_s: int = Field(10, ge=1, le=120)
    max_packets: int = Field(5000, ge=1, le=100_000)
    snaplen: int = Field(262, ge=64, le=65535)


@router.post("/pcap")
async def pcap(
    request: Request,
    body: PcapInput,
    user: User = Depends(require_permission("network.tcpdump")),
) -> dict:
    import hashlib
    from datetime import datetime, timezone
    from app.models.file import FileRecord
    from app.network.pcap import capture

    try:
        result = await capture(
            owner_id=user.id,
            interface=body.interface,
            bpf_filter=body.bpf_filter,
            duration_s=body.duration_s,
            max_packets=body.max_packets,
            snaplen=body.snaplen,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    file_id = None
    if result.path.exists() and result.size_bytes > 0:
        h = hashlib.sha256()
        with open(result.path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        with session_scope() as db:
            rec = FileRecord(
                owner_id=user.id,
                filename=result.path.name,
                mime_type="application/vnd.tcpdump.pcap",
                size_bytes=result.size_bytes,
                sha256_hex=h.hexdigest(),
                storage_path=str(result.path),
                category="pcap",
                tags=["pcap", body.interface],
                uploaded_at=datetime.now(timezone.utc),
            )
            db.add(rec)
            db.flush()
            file_id = str(rec.id)

    with session_scope() as db:
        audit(db, user_id=user.id, action="network.pcap",
              target_type="interface", target_key=body.interface,
              payload={
                  "duration_s": body.duration_s,
                  "bpf": body.bpf_filter,
                  "captured": result.packets_captured,
                  "dropped": result.packets_dropped,
                  "size_bytes": result.size_bytes,
                  "returncode": result.returncode,
                  "file_id": file_id,
              },
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))

    return {
        "capture_id": result.capture_id,
        "interface": result.interface,
        "bpf_filter": result.bpf_filter,
        "duration_s": result.duration_s,
        "max_packets": result.max_packets,
        "snaplen": result.snaplen,
        "size_bytes": result.size_bytes,
        "packets_captured": result.packets_captured,
        "packets_dropped": result.packets_dropped,
        "returncode": result.returncode,
        "stderr_tail": result.stderr_tail,
        "file_id": file_id,
        "download_url": f"/api/v1/files/{file_id}/download" if file_id else None,
    }


class SnmpWalkInput(BaseModel):
    host: str = Field(..., min_length=1, max_length=253)
    oid: str = Field("system", min_length=1, max_length=128)
    version: str = Field("2c", pattern=r"^(1|2c|3)$")
    community: str = Field("public", min_length=1, max_length=64)
    timeout_s: float = Field(8.0, ge=1.0, le=30.0)


@router.post("/snmp-walk")
async def snmp_walk(
    request: Request,
    body: SnmpWalkInput,
    user: User = Depends(require_permission("network.tcpdump")),
) -> dict:
    from app.network.snmp import walk
    try:
        with session_scope() as db:
            enforce_scope(db, body.host, get_settings().scope_of_use)
        result = await walk(
            body.host, body.oid,
            version=body.version, community=body.community,
            timeout_s=body.timeout_s,
        )
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))

    with session_scope() as db:
        audit(db, user_id=user.id, action="network.snmp_walk",
              target_type="host", target_key=body.host,
              payload={"oid": body.oid, "version": body.version,
                       "row_count": len(result.rows),
                       "returncode": result.returncode},
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))
    return {
        "command": result.command,
        "host": result.host,
        "oid_root": result.oid_root,
        "returncode": result.returncode,
        "error": result.error,
        "raw": result.raw,
        "rows": [{"oid": r.oid, "type": r.type, "value": r.value} for r in result.rows],
    }


# ============================================================================
# ASN / BGP looking glass / IP reputation / geoip / security-header audit
# ============================================================================
class _IPInput(BaseModel):
    ip: str = Field(..., min_length=1, max_length=64)


def _audit(user_id, action, target_key, payload, request):
    with session_scope() as db:
        audit(db, user_id=user_id, action=action, target_type="ip",
              target_key=target_key, payload=payload,
              ip=client_ip(request),
              user_agent=request.headers.get("user-agent"))


@router.post("/asn-lookup")
async def asn_lookup_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import asn_lookup
    from app.safety.limits import require_token
    require_token("team_cymru")
    try:
        result = await asn_lookup(body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    _audit(user.id, "network.asn_lookup", body.ip,
           {"asn": result.get("asn"), "as_name": result.get("as_name")}, request)
    return result


class _BgpInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=64)


@router.post("/bgp-looking-glass")
async def bgp_lg_route(
    request: Request, body: _BgpInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import bgp_looking_glass
    from app.safety.limits import require_token
    require_token("ripestat")
    try:
        result = await bgp_looking_glass(body.target)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "network.bgp_lg", body.target,
           {"kind": result.get("kind"), "prefixes": len(result.get("prefixes") or [])},
           request)
    return result


@router.post("/ip-reputation")
async def ip_reputation_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import ip_reputation
    from app.safety.limits import require_token
    require_token("default")  # fan-out to 8 DNSBLs — moderate budget
    try:
        result = await ip_reputation(body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    _audit(user.id, "network.ip_reputation", body.ip,
           {"listed_on": result.get("listed_on", 0)}, request)
    return result


@router.post("/ip-geolocate")
async def ip_geolocate_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import ip_geolocate
    from app.safety.limits import require_token
    require_token("ipapi")
    try:
        result = await ip_geolocate(body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "network.ip_geolocate", body.ip,
           {"country": result.get("country"), "org": result.get("org")}, request)
    return result


class _CveInput(BaseModel):
    cve: str = Field(..., min_length=7, max_length=32)


@router.post("/cve-lookup")
async def cve_lookup_route(
    request: Request, body: _CveInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import cve_lookup
    try:
        result = await cve_lookup(body.cve)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "network.cve_lookup", body.cve.upper(),
           {"severity": (result.get("cvss") or {}).get("severity"),
            "score": (result.get("cvss") or {}).get("score")}, request)
    return result


class _KevSearchInput(BaseModel):
    query: str = Field(..., min_length=1, max_length=128)


@router.post("/kev-lookup")
async def kev_lookup_route(
    request: Request, body: _CveInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import kev_lookup
    try:
        result = await kev_lookup(body.cve)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.kev_lookup", body.cve.upper(),
           {"listed": bool(result.get("listed"))}, request)
    return result


@router.post("/kev-search")
async def kev_search_route(
    request: Request, body: _KevSearchInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import kev_search
    try:
        result = await kev_search(body.query)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.kev_search", body.query,
           {"matches": result.get("total_matches", 0)}, request)
    return result


@router.post("/epss-lookup")
async def epss_lookup_route(
    request: Request, body: _CveInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import epss_lookup
    try:
        result = await epss_lookup(body.cve)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.epss_lookup", body.cve.upper(),
           {"probability": result.get("probability")}, request)
    return result


@router.post("/circl-lookup")
async def circl_lookup_route(
    request: Request, body: _CveInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import circl_lookup
    try:
        result = await circl_lookup(body.cve)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.circl_lookup", body.cve.upper(),
           {"found": bool(result.get("found"))}, request)
    return result


@router.post("/dshield-lookup")
async def dshield_lookup_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import dshield_lookup
    try:
        result = await dshield_lookup(body.ip)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.dshield_lookup", body.ip,
           {"attacks": result.get("attacks")}, request)
    return result


class _HeaderAuditInput(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


@router.post("/header-audit")
async def header_audit_route(
    request: Request, body: _HeaderAuditInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import security_header_audit
    try:
        result = await security_header_audit(body.url)
    except Exception as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{type(e).__name__}: {e}")
    _audit(user.id, "network.header_audit", body.url,
           {"worst": result.get("worst"),
            "status": result.get("final_status")}, request)
    return result


# ============================================================================
# Threat Intel lookups that require a stored API key.
# ============================================================================
class _TargetInput(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)


class _QueryInput(BaseModel):
    query: str = Field(..., min_length=1, max_length=512)


def _handle_ti(fn_name: str, audit_key: str):
    """Wrap a threat-intel lookup: LookupError → 412 (config missing),
    ValueError → 400, httpx upstream error → 502, other → 502."""
    async def wrapped(result_coro, user_id, target, summary, request):
        try:
            result = await result_coro
        except LookupError as e:
            raise HTTPException(412, str(e))
        except ValueError as e:
            raise HTTPException(400, str(e))
        except Exception as e:
            raise HTTPException(502, f"{type(e).__name__}: {e}")
        _audit(user_id, audit_key, target, summary(result) or {}, request)
        return result
    wrapped.__name__ = fn_name
    return wrapped


@router.post("/abuseipdb-lookup")
async def abuseipdb_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import abuseipdb_lookup
    from app.safety.limits import require_token
    require_token("default")
    try:
        result = await abuseipdb_lookup(body.ip)
    except LookupError as e:
        raise HTTPException(412, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.abuseipdb_lookup", body.ip,
           {"confidence": result.get("confidence")}, request)
    return result


@router.post("/greynoise-lookup")
async def greynoise_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import greynoise_lookup
    from app.safety.limits import require_token
    require_token("default")
    try:
        result = await greynoise_lookup(body.ip)
    except LookupError as e:
        raise HTTPException(412, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.greynoise_lookup", body.ip,
           {"classification": result.get("classification")}, request)
    return result


@router.post("/virustotal-lookup")
async def virustotal_route(
    request: Request, body: _TargetInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import virustotal_lookup
    from app.safety.limits import require_token
    require_token("virustotal")
    try:
        result = await virustotal_lookup(body.target)
    except LookupError as e:
        raise HTTPException(412, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.virustotal_lookup", body.target,
           {"malicious": result.get("malicious"),
            "kind": result.get("kind")}, request)
    return result


@router.post("/urlscan-search")
async def urlscan_route(
    request: Request, body: _QueryInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import urlscan_search
    try:
        result = await urlscan_search(body.query)
    except LookupError as e:
        raise HTTPException(412, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.urlscan_search", body.query,
           {"total": result.get("total")}, request)
    return result


@router.post("/shodan-lookup")
async def shodan_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import shodan_lookup
    try:
        result = await shodan_lookup(body.ip)
    except LookupError as e:
        raise HTTPException(412, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.shodan_lookup", body.ip,
           {"ports": len(result.get("ports") or [])}, request)
    return result


@router.post("/censys-lookup")
async def censys_route(
    request: Request, body: _IPInput,
    user: User = Depends(require_permission("dns.sandbox")),
) -> dict:
    from app.network.diagnostics import censys_lookup
    try:
        result = await censys_lookup(body.ip)
    except LookupError as e:
        raise HTTPException(412, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}")
    _audit(user.id, "threat.censys_lookup", body.ip,
           {"services": len(result.get("services") or [])}, request)
    return result


# --- shodan + censys get token-bucket rate limits at the wrapper layer
# (app/network/diagnostics.py:censys_lookup / shodan_lookup). The route
# above already invokes them; a require_token call there would
# double-count. The single-call rate limits live in the wrapper.


# ---------------------------------------------------------------------------
# Subnet / supernet calculator. Read-only CIDR math, no network access, no
# scope enforcement. Gated behind network.ping (same as ping/traceroute) so
# any operator with the diag-tool role can use it.
# ---------------------------------------------------------------------------


class _SubnetCalcInput(BaseModel):
    cidr: str = Field(..., min_length=1, max_length=64)


class _SubnetSplitInput(BaseModel):
    cidr: str = Field(..., min_length=1, max_length=64)
    new_prefix: int = Field(..., ge=1, le=128)
    max_subnets: int = Field(default=1024, ge=1, le=4096)


class _SubnetAggregateInput(BaseModel):
    cidrs: list[str] = Field(..., min_length=1, max_length=4096)


@router.post("/subnet/calc")
async def subnet_describe(
    body: _SubnetCalcInput,
    user: User = Depends(require_permission("network.ping")),
) -> dict:
    try:
        return subnet_calc.calc(body.cidr)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.post("/subnet/split")
async def subnet_split_route(
    body: _SubnetSplitInput,
    user: User = Depends(require_permission("network.ping")),
) -> dict:
    try:
        return subnet_calc.split(body.cidr, body.new_prefix, max_subnets=body.max_subnets)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))


@router.post("/subnet/aggregate")
async def subnet_aggregate_route(
    body: _SubnetAggregateInput,
    user: User = Depends(require_permission("network.ping")),
) -> dict:
    try:
        return subnet_calc.aggregate(body.cidrs)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e))
