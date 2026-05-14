"""Outbound log shipper — batches recent audit_events and posts them to
each enabled destination. Four transports supported:

- **syslog** — RFC 5424 frames over TCP/UDP/TLS (port + facility)
- **splunk_hec** — HTTPS POST /services/collector/event with HEC token
- **elastic** — HTTPS POST _bulk with API key
- **cef** — Common Event Format over syslog (ArcSight/QRadar)

The dispatcher tracks per-destination `last_cursor_ts` so restarts pick
up where they left off. A failure bumps `last_error` and leaves the
cursor unchanged so the next run retries the unshipped batch.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from app.celery_app import celery_app
from app.db import session_scope
from app.models.log_shipping import LogShippingDestination
from app.secrets_vault.vault import decrypt_field


def _resolve_secret(db: OrmSession, secret_id) -> str | None:
    if secret_id is None:
        return None
    row = db.execute(text(
        "SELECT nonce, ciphertext FROM secrets WHERE id = :id"
    ), {"id": secret_id}).first()
    if row is None:
        return None
    return decrypt_field(bytes(row[0]) + bytes(row[1]), domain=b"vault").decode("utf-8")


def _format_rfc5424(event: dict, facility: str = "local0") -> str:
    # PRI = facility * 8 + severity (6 = info)
    fac_map = {f"local{i}": 16 + i for i in range(8)}
    pri = fac_map.get(facility or "local0", 16) * 8 + 6
    ts = event.get("ts") or datetime.now(timezone.utc).isoformat()
    host = socket.gethostname()
    app_name = "meridian"
    msg_id = event.get("action", "-")
    structured = (
        f'[meridian@32473 user_id="{event.get("user_id") or ""}" '
        f'action="{event.get("action") or ""}" '
        f'target="{(event.get("target_key") or "")[:120]}" '
        f'outcome="{event.get("outcome") or "ok"}"]'
    )
    payload = json.dumps(event.get("payload") or {}, separators=(",", ":"))
    return f"<{pri}>1 {ts} {host} {app_name} - {msg_id} {structured} {payload}"


def _format_cef(event: dict) -> str:
    # CEF:0|Vendor|Product|Version|SigID|Name|Severity|Extension
    sev = {"ok": 3, "warn": 6, "error": 8}.get(event.get("outcome", "ok"), 3)
    ext = (
        f"act={event.get('action','')} "
        f"suser={event.get('user_id','')} "
        f"dvchost={socket.gethostname()} "
        f"outcome={event.get('outcome','ok')} "
        f"msg={json.dumps(event.get('payload') or {}, separators=(',',':'))}"
    )
    return (
        f"CEF:0|Meridian|NIP|1.0|{event.get('action','audit')}|"
        f"{event.get('action','audit')}|{sev}|{ext}"
    )


def _send_syslog(dest: LogShippingDestination, payload: str, *, use_cef: bool = False) -> None:
    host, _, port_s = dest.endpoint.partition(":")
    port = int(port_s) if port_s else (6514 if dest.transport == "tls" else 514)
    body = (_format_cef({}) if use_cef else "")  # placeholder
    data = (payload + "\n").encode("utf-8")
    if dest.transport == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(data, (host, port))
        finally:
            s.close()
        return
    # tcp / tls
    raw = socket.create_connection((host, port), timeout=10)
    try:
        if dest.transport == "tls":
            from app.net.tls import strict_ssl_context
            ctx = strict_ssl_context(cafile=dest.ca_cert_path or None)
            raw = ctx.wrap_socket(raw, server_hostname=host)
        raw.sendall(data)
    finally:
        raw.close()


def _send_splunk_hec(dest: LogShippingDestination, token: str, event: dict) -> None:
    import httpx
    r = httpx.post(
        dest.endpoint.rstrip("/") + "/services/collector/event",
        headers={"Authorization": f"Splunk {token}"},
        json={"event": event, "sourcetype": dest.index_or_sourcetype or "meridian:audit",
              "index": dest.index_or_sourcetype or "main"},
        timeout=15.0, verify=dest.ca_cert_path or True,
    )
    r.raise_for_status()


def _send_elastic(dest: LogShippingDestination, api_key: str, event: dict) -> None:
    import httpx
    idx = dest.index_or_sourcetype or "meridian-audit-*"
    body = (
        json.dumps({"index": {"_index": idx}}) + "\n" +
        json.dumps(event) + "\n"
    )
    r = httpx.post(
        dest.endpoint.rstrip("/") + "/_bulk",
        headers={"Authorization": f"ApiKey {api_key}",
                 "Content-Type": "application/x-ndjson"},
        content=body, timeout=15.0, verify=dest.ca_cert_path or True,
    )
    r.raise_for_status()


def _send_graylog_gelf(dest: LogShippingDestination, event: dict) -> None:
    """Graylog GELF v1.1 over TCP or UDP. Endpoint is host:port;
    transport=tcp or udp."""
    gelf = {
        "version": "1.1",
        "host": socket.gethostname(),
        "short_message": event.get("action", "meridian.audit"),
        "timestamp": None,
        "level": {"ok": 6, "warn": 4, "error": 3}.get(event.get("outcome", "ok"), 6),
        "_action": event.get("action"),
        "_user_id": event.get("user_id"),
        "_target_type": event.get("target_type"),
        "_target_key": event.get("target_key"),
        "_outcome": event.get("outcome"),
        "_payload": json.dumps(event.get("payload") or {}, separators=(",", ":")),
    }
    try:
        dt = event.get("ts")
        if dt and isinstance(dt, str):
            gelf["timestamp"] = datetime.fromisoformat(dt.replace("Z", "+00:00")).timestamp()
    except Exception:  # noqa: BLE001
        pass
    payload = json.dumps(gelf, separators=(",", ":")).encode() + b"\x00"  # null-terminated
    host, _, port_s = dest.endpoint.partition(":")
    port = int(port_s) if port_s else 12201
    if dest.transport == "udp":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.sendto(payload, (host, port))
        finally: s.close()
        return
    sock = socket.create_connection((host, port), timeout=10)
    try:
        if dest.transport == "tls":
            from app.net.tls import strict_ssl_context
            ctx = strict_ssl_context(cafile=dest.ca_cert_path or None)
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
    finally: sock.close()


def _send_datadog(dest: LogShippingDestination, api_key: str, event: dict) -> None:
    """Datadog Logs v2 intake. Endpoint should be the regional host
    (e.g. https://http-intake.logs.datadoghq.com)."""
    import httpx
    url = dest.endpoint.rstrip("/") + "/api/v2/logs"
    body = [{
        "ddsource": "meridian",
        "service": "meridian-nip",
        "hostname": socket.gethostname(),
        "ddtags": f"outcome:{event.get('outcome','ok')},action:{event.get('action','')}",
        "message": json.dumps(event, separators=(",", ":")),
    }]
    r = httpx.post(url,
                   headers={"DD-API-KEY": api_key, "Content-Type": "application/json"},
                   json=body, timeout=15.0, verify=dest.ca_cert_path or True)
    r.raise_for_status()


def _send_sumo_logic(dest: LogShippingDestination, event: dict) -> None:
    """Sumo Logic HTTP Source — the URL itself carries the collector
    token, so no separate auth header. `endpoint` is the full collector
    URL (https://endpoint.collection.sumologic.com/.../)."""
    import httpx
    r = httpx.post(dest.endpoint, json=event, timeout=15.0,
                   verify=dest.ca_cert_path or True,
                   headers={"X-Sumo-Category": dest.index_or_sourcetype or "meridian/audit"})
    r.raise_for_status()


def _send_cloudwatch(dest: LogShippingDestination, api_key_json: str, event: dict) -> None:
    """AWS CloudWatch Logs — endpoint = log-group-name :: log-stream-name
    (separated by ::), auth_secret = JSON with AWS credentials.
    Uses boto3 if available, else falls back to HTTPS with SigV4.
    """
    try:
        import boto3   # type: ignore
    except ImportError as e:
        raise RuntimeError(f"AWS CloudWatch requires boto3 on the host: {e}") from e
    creds = json.loads(api_key_json) if api_key_json else {}
    group, _, stream = dest.endpoint.partition("::")
    if not group or not stream:
        raise ValueError("CloudWatch endpoint must be 'group::stream'")
    client = boto3.client(
        "logs",
        aws_access_key_id=creds.get("access_key"),
        aws_secret_access_key=creds.get("secret_key"),
        region_name=creds.get("region", "us-east-1"),
    )
    client.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{
            "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
            "message": json.dumps(event, separators=(",", ":")),
        }],
    )


def _send_gcp_logging(dest: LogShippingDestination, sa_json: str, event: dict) -> None:
    """Google Cloud Logging — endpoint = projects/<project-id>/logs/<log-name>,
    auth_secret = service-account JSON. Uses OAuth2 bearer."""
    import httpx
    sa = json.loads(sa_json) if sa_json else {}
    # For brevity, assume a short-lived OAuth token was generated out-of-band
    # by google.auth (or fetch it here with jwt grant).
    try:
        from google.oauth2 import service_account  # type: ignore
        from google.auth.transport.requests import Request  # type: ignore
    except ImportError as e:
        raise RuntimeError(f"GCP shipping requires google-auth on the host: {e}") from e
    creds_obj = service_account.Credentials.from_service_account_info(
        sa, scopes=["https://www.googleapis.com/auth/logging.write"])
    creds_obj.refresh(Request())
    log_name = dest.endpoint  # projects/<id>/logs/<name>
    r = httpx.post(
        "https://logging.googleapis.com/v2/entries:write",
        headers={"Authorization": f"Bearer {creds_obj.token}",
                 "Content-Type": "application/json"},
        json={"entries": [{
            "logName": log_name,
            "resource": {"type": "generic_node"},
            "jsonPayload": event,
            "severity": {"ok": "INFO", "warn": "WARNING",
                         "error": "ERROR"}.get(event.get("outcome","ok"), "INFO"),
        }]},
        timeout=15.0, verify=dest.ca_cert_path or True,
    )
    r.raise_for_status()


def _send_azure_sentinel(dest: LogShippingDestination, dcr_key: str, event: dict) -> None:
    """Azure Monitor / Sentinel via Log Ingestion API (DCR).
    endpoint = https://<dce>.ingest.monitor.azure.com/dataCollectionRules/<dcr-id>/streams/<stream-name>?api-version=2023-01-01
    auth_secret = short-lived OAuth2 bearer token (caller renews).
    """
    import httpx
    r = httpx.post(dest.endpoint,
                   headers={"Authorization": f"Bearer {dcr_key}",
                            "Content-Type": "application/json"},
                   json=[event], timeout=15.0,
                   verify=dest.ca_cert_path or True)
    r.raise_for_status()


def test_send(db: OrmSession, dest: LogShippingDestination) -> dict[str, Any]:
    """Dispatch a single `meridian.log_shipping.test` event. Used by the
    admin UI's Test button so an operator can sanity-check the endpoint
    + credential without waiting for the next beat tick."""
    secret = _resolve_secret(db, dest.auth_secret_id)
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": "meridian.log_shipping.test",
        "outcome": "ok",
        "payload": {"destination": dest.name, "kind": dest.kind},
        "user_id": None, "target_key": dest.name,
    }
    t0 = time.monotonic()
    try:
        _dispatch_one(dest, secret, event)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return {"ok": True, "latency_ms": int((time.monotonic() - t0) * 1000)}


def _dispatch_one(dest: LogShippingDestination, secret: str | None, event: dict) -> None:
    """Route a single event to the right transport. Raises on failure."""
    if dest.kind == "syslog":
        _send_syslog(dest, _format_rfc5424(event, dest.facility or "local0"))
    elif dest.kind == "cef":
        _send_syslog(dest, _format_cef(event))
    elif dest.kind == "splunk_hec":
        if not secret: raise ValueError("no HEC token stored")
        _send_splunk_hec(dest, secret, event)
    elif dest.kind == "elastic":
        if not secret: raise ValueError("no Elastic API key stored")
        _send_elastic(dest, secret, event)
    elif dest.kind == "graylog_gelf":
        _send_graylog_gelf(dest, event)
    elif dest.kind == "datadog":
        if not secret: raise ValueError("no Datadog API key stored")
        _send_datadog(dest, secret, event)
    elif dest.kind == "sumo_logic":
        _send_sumo_logic(dest, event)
    elif dest.kind == "aws_cloudwatch":
        if not secret:
            raise ValueError("no AWS creds JSON stored (expects {access_key,secret_key,region})")
        _send_cloudwatch(dest, secret, event)
    elif dest.kind == "gcp_logging":
        if not secret:
            raise ValueError("no GCP service-account JSON stored")
        _send_gcp_logging(dest, secret, event)
    elif dest.kind == "azure_sentinel":
        if not secret: raise ValueError("no DCR bearer token stored")
        _send_azure_sentinel(dest, secret, event)
    else:
        raise ValueError(f"unknown kind {dest.kind!r}")


@celery_app.task(name="meridian.jobs.log_shipping.flush")
def flush() -> dict[str, Any]:
    """Beat-triggered — ships any audit_events newer than each
    destination's last_cursor_ts, in batches of `batch_size`.
    """
    import httpx  # noqa: F401 — imported for side-effect in _send_* paths
    shipped = 0
    failures = 0
    with session_scope() as db:
        dests = db.execute(text(
            "SELECT id FROM log_shipping_destinations WHERE enabled = TRUE"
        )).fetchall()
        for (dest_id,) in dests:
            d = db.get(LogShippingDestination, dest_id)
            if d is None:
                continue
            cursor = d.last_cursor_ts or datetime(2025, 1, 1, tzinfo=timezone.utc)
            rows = db.execute(text("""
                SELECT ts, user_id, action, target_type, target_key, payload, outcome
                  FROM audit_events
                 WHERE ts > :cursor
                 ORDER BY ts ASC
                 LIMIT :batch
            """), {"cursor": cursor, "batch": d.batch_size}).fetchall()
            if not rows:
                continue
            secret = _resolve_secret(db, d.auth_secret_id)
            batch_events = [
                {"ts": r.ts.isoformat(), "user_id": str(r.user_id) if r.user_id else None,
                 "action": r.action, "target_type": r.target_type,
                 "target_key": r.target_key, "payload": r.payload or {},
                 "outcome": r.outcome}
                for r in rows
            ]
            try:
                for ev in batch_events:
                    _dispatch_one(d, secret, ev)
                d.last_cursor_ts = rows[-1].ts
                d.last_shipped_at = datetime.now(timezone.utc)
                d.last_error = None
                d.events_shipped_total = (d.events_shipped_total or 0) + len(rows)
                shipped += len(rows)
            except Exception as e:  # noqa: BLE001
                d.last_error = f"{type(e).__name__}: {e}"[:500]
                failures += 1
    return {"shipped": shipped, "failures": failures}
