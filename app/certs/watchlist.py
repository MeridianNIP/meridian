from __future__ import annotations

import asyncio
import socket
import ssl

from app.certs.parser import CertInfo, parse_pem


async def fetch_remote_cert(host: str, port: int = 443, *, timeout_s: float = 8.0) -> CertInfo:
    """Open a TLS connection to host:port and return the peer's leaf certificate.

    Uses an SNI-aware context that does NOT verify the chain — the whole point
    is to inspect what the remote presents, even if it's expired or untrusted.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    loop = asyncio.get_event_loop()

    def _blocking_fetch() -> bytes:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        if der is None:
            raise ValueError(f"no peer cert returned from {host}:{port}")
        pem = ssl.DER_cert_to_PEM_cert(der)
        return pem.encode()

    pem_bytes = await loop.run_in_executor(None, _blocking_fetch)
    return parse_pem(pem_bytes)
