"""Webhooks subsystem.

Inbound: external systems POST signed JSON to /api/v1/webhooks/inbound/{id}.
Outbound: internal events (monitor incidents, cert warnings, audit spikes)
fan out to every enabled subscriber of the event kind.

HMAC shared secret lives in the `secrets` vault, same as directory-integration credentials.
"""
