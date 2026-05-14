"""Subnet / supernet calculator.

Pure-Python stdlib (`ipaddress`); no DNS, no network calls — safe to run
without any privileges. Powers /api/v1/network/subnet/* and the "Subnet
Calc" panel on /ui/dns-tools (or /ui/network — whichever the operator
opens first).

Three operations:

  calc(cidr)            -- describe one network (range, hosts, mask, etc.)
  split(cidr, prefix)   -- split into smaller subnets at the new prefix
  aggregate([cidrs])    -- collapse a list of networks into minimal supernet(s)

Validation is strict: we accept either host syntax ("192.168.1.10/24")
or network syntax ("192.168.1.0/24") — `strict=False` on ip_network.
"""
from __future__ import annotations

import ipaddress
from typing import Union

IPNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _parse(cidr: str, *, strict: bool = False) -> IPNet:
    try:
        return ipaddress.ip_network(cidr.strip(), strict=strict)
    except (ValueError, TypeError) as e:
        raise ValueError(f"invalid CIDR {cidr!r}: {e}") from e


def calc(cidr: str) -> dict:
    """Describe one network. Returns a dict suitable for JSON response."""
    net = _parse(cidr)
    # IPv4 broadcast is meaningful; IPv6 has no broadcast (use last addr).
    is_v6 = isinstance(net, ipaddress.IPv6Network)
    first = net.network_address
    last  = net.broadcast_address
    # "Usable hosts" excludes network + broadcast on IPv4 unless /31 or /32.
    if is_v6:
        usable_first, usable_last = first, last
        usable_count = net.num_addresses
    elif net.prefixlen >= 31:
        usable_first, usable_last = first, last
        usable_count = net.num_addresses
    else:
        usable_first = ipaddress.IPv4Address(int(first) + 1)
        usable_last  = ipaddress.IPv4Address(int(last) - 1)
        usable_count = net.num_addresses - 2
    return {
        "cidr":          str(net),
        "version":       net.version,
        "network":       str(net.network_address),
        "broadcast":     None if is_v6 else str(net.broadcast_address),
        "netmask":       str(net.netmask),
        "wildcard":      None if is_v6 else str(net.hostmask),
        "prefix":        net.prefixlen,
        "total_addresses": net.num_addresses,
        "usable_first":  str(usable_first),
        "usable_last":   str(usable_last),
        "usable_hosts":  usable_count,
        "is_private":    net.is_private,
        "is_global":     net.is_global,
        "is_multicast":  net.is_multicast,
        "is_loopback":   net.is_loopback,
        "is_link_local": net.is_link_local,
        "reverse_pointer": net.network_address.reverse_pointer,
    }


def split(cidr: str, new_prefix: int, *, max_subnets: int = 1024) -> dict:
    """Split `cidr` into subnets at `new_prefix`. Clamps to max_subnets so
    a /8 → /32 split (16M results) doesn't OOM the worker."""
    net = _parse(cidr)
    if new_prefix <= net.prefixlen:
        raise ValueError(
            f"new_prefix {new_prefix} must be larger than current /{net.prefixlen}"
        )
    if (net.version == 4 and new_prefix > 32) or (net.version == 6 and new_prefix > 128):
        raise ValueError(f"new_prefix {new_prefix} out of range for IPv{net.version}")
    expected = 2 ** (new_prefix - net.prefixlen)
    truncated = expected > max_subnets
    subnets: list[dict] = []
    for i, sub in enumerate(net.subnets(new_prefix=new_prefix)):
        if i >= max_subnets:
            break
        subnets.append({
            "cidr": str(sub),
            "first": str(sub.network_address),
            "last":  str(sub.broadcast_address),
            "hosts": sub.num_addresses - (2 if (sub.version == 4 and sub.prefixlen < 31) else 0),
        })
    return {
        "parent":        str(net),
        "new_prefix":    new_prefix,
        "expected_count": expected,
        "returned":      len(subnets),
        "truncated":     truncated,
        "max_subnets":   max_subnets,
        "subnets":       subnets,
    }


def aggregate(cidrs: list[str]) -> dict:
    """Collapse a list of CIDRs into the minimal set of supernets that
    cover the same address space. Mixed IPv4/IPv6 is fine; we collapse
    each family separately."""
    if not cidrs:
        return {"input": [], "supernets": []}
    if len(cidrs) > 4096:
        raise ValueError(f"too many inputs ({len(cidrs)}); max 4096")
    nets = [_parse(c) for c in cidrs]
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    out: list[str] = []
    for fam in (v4, v6):
        if not fam:
            continue
        for sup in ipaddress.collapse_addresses(fam):
            out.append(str(sup))
    return {
        "input":     [str(n) for n in nets],
        "supernets": out,
    }
