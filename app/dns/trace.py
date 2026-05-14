"""DNS hop-trace / troubleshoot — query every relevant resolver + the
authoritative nameservers in parallel and identify the first point of
divergence.

Output sections:
  - `authoritative`: zone's NS servers queried directly for the target.
    This is ground truth.
  - `resolvers`: every house + personal resolver the caller is permitted
    to see (plus a synthetic "Local (127.0.0.1)" row for the portal's own
    BIND9), each labelled with its scope. Answers are compared against
    the authoritative set; rows are tagged `match` / `divergent` / `error`.
  - `recursion_trace`: raw `dig +trace` output, for admins who want to
    see the full root -> TLD -> authoritative walk.
  - `divergence`: which resolvers disagree, and with what answers.

All queries run concurrently; total wall time ~= slowest resolver's RTT
plus the +trace (which is sequential by design — that's its point).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal
import uuid as _uuid

from sqlalchemy import select

from app.db import session_scope
from app.dns.dig import _IPV4_RE, DigRequest, DigResult, run_dig
from app.models.resolver import Resolver

# Cap total resolver fanout so a misconfigured table can't DoS the
# worker pool. 25 internal + 5 external + 4 authoritative is well
# within this.
_MAX_RESOLVER_FANOUT = 80
_PER_QUERY_TIMEOUT_S = 5.0
_TRACE_TIMEOUT_S = 20.0


Status = Literal["match", "divergent", "error", "unknown"]
Scope = Literal["local", "house", "mine", "authoritative"]


@dataclass(frozen=True)
class TraceRow:
    scope: Scope
    name: str
    resolver_ip: str
    region: str | None
    answer: str | None  # first answer line, normalised
    ttl: int | None  # TTL on the returned record (seconds)
    ok: bool
    status: Status
    duration_ms: int
    error: str | None
    flushable: bool  # True when we can `rndc flushname` this
    ad_flag: bool | None  # DNSSEC "authenticated data" flag


@dataclass(frozen=True)
class Summary:
    """Human-readable diagnosis surfaced at the top of the trace UI."""

    headline: str  # one-line verdict
    severity: Literal["ok", "warn", "error", "unknown"]
    evidence: tuple[str, ...]  # bullet-point facts that led to verdict
    suggested_action: str | None  # one actionable next step, or None


@dataclass(frozen=True)
class DnssecRow:
    """Per-resolver DNSSEC detail. Extends TraceRow semantics with the
    FULL SET of DNSKEY + DS records each resolver has for the target's
    zone (not just the first record -- a zone legitimately has multiple
    DNSKEYs: KSK + ZSK, plus extras during rollover). Comparison across
    resolvers is set-based so different line ordering or returned-subset
    differences don't show as spurious divergence."""

    scope: Scope
    name: str
    resolver_ip: str
    region: str | None
    target_answer: str | None
    target_ttl: int | None
    target_ad: bool | None
    target_has_rrsig: bool
    dnskey_records: tuple[str, ...]  # ALL DNSKEY records, normalised + sorted
    ds_records: tuple[str, ...]  # ALL DS records, normalised + sorted
    dnskey_summary: str | None  # ASCII human summary
    ds_summary: str | None  # ASCII human summary
    zone: str | None
    status: Status
    divergence_reason: str | None  # why THIS row is divergent
    duration_ms: int
    error: str | None
    flushable: bool


@dataclass
class TraceReport:
    """Answer-mode trace report."""

    target: str
    record_type: str
    mode: Literal["answer", "dnssec"]
    authoritative_answers: tuple[str, ...]
    rows: tuple[TraceRow, ...]
    dnssec_rows: tuple[DnssecRow, ...]  # empty when mode == "answer"
    zone: str | None  # target's zone (dnssec mode)
    recursion_trace: str  # dig +trace output (may be long)
    recursion_trace_truncated: bool
    divergence: bool
    point_of_divergence: str | None
    summary: Summary


def _normalise(answer: str | None) -> str | None:
    if answer is None:
        return None
    return answer.strip().rstrip(".").lower() or None


def _first_answer_line(stdout: str) -> str | None:
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        return line
    return None


def _first_answer_and_ttl(stdout: str) -> tuple[str | None, int | None]:
    """Parse the first non-comment line of dig output (non-+short mode).
    Returns (rdata, ttl_seconds). Falls back to (raw_line, None) if the
    line doesn't have the standard RR shape (e.g. +short output)."""
    line = _first_answer_line(stdout)
    if line is None:
        return None, None
    parts = line.split()
    if len(parts) >= 5:
        try:
            ttl = int(parts[1])
        except ValueError:
            ttl = None
        data = " ".join(parts[4:])
        return data, ttl
    return line, None


async def _dig(target: str, record_type: str, resolver_ip: str | None, flags: tuple[str, ...]) -> DigResult:
    # dig.py validates resolver with _IPV4_RE and rejects the empty string;
    # passing None means "use the system recursor" (no @server on the
    # command line).
    return await run_dig(
        DigRequest(
            target=target,
            record_type=record_type,
            resolver=(resolver_ip or None),
            flags=flags,
        )
    )


def _timed_out_result(cmd: str) -> DigResult:
    """DigResult stand-in for asyncio-level timeouts (the sandbox itself
    also has a timeout but we wrap each call for predictability)."""
    return DigResult(
        command=cmd,
        stdout="",
        stderr="timeout",
        returncode=124,
        duration_ms=int(_PER_QUERY_TIMEOUT_S * 1000),
        truncated=False,
        timed_out=True,
    )


async def _ad_flagged(target: str, record_type: str, resolver_ip: str | None) -> bool | None:
    """Re-dig with +dnssec to see if the resolver validated (AD flag).
    Uses only the flags dig.py allows (no +comments/+nostats)."""
    try:
        r = await asyncio.wait_for(
            _dig(target, record_type, resolver_ip, ("+dnssec",)),
            timeout=_PER_QUERY_TIMEOUT_S,
        )
    except TimeoutError:
        return None
    if r.returncode != 0:
        return None
    # dig's default output includes a ";; flags: qr rd ra ad;" line when
    # the resolver set the AD (Authenticated Data) bit. Parse it.
    for line in r.stdout.splitlines():
        if ";; flags:" in line:
            flags_part = line.split(";; flags:", 1)[1].split(";", 1)[0]
            return " ad" in (" " + flags_part + " ")
    return None


async def _authoritative_ns_ips(target: str) -> list[tuple[str, str]]:
    """Resolve NS records for the apex of the target, then A for each NS.
    Returns [(nsname, ip), ...]. Uses the local BIND9 recursor (no resolver
    override) so we get the same chain the portal would normally use.
    """
    # Walk from the full name up to the zone. dig SOA works for non-apex
    # names too; the returned SOA is for the zone. But dig +short doesn't
    # give the owner, so we use +noall +authority +answer and parse.
    try:
        soa = await _dig(target, "SOA", None, ("+noall", "+authority", "+answer"))
    except ValueError:
        return []  # bad target; caller handles empty auth list
    zone = None
    for line in (soa.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        # "example.com.  3600  IN  SOA  ..."
        parts = line.split()
        if len(parts) >= 4 and parts[3].upper() == "SOA":
            zone = parts[0].rstrip(".")
            break
    # Recursor commonly returns the ROOT SOA (owner ".") for NXDOMAIN or
    # for names under TLDs the resolver can't reach (e.g. `.local`). That
    # rstrip-ed to "" above — which would then be rejected by dig.py's
    # validator. Skip the auth-NS pass in that case; resolver-only view
    # is still useful.
    if not zone:
        zone = target if target else None
    if not zone or zone == "." or zone == target and target.endswith(".local"):
        return []

    try:
        ns_res = await _dig(zone, "NS", None, ("+short",))
    except ValueError:
        return []
    names = [
        ln.strip().rstrip(".") for ln in ns_res.stdout.splitlines() if ln.strip() and not ln.startswith(";")
    ]
    if not names:
        return []

    # Resolve each NS name to an A. AAAA could be added later. Skip any
    # name that dig.py would reject so one bad NS doesn't kill the whole
    # trace.
    async def _safe_a(n: str):
        try:
            return await _dig(n, "A", None, ("+short",))
        except ValueError:
            return None

    a_results = await asyncio.gather(*[_safe_a(n) for n in names], return_exceptions=False)

    ips: list[tuple[str, str]] = []
    for n, r in zip(names, a_results, strict=False):
        if r is None:
            continue
        for ln in r.stdout.splitlines():
            ip = ln.strip()
            if _IPV4_RE.match(ip):
                ips.append((n, ip))
                break  # one A per NS is enough for ground truth
    return ips


def _load_resolvers(
    user_id: _uuid.UUID | None, include_external: bool, group_tag: str | None = None
) -> list[Resolver]:
    """House resolvers + the caller's personal resolvers, optionally
    filtered to a single `group_tag` (e.g. "Corp Cache"). An empty / None
    group_tag means no filter. `include_external` is a soft UI flag
    forwarded here for future server-side filtering."""
    with session_scope() as db:
        cond = Resolver.owner_user_id.is_(None)
        if user_id is not None:
            from sqlalchemy import or_

            cond = or_(cond, Resolver.owner_user_id == user_id)
        from sqlalchemy import func

        stmt = select(Resolver).where(cond)
        if group_tag:
            stmt = stmt.where(Resolver.group_tag == group_tag)
        rows = (
            db.execute(
                stmt.order_by(Resolver.owner_user_id.nullsfirst(), func.lower(Resolver.name)).limit(
                    _MAX_RESOLVER_FANOUT
                )
            )
            .scalars()
            .all()
        )
        return list(rows)


async def _discover_zone(target: str) -> str | None:
    """Use SOA lookup to find the zone that contains `target`. Returns the
    zone name without trailing dot, or None if it can't be determined
    (e.g. `.local` names)."""
    if not target:
        return None
    try:
        r = await _dig(target, "SOA", None, ("+noall", "+authority", "+answer"))
    except ValueError:
        return None
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[3].upper() == "SOA":
            owner = parts[0].rstrip(".")
            # Reject root-SOA fallbacks; they mean "zone not found".
            if owner and owner != "" and owner != target or (owner == target):
                return owner or None
    return None


async def _dnssec_probe(
    resolver_ip: str | None, target: str, record_type: str, zone: str | None
) -> tuple[DigResult, bool | None, bool, tuple[str, ...], tuple[str, ...]]:
    """Fan out three +dnssec queries to one resolver: the target record
    (capturing AD + RRSIG presence), the zone's DNSKEY set, and the
    zone's DS set. Returns (target_dig, ad, has_rrsig, dnskey_records,
    ds_records) -- records are returned as sorted tuples so callers can
    compare sets across resolvers (a zone usually has multiple DNSKEYs:
    KSK + ZSK + rollover extras -- sampling only the first line would
    produce spurious divergence)."""

    async def _q(name, rtype, flags):
        try:
            return await asyncio.wait_for(
                _dig(name, rtype, resolver_ip, flags),
                timeout=_PER_QUERY_TIMEOUT_S,
            )
        except (TimeoutError, ValueError):
            return None

    tgt_task = _q(target, record_type, ("+dnssec",))
    dk_task = _q(zone, "DNSKEY", ("+dnssec", "+short")) if zone else asyncio.sleep(0, result=None)
    ds_task = _q(zone, "DS", ("+dnssec", "+short")) if zone else asyncio.sleep(0, result=None)
    tgt, dk, ds = await asyncio.gather(tgt_task, dk_task, ds_task)

    # AD + RRSIG from target response
    ad: bool | None = None
    has_rrsig = False
    if tgt is not None and tgt.returncode == 0:
        for line in tgt.stdout.splitlines():
            if ";; flags:" in line:
                flags_part = line.split(";; flags:", 1)[1].split(";", 1)[0]
                ad = " ad" in (" " + flags_part + " ")
            if " RRSIG " in f" {line} ":
                has_rrsig = True

    def _all_records(d: DigResult | None) -> tuple[str, ...]:
        """Canonicalise the answer section: collapse whitespace, drop
        the trailing RRSIG the resolver tagged on (it's a signature on
        the RRset, not part of the set), sort the remaining lines."""
        if d is None or d.returncode != 0:
            return ()
        recs: list[str] = []
        for line in d.stdout.splitlines():
            s = " ".join(line.split())  # collapse whitespace
            if not s or s.startswith(";"):
                continue
            # +short DNSKEY output is 4 fields: flags proto alg key
            # +short DS output is 4 fields: keytag alg digesttype digest
            # +dnssec tacks on RRSIG lines for the RRset -- skip them.
            if s.startswith("RRSIG") or " RRSIG " in f" {s} ":
                continue
            recs.append(s)
        return tuple(sorted(recs))

    return (
        tgt if tgt is not None else _timed_out_result(f"dig @{resolver_ip} {target} {record_type}"),
        ad,
        has_rrsig,
        _all_records(dk),
        _all_records(ds),
    )


def _dnskey_summary(records: tuple[str, ...]) -> str | None:
    """Short human label for a DNSKEY set. Parses `flags proto alg key`
    per record and surfaces how many KSKs (flags 257) vs ZSKs (flags
    256) there are, plus the algorithm numbers present."""
    if not records:
        return None
    ksks = zsks = others = 0
    algs: set[str] = set()
    for r in records:
        parts = r.split()
        if len(parts) < 4:
            continue
        flags, _proto, alg = parts[0], parts[1], parts[2]
        algs.add(alg)
        if flags == "257":
            ksks += 1
        elif flags == "256":
            zsks += 1
        else:
            others += 1
    pieces = []
    if ksks:
        pieces.append(f"{ksks} KSK")
    if zsks:
        pieces.append(f"{zsks} ZSK")
    if others:
        pieces.append(f"{others} other")
    # ASCII only -- middle-dot renders as "\xc2\xb7" in Latin-1 viewers
    # (Excel) which shows up as the mojibake "A-hat middle-dot".
    tail = f" | alg {','.join(sorted(algs))}" if algs else ""
    return f"{len(records)} keys ({' + '.join(pieces)}){tail}" if pieces else f"{len(records)} records{tail}"


def _ds_summary(records: tuple[str, ...]) -> str | None:
    """Short human label for a DS set. ASCII only for Excel/CSV safety."""
    if not records:
        return None
    algs: set[str] = set()
    dts: set[str] = set()
    for r in records:
        parts = r.split()
        if len(parts) >= 3:
            algs.add(parts[1])
            dts.add(parts[2])
    return f"{len(records)} DS | alg {','.join(sorted(algs))} digest-type {','.join(sorted(dts))}"


def _majority(values: list[str | None]) -> str | None:
    """Most common non-null value. Used as ground truth when we don't
    have an authoritative query for a given zone's DNSKEY/DS (parent-NS
    traversal is V2)."""
    from collections import Counter

    clean = [v for v in values if v]
    if not clean:
        return None
    return Counter(clean).most_common(1)[0][0]


def _fmt_ttl(seconds: int | None) -> str:
    """Compact human TTL: 300 -> '5m', 86400 -> '1d', 172800 -> '2d'."""
    if seconds is None or seconds < 0:
        return "?"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _build_answer_summary(rows: list[TraceRow], auth_answers: set[str], target: str) -> Summary:
    match = [r for r in rows if r.status == "match" and r.scope != "authoritative"]
    diverge = [r for r in rows if r.status == "divergent" and r.scope != "authoritative"]
    errors = [r for r in rows if r.status == "error" and r.scope != "authoritative"]
    total_resolver_rows = len(match) + len(diverge) + len(errors)

    if not auth_answers:
        return Summary(
            headline="No authoritative ground truth — can't verify correctness.",
            severity="unknown",
            evidence=(
                f"{total_resolver_rows} resolvers answered.",
                "Authoritative nameserver lookup returned no reachable servers.",
                "Likely target is under a private / unreachable zone (e.g. .local).",
            ),
            suggested_action="Compare resolver answers manually below; authoritative column is empty.",
        )
    if not diverge and not errors:
        one_answer = next(iter(auth_answers))
        return Summary(
            headline=f"All {total_resolver_rows} resolvers agree with authoritative ({one_answer}).",
            severity="ok",
            evidence=(f"Authoritative: {', '.join(sorted(auth_answers))}",),
            suggested_action=None,
        )
    # Some disagree. Pull TTLs for the evidence + action so the operator
    # knows how long a stale cache will take to expire if they can't flush.
    diverge_names = [f"{r.name} ({r.resolver_ip})" for r in diverge[:3]]
    more = f" and {len(diverge) - 3} more" if len(diverge) > 3 else ""
    flushable = [r for r in diverge if r.flushable]
    # Worst-case TTL across the divergent set — that's the longest you
    # might have to wait.
    div_ttls = [r.ttl for r in diverge if r.ttl is not None]
    max_ttl = max(div_ttls) if div_ttls else None
    # Ground-truth TTL from authoritative rows in the input set.
    auth_rows = [r for r in rows if r.scope == "authoritative" and r.ttl is not None]
    auth_ttl = auth_rows[0].ttl if auth_rows else None

    evidence = [
        f"Authoritative: {', '.join(sorted(auth_answers))}"
        + (f"  (TTL {_fmt_ttl(auth_ttl)})" if auth_ttl is not None else ""),
        f"Divergent: {', '.join(diverge_names)}{more}",
    ]
    if max_ttl is not None:
        evidence.append(
            f"Longest divergent TTL: {_fmt_ttl(max_ttl)} (~{max_ttl}s) — worst-case wait for natural expiry."
        )
    if errors:
        evidence.append(f"{len(errors)} resolvers returned errors or timed out.")

    action: str | None = None
    if flushable:
        action = f"`rndc flushname {target}` on " + ", ".join(r.name for r in flushable)
    elif diverge:
        ttl_hint = f" (~{_fmt_ttl(max_ttl)} worst case)" if max_ttl is not None else ""
        action = (
            "The divergent resolvers are external. Flush cache at the operator, or "
            f"wait for the TTL to expire{ttl_hint}."
        )
    return Summary(
        headline=f"{len(diverge)} of {total_resolver_rows} resolvers returned an answer different from authoritative.",
        severity="warn" if not errors else "error",
        evidence=tuple(evidence),
        suggested_action=action,
    )


def _build_dnssec_summary(rows: list[DnssecRow], zone: str | None, target: str) -> Summary:
    if not rows:
        return Summary(
            headline="No resolvers returned a DNSSEC response.",
            severity="error",
            evidence=(),
            suggested_action=None,
        )
    if zone is None:
        return Summary(
            headline="Could not determine the zone containing this target.",
            severity="unknown",
            evidence=(
                "SOA lookup returned no usable zone owner.",
                "This is normal for .local / private-use names.",
            ),
            suggested_action=None,
        )

    ad_true = [r for r in rows if r.target_ad is True]
    ad_false = [r for r in rows if r.target_ad is False]
    ad_none = [r for r in rows if r.target_ad is None]
    from collections import Counter

    dk_counter = Counter(r.dnskey_records for r in rows if r.dnskey_records)
    ds_counter = Counter(r.ds_records for r in rows if r.ds_records)
    majority_dk = dk_counter.most_common(1)[0][0] if dk_counter else ()
    majority_ds = ds_counter.most_common(1)[0][0] if ds_counter else ()
    majority_dk_set = set(majority_dk)
    majority_ds_set = set(majority_ds)
    sample_dk_summary = next((r.dnskey_summary for r in rows if r.dnskey_summary), None)
    sample_ds_summary = next((r.ds_summary for r in rows if r.ds_summary), None)

    # Fast happy path: one DNSKEY set, <=1 DS set, all AD flags set.
    if len(dk_counter) <= 1 and len(ds_counter) <= 1 and ad_false == [] and ad_true:
        return Summary(
            headline=f"DNSSEC chain intact at {zone}: all resolvers validate; DNSKEY + DS consistent.",
            severity="ok",
            evidence=(
                f"{len(ad_true)} of {len(rows)} resolvers set the AD flag.",
                f"DNSKEY: {sample_dk_summary}" if sample_dk_summary else "No DNSKEY present.",
                f"DS: {sample_ds_summary}"
                if sample_ds_summary
                else "No DS present (zone is an apex / unsigned parent).",
            ),
            suggested_action=None,
        )

    evidence: list[str] = []
    # Culprit = a resolver whose DNSKEY or DS set ISN'T a subset of
    # the majority set (extra records the majority doesn't have), OR
    # which failed to set AD when others did.
    culprits: list[DnssecRow] = []
    for r in rows:
        dk = set(r.dnskey_records)
        ds = set(r.ds_records)
        if majority_dk_set and dk and not dk.issubset(majority_dk_set):
            culprits.append(r)
            continue
        if majority_ds_set and ds and not ds.issubset(majority_ds_set):
            culprits.append(r)
            continue
        if r.target_ad is False and ad_true:
            culprits.append(r)

    if culprits:
        c = culprits[0]
        headline = (
            f"DNSSEC chain diverges at zone `{zone}` -- {c.name} "
            f"({c.resolver_ip}) disagrees with the rest."
        )
        if c.dnskey_records and majority_dk and set(c.dnskey_records) != majority_dk_set:
            extras = set(c.dnskey_records) - majority_dk_set
            missing = majority_dk_set - set(c.dnskey_records)
            if extras:
                evidence.append(f"{c.name} has {len(extras)} DNSKEY(s) not in majority set.")
            if missing:
                evidence.append(f"{c.name} is missing {len(missing)} DNSKEY(s) present in majority.")
        if c.ds_records and majority_ds and set(c.ds_records) != majority_ds_set:
            extras = set(c.ds_records) - majority_ds_set
            missing = majority_ds_set - set(c.ds_records)
            if extras:
                evidence.append(f"{c.name} has {len(extras)} DS record(s) not in majority set.")
            if missing:
                evidence.append(f"{c.name} is missing {len(missing)} DS record(s) present in majority.")
        if c.target_ad is False:
            evidence.append(f"{c.name} did not set AD flag; {len(ad_true)} other resolvers did.")
        action = None
        if c.flushable:
            action = f"`rndc flushtree {zone}` on the local recursor, then re-check."
        elif c.scope in ("house", "mine"):
            action = f"If {c.name} is under your control, flush `{zone}` there. Otherwise wait for TTL."
        return Summary(
            headline=headline,
            severity="error",
            evidence=tuple(evidence),
            suggested_action=action,
        )

    # Inconsistent but no clear culprit (e.g. all resolvers lack AD flag).
    if ad_false and not ad_true:
        return Summary(
            headline=f"No resolver validated DNSSEC for {target} (AD flag never set).",
            severity="warn",
            evidence=(
                f"{len(ad_false)} resolvers responded; none set AD.",
                f"DNSKEY present: {'yes' if majority_dk_set else 'no'}. DS present: {'yes' if majority_ds_set else 'no'}.",
                "Likely: zone is unsigned, or trust-anchor issue on the recursors, or DS missing at parent.",
            ),
            suggested_action=(
                f"Check `delv @127.0.0.1 {target}` for validation detail; "
                f"run `dig DS {zone} @<parent-ns>` to see if DS is published."
            ),
        )
    return Summary(
        headline="DNSSEC state is mixed but no single resolver is obviously at fault.",
        severity="warn",
        evidence=(
            f"AD flag: true={len(ad_true)} false={len(ad_false)} unknown={len(ad_none)}.",
            f"Unique DNSKEY values: {len(majority_dk_set)}.",
            f"Unique DS values: {len(majority_ds_set)}.",
        ),
        suggested_action=None,
    )


async def run_trace(
    target: str,
    record_type: str = "A",
    *,
    user_id: _uuid.UUID | None = None,
    include_external: bool = True,
    group_tag: str | None = None,
    mode: Literal["answer", "dnssec"] = "answer",
) -> TraceReport:
    # --- gather targets ---------------------------------------------------
    resolvers = _load_resolvers(user_id, include_external, group_tag=group_tag)
    auth_ns = await _authoritative_ns_ips(target)

    # Synthetic local row: whatever sits on 127.0.0.1 (our BIND9). Not in
    # the resolvers table; we always include it because this is the
    # recursor the portal itself uses and the one admins can flush.
    @dataclass
    class _ResolverLite:
        name: str
        ip: str
        region: str | None
        owner_user_id: _uuid.UUID | None

    synthetic_local = _ResolverLite(
        name="Local recursor",
        ip="127.0.0.1",
        region="Portal host",
        owner_user_id=None,
    )
    resolver_chain: list = [synthetic_local] + list(resolvers)

    # --- fire all queries in parallel ------------------------------------
    async def _probe_one(r) -> tuple[object, DigResult, bool | None]:
        try:
            dig_res, ad = await asyncio.gather(
                asyncio.wait_for(
                    _dig(target, record_type, r.ip, ("+noall", "+answer")), timeout=_PER_QUERY_TIMEOUT_S
                ),
                _ad_flagged(target, record_type, r.ip),
            )
        except TimeoutError:
            dig_res = _timed_out_result(f"dig @{r.ip} {target} {record_type}")
            ad = None
        except ValueError as e:
            # dig.py rejected the resolver IP (shouldn't happen for DB rows,
            # but stay defensive). Emit a synthetic error row so the whole
            # trace doesn't 400 on one bad entry.
            dig_res = DigResult(
                command=f"dig @{r.ip} {target} {record_type}",
                stdout="",
                stderr=str(e),
                returncode=2,
                duration_ms=0,
                truncated=False,
                timed_out=False,
            )
            ad = None
        return r, dig_res, ad

    async def _probe_auth(ns_name: str, ns_ip: str):
        try:
            dig_res = await asyncio.wait_for(
                _dig(target, record_type, ns_ip, ("+noall", "+answer")),
                timeout=_PER_QUERY_TIMEOUT_S,
            )
        except TimeoutError:
            dig_res = _timed_out_result(f"dig @{ns_ip} {target} {record_type}")
        return ns_name, ns_ip, dig_res

    async def _trace():
        # dig.py's flag allowlist only accepts the chips the UI exposes;
        # `+trace` is on that list, extra +no* shortcuts are not. Keep
        # the call minimal and accept the default verbosity.
        try:
            return await asyncio.wait_for(
                _dig(target, record_type, None, ("+trace",)),
                timeout=_TRACE_TIMEOUT_S,
            )
        except TimeoutError:
            return DigResult(
                command=f"dig {target} {record_type} +trace",
                stdout="[+trace timed out]",
                stderr="timeout",
                returncode=124,
                duration_ms=int(_TRACE_TIMEOUT_S * 1000),
                truncated=False,
                timed_out=True,
            )

    resolver_task = asyncio.gather(*[_probe_one(r) for r in resolver_chain])
    auth_task = asyncio.gather(*[_probe_auth(n, ip) for n, ip in auth_ns])
    trace_task = asyncio.create_task(_trace())

    resolver_probes, auth_probes, trace_res = await asyncio.gather(
        resolver_task,
        auth_task,
        trace_task,
    )

    # --- build authoritative answer set ---------------------------------
    auth_answers = set()
    auth_ttls: list[int] = []
    auth_rows_struct: list[TraceRow] = []
    for ns_name, ns_ip, r in auth_probes:
        raw_ans, ttl = _first_answer_and_ttl(r.stdout)
        ans = _normalise(raw_ans)
        if ans:
            auth_answers.add(ans)
        if ttl is not None:
            auth_ttls.append(ttl)
        auth_rows_struct.append(
            TraceRow(
                scope="authoritative",
                name=ns_name,
                resolver_ip=ns_ip,
                region=None,
                answer=ans,
                ttl=ttl,
                ok=(r.returncode == 0 and ans is not None),
                status="match" if ans else "error",
                duration_ms=r.duration_ms,
                error=(r.stderr.strip() or None) if r.returncode != 0 else None,
                flushable=False,
                ad_flag=None,
            )
        )

    # --- classify each resolver row -------------------------------------
    def _scope_for(res) -> Scope:
        if res.ip == "127.0.0.1":
            return "local"
        if getattr(res, "owner_user_id", None) is None:
            return "house"
        return "mine"

    rows: list[TraceRow] = []
    for res, dig_res, ad in resolver_probes:
        raw_ans, ttl = _first_answer_and_ttl(dig_res.stdout)
        ans = _normalise(raw_ans)
        if dig_res.returncode != 0 or ans is None:
            status: Status = "error"
        elif auth_answers and ans not in auth_answers:
            status = "divergent"
        elif auth_answers:
            status = "match"
        else:
            status = "unknown"
        rows.append(
            TraceRow(
                scope=_scope_for(res),
                name=res.name,
                resolver_ip=res.ip,
                region=getattr(res, "region", None),
                answer=ans,
                ttl=ttl,
                ok=(status == "match"),
                status=status,
                duration_ms=dig_res.duration_ms,
                error=(dig_res.stderr.strip() or None) if dig_res.returncode != 0 else None,
                flushable=(res.ip == "127.0.0.1"),
                ad_flag=ad,
            )
        )

    # Authoritative rows come last so the UI groups: local/house/mine, then authoritative.
    rows.extend(auth_rows_struct)

    # --- divergence summary --------------------------------------------
    divergent = [r for r in rows if r.status == "divergent"]
    pod = None
    if divergent:
        first = divergent[0]
        pod = f"{first.name} ({first.resolver_ip}) returns {first.answer or '—'}; authoritative returns {', '.join(sorted(auth_answers)) or '—'}"

    # Cap trace output so the response stays under a megabyte.
    trace_out = trace_res.stdout or ""
    truncated = len(trace_out) > 16_000
    if truncated:
        trace_out = trace_out[:16_000] + "\n... [truncated]"

    # --- DNSSEC mode: one extra probe per resolver --------------------
    dnssec_rows: list[DnssecRow] = []
    zone: str | None = None
    if mode == "dnssec":
        zone = await _discover_zone(target)

        async def _dprobe(r):
            t_dig, ad, has_rrsig, dk_set, ds_set = await _dnssec_probe(r.ip, target, record_type, zone)
            raw_ans, ttl = _first_answer_and_ttl(t_dig.stdout)
            ans = _normalise(raw_ans)
            if t_dig.returncode != 0 or ans is None:
                status: Status = "error"
            else:
                status = "match"  # divergence recomputed below
            return DnssecRow(
                scope=_scope_for(r),
                name=r.name,
                resolver_ip=r.ip,
                region=getattr(r, "region", None),
                target_answer=ans,
                target_ttl=ttl,
                target_ad=ad,
                target_has_rrsig=has_rrsig,
                dnskey_records=dk_set,
                ds_records=ds_set,
                dnskey_summary=_dnskey_summary(dk_set),
                ds_summary=_ds_summary(ds_set),
                zone=zone,
                status=status,
                divergence_reason=None,  # filled in by status classifier below
                duration_ms=t_dig.duration_ms,
                error=(t_dig.stderr.strip() or None) if t_dig.returncode != 0 else None,
                flushable=(r.ip == "127.0.0.1"),
            )

        dnssec_rows = list(await asyncio.gather(*[_dprobe(r) for r in resolver_chain]))
        # DNSSEC-specific status: don't treat target-answer divergence as
        # "divergent" in this mode (geo-DNS causes legitimate answer
        # differences that aren't DNSSEC issues). Classify each row by:
        #   - error     : query failed / timed out
        #   - unknown   : zone appears unsigned (no DNSKEY, no DS, no AD
        #                 flag anywhere among resolvers) -- nothing to validate
        #   - divergent : this resolver's DNSKEY or DS differs from the
        #                 majority, or this resolver failed to set AD when
        #                 others did (likely stale cache or bad trust anchor)
        #   - match     : DNSSEC state agrees with majority
        # Set-based majority comparison (a zone has KSK + ZSK, plus
        # rollover extras; first-line sampling would produce spurious
        # divergence). A resolver's DNSKEY_SET is "consistent with
        # majority" if it's exactly equal to the majority set, OR if
        # it's a subset of the majority (dig may truncate very large
        # RRsets depending on buffer size -- subsets are still valid).
        from collections import Counter

        dk_counter = Counter(r.dnskey_records for r in dnssec_rows if r.dnskey_records)
        ds_counter = Counter(r.ds_records for r in dnssec_rows if r.ds_records)
        majority_dk = dk_counter.most_common(1)[0][0] if dk_counter else ()
        majority_ds = ds_counter.most_common(1)[0][0] if ds_counter else ()
        majority_dk_set = set(majority_dk)
        majority_ds_set = set(majority_ds)
        any_ad_true = any(r.target_ad is True for r in dnssec_rows)
        ad_true_count = sum(1 for r in dnssec_rows if r.target_ad is True)
        zone_unsigned = not dk_counter and not ds_counter and not any_ad_true

        def _dnssec_status(row: DnssecRow) -> tuple[Status, str | None]:
            """Returns (status, reason-if-divergent). Reason is populated
            only when status == 'divergent' so the UI can tell the user
            exactly what's off on THIS row, without having to scan the
            summary at the top."""
            if row.error or row.target_answer is None:
                return "error", row.error or "no answer"
            if zone_unsigned:
                return "unknown", None
            dk_set = set(row.dnskey_records)
            ds_set = set(row.ds_records)
            # DNSKEY divergence: this resolver has keys not in the majority
            # set OR is missing keys that the majority has.
            if majority_dk_set and dk_set:
                extras = dk_set - majority_dk_set
                missing = majority_dk_set - dk_set
                if extras or missing:
                    bits = []
                    if extras:
                        bits.append(f"{len(extras)} extra DNSKEY not in majority set")
                    if missing:
                        bits.append(f"missing {len(missing)} DNSKEY present in majority")
                    return "divergent", "; ".join(bits)
            # DS divergence, same logic.
            if majority_ds_set and ds_set:
                extras = ds_set - majority_ds_set
                missing = majority_ds_set - ds_set
                if extras or missing:
                    bits = []
                    if extras:
                        bits.append(f"{len(extras)} extra DS not in majority set")
                    if missing:
                        bits.append(f"missing {len(missing)} DS present in majority")
                    return "divergent", "; ".join(bits)
            # AD flag divergence: this resolver didn't validate even though
            # others did. This is the most common real-world DNSSEC
            # breakage -- stale / missing trust anchor on ONE resolver.
            if row.target_ad is False and any_ad_true:
                return "divergent", (
                    f"AD flag not set by this resolver; {ad_true_count} other resolver(s) validated. "
                    "Likely a stale/missing trust anchor or recursor not doing validation."
                )
            return "match", None

        new_rows = []
        for row in dnssec_rows:
            st, reason = _dnssec_status(row)
            new_rows.append(
                DnssecRow(
                    **{k: v for k, v in row.__dict__.items() if k not in ("status", "divergence_reason")},
                    status=st,
                    divergence_reason=reason,
                )
            )
        dnssec_rows = new_rows

    # --- summary ------------------------------------------------------
    if mode == "dnssec":
        summary = _build_dnssec_summary(dnssec_rows, zone, target)
    else:
        summary = _build_answer_summary(list(rows), set(auth_answers), target)

    return TraceReport(
        target=target,
        record_type=record_type,
        mode=mode,
        authoritative_answers=tuple(sorted(auth_answers)),
        rows=tuple(rows),
        dnssec_rows=tuple(dnssec_rows),
        zone=zone,
        recursion_trace=trace_out,
        recursion_trace_truncated=truncated,
        divergence=bool(divergent) or not auth_answers,
        point_of_divergence=pod,
        summary=summary,
    )
