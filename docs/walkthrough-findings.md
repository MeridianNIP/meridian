# Portal walkthrough — findings log

> **STATUS: CLOSED — kept as history.** This document is the scratch pad from
> the pre-1.0 walkthrough that drove the gap-closing work landed in v1.0.0.
> The status column does **not** reflect current state — most entries shipped
> as features in 1.0.0; commercial-model references (FSL-1.1, paid tiers,
> license tokens) are historical context superseded by the 2026-05-13
> Apache 2.0 decision. Don't act on entries here without checking the
> current code first.

Running log of gaps, bugs, and enhancement ideas found while walking through
the live Meridian portal page by page. Not a spec; not a backlog ticket
board. This is the scratch pad between "I noticed X" and "someone writes
code for X."

Entry format:
- **Finding** — one-line summary
- **Where** — page / template / code path
- **Type** — `fix` (broken), `enhance` (works but incomplete), `defer` (tied
  to a gated decision like the commercial model), `question` (design
  undecided)
- **Status** — `open`, `in-progress`, `done`, `wontfix`, `deferred-to-<x>`
- **Notes** — any extra context

---

## Dashboard (`/ui/dashboard`)

### Password change on first login did not trigger
- **Where**: first admin login after `install.sh seed_first_admin` runs
  `users create ... --force-change-at-login`.
- **Type**: `fix`
- **Status**: `open`
- **Notes**: User OK with it for now but the flag is supposed to force a
  reset flow and didn't. Likely the `must_change_password` / session check
  isn't wired into the login flow. `app/auth/` and the login route need
  inspection when touched.

### Stat tile titles should be clickable links to their detail pages
- **Where**: dashboard top-row tiles — "Queries today", "Active sessions",
  "Recent alerts", "License".
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: All four tiles now wrapped in `<a>` with role-aware hrefs:
  - Queries today → `/ui/monitors` (proxy destination; a dedicated
    queries-log page doesn't exist yet — future work)
  - Active sessions → `/ui/admin/users` for admin (all users' sessions);
    `/ui/settings#sessions` for non-admin (just theirs)
  - Recent alerts → `/ui/monitors#alerts`
  - License → `/ui/admin/branding#license` for admin (install key);
    `/ui/settings` for non-admin (info-only)
  - Title attrs explain each destination on hover.

### Active sessions should be role-scoped
- **Where**: dashboard "Active sessions" tile + detail page.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Admin sees all sessions (user, device, IP, last-seen). Analyst
  / operator / read-only see only their own. Ties into existing scope /
  RBAC model.

### License tile wording
- **Where**: dashboard License tile.
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; Option 2 picked; deployed live)
- **Notes**: Unlicensed state now reads `COMMUNITY · free for
  non-commercial · commercial → meridiannip.com/pro` (previously
  "TIER / unlicensed"). Licensed state unchanged (tier name + days
  remaining). Pricing decision updated in
  `project_meridian_commercial_model.md`: two customer-selectable options
  — $550/yr subscription OR $1500 one-time perpetual; FSL-1.1's 2-year
  auto-Apache rollover makes both paths converge to perpetual use.

### "your max: 1" line on Active sessions tile
- **Where**: dashboard Active sessions tile delta line.
- **Type**: `fix`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Per-user session cap dropped from the dashboard. Delta line
  now reads `all users · last 24h` (admin view) or `across your devices`
  (non-admin). Max-user caps are being removed from the licensing model
  entirely (per revised commercial plan), so the number wasn't useful.

### "Recent activity" should show *which user* performed each event
- **Where**: dashboard.html:62-74 "Recent activity" card; enrichment in
  `app/ui/routes.py` dashboard route.
- **Type**: `fix`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Dashboard route now does a bulk user-id lookup and builds
  render-ready items with `actor` (username of who did the action) and
  resolved `target` (when `target_type='user'`, shows the target user's
  username instead of their UUID). Template updated to render
  "{ts} {actor} {action} · {target}" with outcome shown when != "ok".
  Fixes the "auth.login · 81b79f88-..." unreadability.

### Pinned tools is hardcoded, not user-customizable
- **Where**: dashboard.html:46-59 — six static tiles.
- **Type**: `enhance`
- **Status**: `open` (circling back from an earlier session per user
  recollection; no prior work in memory)
- **Notes**: Intent is per-user customization — each user picks their own
  set of shortcuts for the dashboard. Requires:
  - `user_pinned_tools` table (`user_id`, `tool_key`, `position`)
  - An "add/remove/reorder" UI on the dashboard itself or on a settings
    page
  - Backfill a sensible default (the current six) for new users
  - Server route to read/write the pins for the current user

### "My settings" button in dashboard header is redundant with avatar menu
- **Where**: `app/templates/dashboard.html:12` — page-head button →
  `/ui/settings`.
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; button removed, deployed live)
- **Notes**: Removed — avatar dropdown already exposes all settings
  anchors. Reintroduce a differently-named button ("Customize dashboard")
  when the pinned-tools customization UI ships.

### Recent activity was still rendering opaque UUIDs for non-user targets
- **Where**: dashboard `Recent activity` feed; enrichment in `app/ui/routes.py`.
- **Type**: `fix`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Follow-on to the actor fix above — `auth.login` events had
  `target_type='session'` with a UUID `target_key`, which rendered as
  "admin · auth.login · 81b79f88-...". Session UUIDs tell an end-user
  nothing. Enrichment now hides any UUID-shaped target_key outright;
  readable keys (domain names, hostnames, zone names, IPs) still render.

---

## DNS Tools (`/ui/dns-tools`)

### Dig resolver dropdown had 4 resolvers; should match Propagation's 16
- **Where**: `app/templates/dns_tools.html:49-54` (Dig panel) and
  `:137-142` (Reverse DNS panel); canonical list in
  `app/dns/propagation.py:PUBLIC_RESOLVERS`.
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Both dropdowns now render the 16-entry `PUBLIC_RESOLVERS`
  panel (plus the "System (BIND9)" default). DNS-tools route injects
  `public_resolvers` into the template context so the list stays in sync
  with the Propagation tab automatically — no duplication.

### Propagation results should have CSV export
- **Where**: `app/templates/dns_tools.html` propagation panel; results table
  rendered into `#prop-output` by `portal.js:renderResult()`.
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Added an "Export CSV" button in the Results card header,
  disabled until a results table exists (observed via MutationObserver),
  client-side CSV generated from the rendered rows so no extra API
  round-trip. Filename template `<target>-<record-type>-<iso-stamp>.csv`.

### DNSSEC panel should have a graphical chain-visualization (dnsviz-style)
- **Where**: `app/templates/dns_tools.html` DNSSEC panel.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Today's DNSSEC panel runs a textual validation. The user
  wants the equivalent of https://dnsviz.net/ — a rendered trust-chain
  diagram with every DS / DNSKEY / RRSIG node, colour-coded by status,
  showing exactly where the chain breaks. The `dnsviz` Python tool is
  already installed on the VM (`/usr/local/bin/dnsviz`, installed by
  `install.sh` into `/opt/admin-tools`). Implementation sketch:
  - Backend: new endpoint `POST /api/v1/dns/dnssec-chain` that runs
    `dnsviz probe <target>` + `dnsviz graph -T svg`, captures stdout,
    returns `{svg: "...", summary: {...}}`.
  - Frontend: DNSSEC panel grows a "Visualize chain" button that posts
    the target and embeds the returned SVG inline; clicking a node
    opens a side-panel with the text analysis from `dnsviz grok`.
  - Security: dnsviz does live DNS traffic. Rate-limit per-user and
    sandbox via the same `/run/meridian-sandbox` + AppArmor profile the
    existing DNS tools use.

### Hop trace — DNSSEC mode + diagnosis summary (IMPLEMENTED, extends earlier build)
- **Where**: `app/dns/trace.py` (Summary + DnssecRow dataclasses,
  `_dnssec_probe`, `_build_answer_summary`, `_build_dnssec_summary`);
  `app/dns/routes.py` TraceInput.mode; `app/templates/dns_tools.html`
  mode selector + new columns + summary card.
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Every trace now leads with a **diagnosis summary** — a
  headline verdict, evidence bullets explaining how the verdict was
  reached, and (when possible) one suggested next action (e.g. `rndc
  flushname <target> on Local recursor`). Works for both modes:
  **Answer mode** compares resolver answers against authoritative;
  **DNSSEC mode** (selected via form + auto-set when Troubleshoot is
  clicked from the DNSSEC tab) additionally queries DNSKEY + DS of the
  target's zone at each resolver and captures AD/RRSIG presence. When a
  single resolver disagrees with the majority, the summary names it
  explicitly ("Problem: {resolver} has wrong DNSKEY for zone {X}").
  Table columns shift to show DNSKEY / DS samples per resolver in
  DNSSEC mode; CSV export adapts to whichever mode was run.
  Known follow-ups: (1) authoritative-truth for DNSSEC comes from the
  majority-of-resolvers heuristic, not a parent-NS DS lookup — V2; (2)
  a dnsviz-style graphical chain view as a separate tab is still open.

### Hop trace — base build (resolver-by-resolver comparison)
- **Where**: `app/dns/trace.py` (new module); `/api/v1/dns/trace`
  endpoint in `app/dns/routes.py`; new "Hop Trace" tab in
  `app/templates/dns_tools.html`; "Troubleshoot →" buttons on the Dig
  and DNSSEC panels.
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Given a target + record type, fires three waves of DNS
  queries in parallel: (1) every visible resolver from the Resolvers
  tab (house + personal + portal's local BIND9); (2) each authoritative
  NS server for the target's zone (ground truth); (3) a full `dig
  +trace`. Total wall time ≈ slowest resolver's RTT (5s timeout per
  query, 80-resolver fanout cap). Each resolver row is tagged `match` /
  `divergent` / `error` based on its answer vs the authoritative set;
  divergent rows show the `point_of_divergence` banner. For rows where
  the resolver is our own BIND9, a one-click **Flush this record**
  button pipes to the existing `rndc-flush` endpoint (admin-only). AD
  flag per resolver captured via a second `+dnssec` query. CSV export
  of the chain supported. Cross-tab Troubleshoot button on Dig /
  DNSSEC pre-fills the target + record type and auto-submits the trace.

### (superseded) "DNS walk" design notes
- **Where**: would be a new tab/panel under DNS Tools, or a new
  /ui/network-diag-style page.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Operator workflow: given a domain and a RR type, query
  **each configured resolver in a chain** (end-user-facing local DNS →
  upstream local DNS → enterprise cache → authoritative on the
  Internet) and show the answer each one returned side-by-side. The
  point is to pin down exactly which resolver has the bad cache so the
  operator knows where to run `rndc flushname` / `flushtree` (or ask
  the upstream operator to). Implementation sketch:
  - Config: admin defines an ordered list of resolvers that represents
    "the chain" (or multiple named chains for multi-site). Could piggyback
    on the user-defined resolvers feature below.
  - Query each resolver in order with the same `dig` call, collect
    answer + TTL + AA/AD flags + RRSIG presence + server returned in
    the Additional section.
  - Also do one authoritative query (resolve NS for the zone apex, then
    query one of those servers directly) as the ground-truth row at
    the bottom.
  - Render as a table: columns = each resolver + authoritative;
    highlight the first row that disagrees with authoritative. Offer a
    one-click "Flush this record on this resolver" action (gated by
    permission) that pipes to rndc if the resolver is our own BIND9.

### Users should be able to add / edit / remove their own resolvers
- **Where**: new `resolvers` table; `app/models/resolver.py`;
  `app/dns/resolver_routes.py`; new "Resolvers" tab in
  `app/templates/dns_tools.html`.
- **Type**: `enhance`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Implemented as a single `resolvers` table with
  `owner_user_id` NULL = house (admin-curated, shared) vs owner = personal
  (per-user). The 16 canonical public resolvers are seeded on install as
  house entries with `is_propagation_default=TRUE`; admins can rename,
  re-tag, delete, or un-default any of them. Propagation tool now
  DB-sourced (`_load_active_panel()` in `propagation.py`), with the
  in-code `PUBLIC_RESOLVERS` tuple kept as a fresh-install / DB-blip
  fallback. Dig + Reverse dropdowns pull from DB grouped by scope
  (`<optgroup>` House / Mine). CRUD API at `/api/v1/dns/resolvers` with
  ownership-aware permissions (owners + admins can write; everyone reads
  house + own). Management UI is a new **Resolvers** tab under DNS Tools.
  Admin-only controls: scope=house, is_propagation_default flag,
  editing/deleting house entries.
  Known follow-ups (separate findings): edit-in-place (currently delete +
  re-add); CSRF protection at app layer (flagged globally in
  `project_ddi_portal.md`); regional fast-path defaults (auto-curate
  propagation panel based on install region).

### Bug: personal resolvers flagged `is_propagation_default` were silently ignored
- **Where**: `app/dns/propagation.py:_load_active_panel`;
  `app/dns/routes.py` `/propagation` endpoint.
- **Type**: `fix`
- **Status**: `done` (2026-04-20; deployed live)
- **Notes**: Original query filtered `owner_user_id IS NULL` only, so a
  personal resolver with `is_propagation_default=TRUE` (admin-accessible
  via the add-form checkbox) would save but never show up in propagation
  output. Fix threads `user_id` through `check_propagation(...)` down to
  `_load_active_panel(user_id=...)`, which now selects house entries
  plus that user's personal entries with the flag. Personal entries
  still don't leak into *other* users' propagation checks.

### UX: "include in Propagation panel" checkbox is easy to miss on add
- **Where**: Resolvers tab → Add form.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Field layout hides the checkbox in a narrow column; users
  expect a newly-added resolver to participate in Propagation by default.
  Options: (a) default the checkbox to checked for scope=mine; (b) move
  it into a more prominent row; (c) add edit-in-place so the flag can
  be toggled after the fact without delete/re-add.

---

## Auth — password recovery / reset

### Password-reset crashed with `column "revoke_reason" does not exist`
- **Where**: `app/auth/routes.py:407` — "Set new password" endpoint.
- **Type**: `fix`
- **Status**: `done` (2026-04-20; deployed live to meridian-vm, app restarted)
- **Notes**: SQL text wrote `revoke_reason` (no `d`); schema column is
  `sessions.revoked_reason`. Typo. Fixed the query; every other call site
  in the codebase already uses the correct name.

### Schema column-naming inconsistency: `revoke_reason` vs `revoked_reason`
- **Where**: `db/schema.sql` — `sessions.revoked_reason` (line 156) and
  `licenses.revoked_reason` (line 315) vs `certificates.revoke_reason`
  (line 1015).
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Three tables use the "revoked_*" pattern, one (certificates)
  dropped the `d`. `app/models/cert.py:54` matches its schema, so nothing
  is broken today, but the inconsistency will keep biting on future code
  that assumes one spelling. Normalize to `revoked_reason` everywhere when
  we do the first DB migration (ties to the "no migrations yet" gap in
  `project_ddi_portal.md`).

---

## Admin — global settings, roles, permissions (NEW, big)

### Super-Admin Global Settings page (compliance-critical)
- **Where**: no current page; requested 2026-04-21 during walkthrough.
- **Type**: `enhance`
- **Status**: `open` (substantial; needs a dedicated design pass)
- **Notes**: A new `/ui/admin/settings` surface, visible ONLY to
  `super_admin`, that acts as the policy root for the entire portal:
  - **Session / idle**: global default + MAX idle timeout (sub-admins
    and users can opt into shorter, never longer). Lives next to the
    existing `session_idle_timeout_default_min` / `_max_min` branding
    fields -- expose them here too, with an enforcement note.
  - **Roles**: list existing (admin / super_admin / analyst / operator
    / read-only / custom). Allow creating new roles, renaming,
    archiving (not delete -- role might be referenced by audit rows).
    Each role carries a default permission mask.
  - **Permissions**: per-role permission matrix (read / write / admin
    on each module: DNS Tools, Network, Monitors, Runbooks, IPAM,
    DHCP, Certificates, Admin panel tabs, etc.). The existing scope
    manager handles feature toggles per group; this is the lower-
    level capability matrix.
  - **Password policy** (length, complexity, reuse window, max age).
  - **MFA policy** (required / optional / per-role).
  - **Audit retention** (days before archive; days before purge).
  - **Lockout policy** (failed-login threshold + cooldown).
  - **Login banner / pre-login warning**.
  - **Scope Manager overrides** (super admin can lock a feature
    on-or-off globally so group admins can't override).
  - **Compliance templates** (SOC 2 / HIPAA / NIST defaults) -- one-
    click apply baseline values, log the change to audit.
- **Why commercial-critical**: SOC 2 / HIPAA / ISO 27001 auditors
  require demonstrable access-policy enforcement at the org level;
  today bits of this are scattered across branding, scope manager,
  and user settings. A single Super-Admin Global Settings page is
  the minimum bar. Also gates the "sub-admin can only tighten, not
  loosen" guarantee the user wants for commercial customers.
- **Schema hits**: `role_permissions` join table (or a JSONB column
  on roles); `policy_settings` table or an extension of `branding`;
  an audit-event class for policy changes with a special hash-chain
  entry.
- **Blast radius**: this touches auth, RBAC, branding, admin UX, and
  the audit log. Worth a dedicated session / small design doc
  before starting. Queued as the next major feature after the
  walkthrough completes.

### Role management in admin UI (subset of the above)
- **Where**: today roles are a fixed enum used across
  `app/models/user.py`, `app/auth/*`, and templates (`user.role in
  ('admin', 'super_admin')`). Scope Manager handles feature toggles;
  there is no UI to create roles or tune per-role permissions.
- **Type**: `enhance`
- **Status**: `open` (depends on the global-settings page above)
- **Notes**: Once roles are schema-backed (not a hardcoded enum),
  most of the "if user.role in (...)" sprinkled across templates
  can switch to permission-bit checks, which is what a grown-up
  RBAC looks like.

---

## Template for new entries

```
### <Short finding title>
- **Where**: <page / template / code path>
- **Type**: `fix` | `enhance` | `defer` | `question`
- **Status**: `open`
- **Notes**: <context>
```

Append new sections below as you walk through each page.

---

## Post-walkthrough backlog (2026-04-21)

Parked during the Wizards pass — revisit after the page-by-page walkthrough
is complete. None block the current audit.

### Built-in scheduled reports (daily / weekly / monthly / custom)
- **Where**: new `/ui/reports` page + a scheduler hook (Celery beat)
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Users want regularly-generated reports from DNS Tools, Network
  Tools, Threat Intel, and Wizards output. Needs:
  - Report definitions (name, data source, target, cadence, recipients)
  - Cadence presets: daily, weekly, monthly, plus custom cron
  - Output formats: PDF (print pipeline already exists), CSV, email body
  - Delivery: email channel (reuse existing notification channels), file
    drop into `/ui/files`, or in-app inbox
  - Ad-hoc re-run + download of the last N generations
  - Row-level permission check so a viewer can't schedule admin-only data
- Depends on: deciding data-source registry shape (per-tool "export for
  report" contract) before implementing.

### Important Links page (user-curated bookmarks)
- **Where**: new `/ui/links` sidebar entry; new `important_links` table
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Per-user (and optionally team-scoped) bookmark board. Each
  link carries URL + title + description + category/tag + owner. Full
  CRUD (add / edit / delete). Consider:
  - Personal vs shared (global) scope, same toggle pattern as
    notification channels
  - Optional icon / favicon fetch (cached, served from `/static` so
    nginx does the work)
  - Search / filter box at the top
  - Order: manual drag or alphabetical by category
  - Export / import (JSON) for migration between portals

### Global Settings — log shipping to SIEM / syslog
- **Where**: new section on `/ui/admin/settings` + new
  `log_shipping_config` table.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Corporate environments require portal activity to land in
  a centralised log server. Support:
  - **Syslog (RFC 5424 over TCP/UDP)** — host, port, facility, TLS
    cert, optional mTLS client cert
  - **Splunk HEC** — URL, HEC token, index, source, sourcetype
  - **Elastic / ECS** — URL, API key, index pattern
  - **CEF-over-syslog** for ArcSight / QRadar (map Meridian audit rows
    to CEF key=value pairs)
  Config fields: enabled toggle, transport, destination URL/host/port,
  auth secret (vault), optional CA cert, batch size, flush interval,
  event filter (which audit categories to ship), retry policy. A
  sidecar worker (or Celery beat task) tails `audit_events` +
  `notif_deliveries` and POSTs/sends in batches. Failures fall back to
  a disk spool so a downed collector doesn't drop events.

### Global Settings — make the page active
- **Where**: `/ui/admin/settings` + new schemas (`roles`,
  `role_permissions`, `audit_retention`, `password_policy`,
  `session_policy`, `compliance_baseline`).
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Current preview reads policies off the `branding` row.
  Move each policy domain to its own table + edit surface:
  - **Session / idle / lockout** — `session_policy` table
  - **Password policy** (min length, complexity, rotation period, expiry
    warnings) — `password_policy` table
  - **MFA requirement** (require / recommend / off by role) —
    `mfa_policy` table
  - **Audit retention** + **query retention** + **archive retention** —
    `retention_policy` table (extends the current `retention_rules`)
  - **Roles** + **role_permissions** — first-class tables (today role is
    a hardcoded enum)
  Each with a PATCH endpoint + audit trail. Save buttons light up as
  each domain ships its schema.

### Password max-age expiry notifications
- **Where**: new beat task + in-portal inbox + email channel.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Notify users at 15 / 10 / 5 / 4 / 3 / 2 / 1 days before
  their password expires. Dispatch through both the in-app
  `notif_deliveries` inbox and the user's preferred email channel. Each
  threshold fires once per password cycle (track `last_notified_at` on
  `users` per threshold, or compute from `password_changed_at`).
  Reuses the existing notifications dispatcher.

### Archive retention — editable default, 365
- **Where**: `retention_rules` table + Global Settings UI.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: `retention_rules` already exists with per-scope
  `keep_days`. Surface it as an edit surface in Global Settings with a
  365-day default for each scope (audit_archive, monitor_raw,
  device_snapshots, etc.). Backend accepts an UPDATE; operators see
  the active cap + last-trim timestamp.

### AD auto-provisioning + group → role mapping
- **Where**: directory integration + user-create flow + login hook.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Two behaviours, configurable per DirectoryIntegration:
  1. **Auto-create on first login** — a user who authenticates against
     AD but has no Meridian row gets one created. Username pulled from
     `sAMAccountName` or `userPrincipalName`, email from `mail`.
  2. **Group-to-role mapping** — a JSONB config column on
     `directory_integrations` holds `{ "CN=MNIP-Admins,…": "admin",
     "CN=MNIP-Operators,…": "analyst", … }`. On login, read
     `memberOf`, match against the map, assign the highest-privilege
     role that matches. Re-run on every login so group membership
     changes in AD take effect without a Meridian edit.
  Nested groups need recursive `memberOf:1.2.840.113556.1.4.1941:=`
  matching filter.

### TLS / cipher minimums — audit + lock down deprecated
- **Where**: `/etc/nginx/conf.d/meridian.conf`, app `httpx` clients,
  log-shipping TLS transport, outbound ACME/webhook calls.
- **Type**: `fix`
- **Status**: `open`
- **Notes**: Audit all TLS surfaces and reject deprecated config as of
  2026:
  - **nginx (portal)**: TLS 1.2 + 1.3 only; ciphers from Mozilla
    "Intermediate" or "Modern" profile; HSTS with `preload`;
    disable session-ticket reuse; prefer server ciphers off on 1.3.
  - **httpx outbound**: force `http2=True` where supported; pin
    `ssl.TLSVersion.TLSv1_2` as minimum on every `httpx.AsyncClient`
    construction.
  - **Syslog-TLS / Splunk HEC / Elastic**: same cert validation
    path — reject TLS < 1.2, ECDHE preferred, no RSA key exchange.
  - **LDAPS outbound (directory integrations)**: reject TLS < 1.2;
    require CERT_REQUIRED on `ldap3.Tls`.
  - **SMTP submission**: STARTTLS mandatory; reject anonymous auth;
    reject cleartext AUTH PLAIN over non-TLS.
  Deprecated items to ban explicitly: SSLv2, SSLv3, TLS 1.0, TLS 1.1,
  RC4, 3DES, NULL, EXPORT, anon DH, SHA-1 signatures, RSA-1024 and
  smaller. Ship a `scripts/audit-tls.sh` that runs `testssl.sh` /
  `sslyze` against every exposed TLS surface and pipes the report
  into the portal's admin health page.

### Scope Manager is not a role system — clarify separation
- **Where**: navigation + Global Settings copy.
- **Type**: `enhance` (docs + labelling)
- **Status**: `open`
- **Notes**: Scope Manager is a **firewall / allow-list** for which
  targets (domains, IPs, CIDRs) sandboxed tools may query — it
  prevents operators from dig/nmap/curl-ing the public internet from
  the portal. It has nothing to do with roles or permissions. The
  Global Settings page should make that distinction clear, and the
  Roles/Permissions section there should link to Admin → Users +
  a future Roles table — never to Scope Manager. Rename or relabel
  if users confuse the two.

### Monitors — per-monitor notification tuning
- **Where**: `app/monitors/incidents.py`, `app/monitors/routes.py`, monitors form
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: The open/close-incident + single-notification-per-transition
  design already exists. What's missing is per-monitor tuning. Add:
  - `fail_threshold` field (default 3 — today it's a hardcoded 2 in
    `reconcile()`)
  - Optional `recovery_notify` boolean (default on) so silent-recovery
    monitors are possible
  - Re-notify interval for prolonged outages (e.g. page again every 60
    min while still down) — separate from the initial open notification
  - Quiet hours window per monitor (e.g. "don't page on `non-prod`
    between 22:00–06:00")

### Directory integrations — expand `kind` enum
- **Where**: `directory_type` Postgres enum + `_ALLOWED_DIR` in
  `app/admin/integrations_routes.py` + admin-integrations form.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Current enum: `active_directory / entra_id / ldap_generic`.
  Samba AD works via `active_directory` but users with non-Windows DCs
  miss seeing their stack. Add dedicated values: `samba_ad_dc`,
  `freeipa`, `389_ds`, `openldap`, `jumpcloud`. Each should ship with
  tuned defaults (URI template, bind DN example, schema hints) in the
  admin form's help text.

### Network Devices — operator-facing tab on Network Tools
- **Where**: new tab on `/ui/network-tools`; CRUD stays at
  `/ui/admin/devices`.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Admin owns device registry + credentials + retention
  policy. Network Tools should get a read-only **Devices** tab listing
  inventory with per-row actions: trigger backup-now, view latest
  snapshot, diff two snapshots. Reuses existing endpoints at
  `/api/v1/devices/{id}/snapshots` / `/snapshots/{a}/diff/{b}` —
  no new backend required.

### Device snapshots — per-device retention count
- **Where**: `network_devices` schema + nightly trim task.
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Snapshots pile up indefinitely. Add `retain_snapshots_count`
  column (default 50). Nightly Celery beat task walks every device,
  deletes `DeviceConfigSnapshot` rows beyond the N most recent per
  device. Surface the field in the admin form + "trim now" action.

### System Updates — Update+Reboot now / Schedule window
- **Where**: `/ui/admin/updates` page + systemd timer or Celery beat.
- **Type**: `enhance`
- **Status**: `open` — decided 2026-04-21 per user: two buttons
  (immediate + scheduled), both include the reboot in the same flow
- **Notes**: Observability exists — apt metadata lists available
  updates. Add two actions:
  1. **Update + Reboot now** — confirm dialog, `apt-get update &&
     apt-get -y upgrade`, on success `systemctl reboot`. Portal goes
     down for ~60s. Intended for impromptu windows ("can do it now").
  2. **Schedule Update + Reboot** — datetime picker + optional cron
     pattern for recurring. Persists to a scheduled_jobs-style table.
     Fires the same apt-update + reboot at the chosen time.
  Streaming apt output back to the page via SSE is nice-to-have. Both
  actions need `admin.system.update` permission (new). Audit every
  start + completion. Ordinary `apt upgrade` (no reboot) is still
  available via SSH for library-only security updates; the UI flow is
  specifically for kernel + init-affecting updates that need a reboot
  to take effect.

### Monitors — interval in minutes, not seconds
- **Where**: monitors form + watchlist display
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Keep DB storage as `interval_seconds` (Celery beat logic
  and sample timestamps shouldn't change). Change the form to a decimal
  **minutes** field (step 0.5) and display "every 5 min" in the
  watchlist row. Pydantic validator converts on the way in/out. The
  current min bound of 30 s → 0.5 min, max 60 min.
- **Where**: likely under Wizards or a new "Mail tools" category on DNS
  Tools (currently we have `dmarc.tuning` wizard; no standalone SPF /
  DKIM syntax checker)
- **Type**: `enhance`
- **Status**: `open`
- **Notes**: Users want parser-level validation, not just "record
  present". Scope:
  - **SPF**: tokenise the record, resolve `include:` / `redirect=`
    chains, flag >10 DNS-lookup limit, detect `+all`, `?all` foot-guns,
    show effective sender set.
  - **DKIM**: given selector + domain, fetch `<sel>._domainkey.<dom>`
    TXT, parse `v=DKIM1; k=rsa; p=…`, validate base64 key, show key
    bit-length, flag weak keys (<2048).
  - **DMARC**: extend the existing `dmarc.tuning` wizard to flag common
    syntax errors (`rua` without `mailto:`, bad `pct`, missing
    semicolons), not just policy stage.
  - Consider grouping under a **Mail Auth** category so they live next
    to `mail.delivery` and `mail.flow_validator` wizards.
- Audit list before implementing — `mail.delivery` + `mail.flow_validator`
  + `dmarc.tuning` may already cover part of this. Confirm gaps first.
