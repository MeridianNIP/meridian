#!/usr/bin/env python3
"""One-shot generator for per-page documentation stubs.

Each portal page gets a matching doc file under docs/user/ or docs/admin/
with real content (not "TODO"): what the page is for, the key things on
it, common tasks, gotchas, and related links. Produces HTML using the
same layout as docs/user/getting-started.html.

Re-run whenever a new page lands — existing stubs are NOT overwritten
unless --force is passed, so your edits survive.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from textwrap import dedent


DOCS_ROOT = Path(__file__).resolve().parents[1] / "docs"


# -----------------------------------------------------------------------------
# Shared shell: header, sidebar, footer. Sidebar links every stub we produce.
# -----------------------------------------------------------------------------
def _sidebar_html(rel_prefix: str) -> str:
    """rel_prefix is "../" for user/admin pages (one level deep)."""
    def link(path: str, text: str) -> str:
        return f'<a href="{rel_prefix}{path}">{text}</a>'

    return dedent(f"""\
    <aside class="sidebar" id="sidebar">
      <a class="logo" href="{rel_prefix}index.html">
        <div class="logo-mark"></div>
        <div><div class="logo-text">MERIDIAN</div><div class="logo-sub">DOCUMENTATION</div></div>
      </a>
      <input class="search" id="docs-search" placeholder="search docs..." spellcheck="false">

      <h3>Installation</h3>
      {link('installation/overview.html', 'Install overview')}
      {link('installation/prompts.html', 'Installer prompts')}
      {link('installation/luks.html', 'LUKS setup')}

      <h3>User · tools</h3>
      {link('user/getting-started.html', 'Getting started')}
      {link('user/dashboard.html',       'Dashboard')}
      {link('user/dns-tools.html',       'DNS Tools')}
      {link('user/network-tools.html',   'Network Tools')}
      {link('user/monitors.html',        'Monitors')}
      {link('user/wizards.html',         'Wizards')}
      {link('user/certificates.html',    'Certificates')}
      {link('user/runbooks.html',        'Runbooks')}
      {link('user/dhcp.html',            'DHCP')}
      {link('user/ipam.html',            'IPAM')}
      {link('user/directory.html',       'Directory')}
      {link('user/files.html',           'File Repo')}
      {link('user/messages.html',        'Messages')}
      {link('user/approvals.html',       'Approvals')}
      {link('user/settings.html',        'User Settings')}

      <h3>Admin</h3>
      {link('admin/overview.html',       'Admin overview')}
      {link('admin/users.html',          'Users')}
      {link('admin/scope.html',          'Scope Manager')}
      {link('admin/integrations.html',   'Integrations')}
      {link('admin/devices.html',        'Network Devices')}
      {link('admin/vulnerabilities.html','Vulnerabilities')}
      {link('admin/health.html',         'System Health')}
      {link('admin/updates.html',        'Updates')}
      {link('admin/webhooks.html',       'Webhooks')}
      {link('admin/branding.html',       'Branding &amp; identity')}
      {link('admin/security.html',       'Database security')}
      {link('admin/scheduled-jobs.html', 'Scheduled jobs')}
      {link('admin/backup-restore.html', 'Backup &amp; restore')}

      <h3>Reference</h3>
      {link('reference/cli.html',        'meridian-nip CLI')}

      <h3>Legal</h3>
      {link('legal/aup-template.html',   'AUP template')}
      {link('legal/oss.html',            'Open-source licenses')}
    </aside>
    """)


def _render(title: str, crumb: str, subtitle: str, body: str,
            rel_prefix: str = "../") -> str:
    return dedent(f"""\
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} · Meridian Docs</title>
    <link rel="stylesheet" href="{rel_prefix}css/docs.css">
    </head>
    <body>
    <div class="grid-bg"></div>
    <div class="frame">
    {_sidebar_html(rel_prefix)}
    <main class="content">
    <div class="page-meta">{crumb}</div>
    <h1>{title}</h1>
    <div class="page-sub">{subtitle}</div>
    {body}
    </main>
    </div>
    </body>
    </html>
    """)


# -----------------------------------------------------------------------------
# Per-page content. The goal of each entry is "a user who opens this page
# cold can actually get something done" — not just restate the UI text.
# -----------------------------------------------------------------------------
PAGES: list[dict] = [
    # ---------------------------------------------------------------- user
    dict(path="user/dashboard.html", crumb="USER · DASHBOARD",
         title="Dashboard",
         subtitle="Your landing page: quick stats, pinned tools, recent audit, license state.",
         body="""
<h2>What you see</h2>
<ul>
<li><strong>Queries today</strong> — how many sandboxed DNS/network tool runs you've triggered since midnight UTC.</li>
<li><strong>Active sessions</strong> — how many devices are currently logged in as you. Manage them in Settings &rarr; Sessions.</li>
<li><strong>Recent alerts</strong> — monitor incidents opened against anything you own in the last 24 h.</li>
<li><strong>License</strong> — current tier and days remaining. Unlicensed shows here too.</li>
</ul>

<h2>Common tasks</h2>
<ol>
<li>Jump straight into a tool — click a tile in "Pinned tools".</li>
<li>Open your settings — click the user chip top-right, then "My profile".</li>
<li>Audit your own actions — scroll to "Recent audit" at the bottom of the page.</li>
</ol>

<h2>Gotchas</h2>
<ul>
<li>"Customize dashboard" currently points to <strong>My settings</strong>. Per-user dashboard widgets are on the roadmap.</li>
</ul>
"""),

    dict(path="user/dns-tools.html", crumb="USER · DNS TOOLS",
         title="DNS Tools",
         subtitle="Sandboxed DNS diagnostics: dig, propagation, DNSSEC, reverse, zone health, AXFR, CT/crt.sh, WHOIS, bulk WHOIS, typosquat, rndc flush.",
         body="""
<h2>The tabs, one sentence each</h2>
<ul>
<li><strong>Dig</strong> — single query against a chosen resolver, with the common flags exposed as clickable chips.</li>
<li><strong>Propagation</strong> — the same A/AAAA/MX/NS/TXT query against 16 public resolvers in parallel; highlights divergence.</li>
<li><strong>DNSSEC</strong> — walks the chain of trust (DNSKEY &rarr; DS at parent &rarr; root) and flags missing/weak links.</li>
<li><strong>Reverse</strong> — PTR lookup for an IP, optionally against a specific resolver.</li>
<li><strong>Zone Health</strong> — SOA agreement, lame-NS detection, MX/apex sanity.</li>
<li><strong>AXFR</strong> — tries a zone transfer against each authoritative NS. A refusal is the <em>expected</em> healthy answer.</li>
<li><strong>CT / crt.sh</strong> — certificate-transparency history for a domain (passive subdomain discovery).</li>
<li><strong>WHOIS</strong> — registrar, registrant, creation/expiry, name servers, DNSSEC flag, status codes.</li>
<li><strong>Bulk WHOIS</strong> — paste up to 200 domains; concurrency capped at 4 to avoid upstream rate-limits; export as CSV.</li>
<li><strong>Typosquat</strong> — homoglyph / omission / transposition / insertion / TLD-swap permutations, resolved in parallel.</li>
<li><strong>rndc flush</strong> (admin only) — flush the local BIND9 recursive cache, optionally targeted to one zone.</li>
</ul>

<h2>Deep-linkable</h2>
<p>Every tab is bookmarkable: <code>/ui/dns-tools#propagation</code>, <code>/ui/dns-tools#axfr</code>, etc. The URL hash updates as you click tabs.</p>

<h2>Scope guardrails</h2>
<p>Each target is checked against the <a href="../admin/scope.html">Scope Manager</a>. If your install is set to <code>internal</code>, queries against public IPs are rejected before they leave the host — and vice versa for <code>external</code>. If you need both, set scope to <code>both</code>.</p>

<h2>Gotchas</h2>
<ul>
<li><strong>AXFR that succeeds is a finding.</strong> The whole point is that most NSes <em>refuse</em> — a success means someone misconfigured their authoritative server.</li>
<li><strong>crt.sh 404 = no results.</strong> We render it as an empty table rather than an error.</li>
<li><strong>Propagation latency</strong> is dominated by the slowest resolver. Expect 3-8 seconds end-to-end.</li>
</ul>
"""),

    dict(path="user/network-tools.html", crumb="USER · NETWORK TOOLS",
         title="Network Tools",
         subtitle="Sandboxed reachability + performance: ping, traceroute, HTTP test, port scan, SNMP walk, packet capture, ASN lookup, BGP looking glass, IP reputation, geolocation, security-header audit, CVE lookup.",
         body="""
<h2>Reachability</h2>
<ul>
<li><strong>Ping</strong> — IPv4 or IPv6, configurable count, interval, timeout, packet size. Returns transmitted/received/loss % + RTT min/avg/max/jitter.</li>
<li><strong>Traceroute</strong> — renders hop-by-hop as a table with TTL, host/IP, and all RTT probes per hop.</li>
<li><strong>HTTP test</strong> — GET/HEAD/POST against a URL, follows redirects, shows the full request chain, response headers, and body preview.</li>
<li><strong>Port scan</strong> — nmap-backed, port-spec like <code>22,80,443</code> or <code>1-1024</code>. Concurrency capped at 256.</li>
<li><strong>SNMP walk</strong> — v1/v2c/v3, read-only. Pre-loaded MIBs from <code>snmp-mibs-downloader</code> when available.</li>
<li><strong>Packet capture</strong> — tcpdump with a BPF filter, duration-capped, auto-uploaded to File Repo on finish.</li>
</ul>

<h2>Research (no target reachability required)</h2>
<ul>
<li><strong>ASN lookup</strong> — Team Cymru whois-over-dig. IP &rarr; ASN + org + country + BGP prefix.</li>
<li><strong>BGP LG</strong> — RIPEstat-backed. IP &rarr; covering prefix + origin ASN(s); <code>AS&lt;n&gt;</code> &rarr; holder + country.</li>
<li><strong>IP reputation</strong> — 8 parallel DNSBL checks (Spamhaus, Barracuda, SpamCop, SORBS, CBL, PSBL, DroneBL, Lashback).</li>
<li><strong>Geolocation</strong> — ipapi.co free tier, rate-limited upstream.</li>
<li><strong>Header audit</strong> — HSTS / CSP / Frame-Options / XCTO / Referrer-Policy / Permissions-Policy / cookie flags with concrete fix recipes.</li>
<li><strong>CVE lookup</strong> — NVD API v2. Gives CVSS v3.1 vector, CWE chain, primary references, and cross-reference links to NVD, MITRE, GHSA, Debian, Ubuntu, Red Hat.</li>
</ul>

<h2>Gotchas</h2>
<ul>
<li><strong>Port scan on hostile networks</strong> can be disruptive. Scope Manager prevents scanning production ranges unless explicitly allowed.</li>
<li><strong>Packet capture</strong> needs <code>cap_net_raw</code> on tcpdump (set automatically by <code>install.sh</code>). If pcap errors with "permission denied", check AppArmor profile.</li>
<li><strong>Geolocation</strong> is ipapi.co; if you expect thousands of queries, swap in MaxMind GeoLite2 locally.</li>
</ul>
"""),

    dict(path="user/monitors.html", crumb="USER · MONITORS",
         title="Monitors",
         subtitle="HTTP/HTTPS · TCP port · ICMP ping · cert-expiry · DNS-record monitors, sampled in the background.",
         body="""
<h2>Creating a monitor</h2>
<p>Fill in <strong>Name</strong>, <strong>Kind</strong>, <strong>Target</strong>, <strong>Interval</strong> (&ge; 30 s), and <strong>Timeout</strong>. The background scheduler (<code>meridian-beat</code>) picks it up within one beat tick (&sim; 60 s) and starts sampling.</p>

<h2>Kinds</h2>
<ul>
<li><code>https</code> / <code>http</code> — HEAD by default, 2xx/3xx = OK, timeout/5xx = down, cert errors trigger cert-specific notifications.</li>
<li><code>port_tcp</code> — bare TCP connect. Use for things like SMB/SSH/databases where you just want to know the port answers.</li>
<li><code>ping_icmp</code> — ICMP echo. Requires the host to respond; many cloud providers block it.</li>
<li><code>cert_expiry</code> — pulls the cert and alerts at 30/14/7-day thresholds.</li>
<li><code>dns_record</code> — checks that a record resolves to a specific expected value.</li>
</ul>

<h2>Editing + deleting</h2>
<p>Each row has <strong>Edit</strong> (inline form pre-populated with current values), <strong>Disable/Enable</strong>, and <strong>Delete</strong>. Deleting a monitor removes its samples and incident history too.</p>

<h2>Notifications</h2>
<p>Monitors dispatch <code>monitor.incident.opened</code> on state change to bad, and <code>monitor.incident.closed</code> on recovery. Attach <a href="../admin/integrations.html">notification channels</a> in Admin &rarr; Integrations &rarr; Notifications.</p>

<h2>Gotchas</h2>
<ul>
<li><strong>HTTPS against an IP</strong> (not a hostname) will fail TLS hostname verification. Use the hostname or set kind = <code>port_tcp</code>.</li>
<li><strong>Interval &lt; 30 s</strong> is rejected — beat runs per minute, so anything tighter is wishful thinking.</li>
<li><strong>Consecutive-fails</strong> is what triggers an alert, not a single sample — defaults to 2.</li>
</ul>
"""),

    dict(path="user/wizards.html", crumb="USER · WIZARDS",
         title="Wizards",
         subtitle="Guided, multi-step diagnostics. Each step explains what it checked and suggests evidence-backed next steps.",
         body="""
<h2>When to use a wizard vs a tool</h2>
<p>Use a <strong>tool</strong> when you know exactly what you want to check (e.g. "dig the AAAA for this host"). Use a <strong>wizard</strong> when you have a symptom and want the portal to walk through the usual chain.</p>

<h2>Wizard catalog</h2>
<ul>
<li><code>dns.resolve_fail</code> — "Why isn't my domain resolving?". Checks delegation, SOA consistency, propagation, DNSSEC.</li>
<li><code>zone.health</code> — formalizes the zone-health tool as a guided report.</li>
<li><code>axfr.audit</code> — tries AXFR against every authoritative NS and flags any that succeed.</li>
<li><code>dnssec.chain</code> — end-to-end chain-of-trust walk with DS/DNSKEY validation per label.</li>
<li><code>dmarc.tuning</code> — pulls the SPF/DKIM/DMARC records and rates the policy.</li>
<li><code>mail.delivery</code> + <code>mail.flow_validator</code> — "why is my mail bouncing?" and "is this domain configured to send?".</li>
<li><code>registrar.mismatch</code> — compares registrar WHOIS NS set against the zone's actual NS records.</li>
<li><code>ssl.deep_inspect</code> — full TLS audit: chain, hostname, expiry, cipher set, cert key type, issuer, self-signed check.</li>
<li><code>cloudflare.validator</code> — detects Cloudflare in front of a domain and checks proxying/origin coverage.</li>
<li><code>typosquat.sweep</code> — permutation generation + resolution check.</li>
<li><code>network.reachability</code> — ping/trace/port sweep bundled into a single report.</li>
<li><code>network.up_for_everyone</code> — DNS + HTTP from multiple public resolvers to distinguish "broken for me" from "broken globally".</li>
<li><code>ip.reputation</code> — DNSBL check + ASN/prefix context.</li>
<li><code>domain.bringup</code> — checklist for a brand-new domain about to go live.</li>
<li><code>infoblox.drift</code> — compares Infoblox DHCP/IPAM records against live DNS.</li>
</ul>

<h2>How to read the output</h2>
<p>Each step is one of <strong>ok</strong> / <strong>info</strong> / <strong>warn</strong> / <strong>fail</strong>. The badge color matches. Below the steps, the wizard ranks suggested next actions by priority (<code>critical</code> / <code>recommended</code> / <code>suggested</code> / <code>info</code>), each with a one-click deeplink to the relevant tool or admin page.</p>

<h2>Gotchas</h2>
<ul>
<li>DNS propagation fans out to 16 public resolvers. A wizard run that uses it will take 5-10 s — the "running..." state is normal.</li>
<li>Wizard runs are recorded in <code>wizard_runs</code>. You can see your recent ones under Admin &rarr; Audit.</li>
</ul>
"""),

    dict(path="user/certificates.html", crumb="USER · CERTIFICATES",
         title="Certificates",
         subtitle="Portal's own TLS certificate, external watchlist, and CSR generation.",
         body="""
<h2>Three sections on this page</h2>
<ol>
<li><strong>Portal cert</strong> — the cert Nginx presents. Shows issuer, SANs, expiry, renewal method (Let's Encrypt / Cloudflare Origin / self-signed).</li>
<li><strong>Watchlist</strong> — external certs you want monitored. Each entry is polled on the schedule in <em>Admin &rarr; Updates</em>; alerts fire at 30/14/7 days remaining.</li>
<li><strong>CSR generator</strong> — produces a private key + certificate signing request you can hand to a CA. Supported key types: <code>ecdsa_p256</code>, <code>ecdsa_p384</code>, <code>rsa2048</code>, <code>rsa3072</code>, <code>rsa4096</code>, <code>ed25519</code>.</li>
</ol>

<h2>Watchlist entries</h2>
<p>Add a host + port, optionally a friendly label. Meridian opens a TLS connection, pulls the leaf cert, stores its fingerprint, issuer, and expiry. On refresh it re-pulls and flags a <strong>fingerprint changed</strong> banner when the cert has rotated (useful for detecting unannounced deploys).</p>

<h2>Gotchas</h2>
<ul>
<li>Self-signed portals show <code>"no letsencrypt cert (self-signed portal?)"</code> in System Health — that's an informational warn, not a failure.</li>
<li>CSR generation is local-only; the private key is stored in the vault (AES-256-GCM). Download the PEM once — you can't re-export it later.</li>
</ul>
"""),

    dict(path="user/runbooks.html", crumb="USER · RUNBOOKS",
         title="Runbooks",
         subtitle="Chain tools into repeatable workflows with per-step permission gating and continue_on logic.",
         body="""
<h2>Anatomy of a runbook</h2>
<p>A runbook is an ordered list of steps. Each step picks a <strong>tool</strong> from the catalog (DNS tools, network tools, integrations) and binds its parameters. At run time Meridian:</p>
<ol>
<li>Checks the invoking user holds the tool's <code>required_permission</code>. Skips any step the user cannot run (recorded in the run log as "skipped").</li>
<li>Executes the step. Captures output, exit status, duration.</li>
<li>Applies <strong>continue_on</strong>: if the step's outcome is worse than the configured threshold (e.g. <code>continue_on = "ok"</code> stops at first warn/fail), the runbook short-circuits.</li>
</ol>

<h2>Shared vs private</h2>
<p>A private runbook is only visible to its owner. A shared runbook is visible and runnable by anyone with the component permissions. Only admins can toggle the shared flag on someone else's runbook.</p>

<h2>Common patterns</h2>
<ul>
<li><strong>Incident triage</strong> — ping the host, HTTP test the app, dig the DNS, check cert expiry. Stop on first warn for a fast answer.</li>
<li><strong>New-domain checklist</strong> — dig NS/SOA/MX/TXT, AXFR audit, DNSSEC chain, crt.sh history, WHOIS. Always run all.</li>
<li><strong>Pre-deploy sanity</strong> — port scan the target, HTTP 200 check, cert expiry check.</li>
</ul>

<h2>Gotchas</h2>
<ul>
<li>You can't run a runbook until it has been saved. The <strong>Run</strong> button shows a warning until you do.</li>
<li>Run history lives in the <code>runbook_runs</code> table. You can review prior step-by-step output at any time.</li>
</ul>
"""),

    dict(path="user/dhcp.html", crumb="USER · DHCP",
         title="DHCP Intelligence",
         subtitle="Unified query across external DHCP backends. This portal does not run a DHCP server; it reads from your existing systems.",
         body="""
<h2>Supported backends</h2>
<ul>
<li>Infoblox Grid</li>
<li>Infoblox CSP</li>
<li>ISC Kea (via its REST API)</li>
<li>Microsoft DHCP (via WMI/PowerShell bridge)</li>
<li>Generic REST (adapter per-source)</li>
</ul>
<p>Configure connections under <a href="../admin/integrations.html">Admin &rarr; Integrations &rarr; DHCP sources</a>. Credentials are AES-256-GCM encrypted in the vault.</p>

<h2>What you can do</h2>
<ul>
<li>Look up a lease by IP, MAC, or hostname across every configured source.</li>
<li>Scope utilization: current lease count / pool size per scope, rate of change.</li>
<li>Exhaustion warnings: scopes over 80 % get flagged in <a href="dashboard.html">Dashboard &rarr; Recent alerts</a>.</li>
</ul>

<h2>Gotchas</h2>
<ul>
<li>Queries fan out to all configured backends in parallel. Rate limiting on Infoblox's WAPI is a common cause of stalls — tune the integration's request budget.</li>
<li>Historical leases depend on the backend's retention. ISC Kea's default is aggressive; Infoblox keeps weeks.</li>
</ul>
"""),

    dict(path="user/ipam.html", crumb="USER · IPAM",
         title="IPAM Intelligence",
         subtitle="Unified query across external IPAM systems. This portal reads from Infoblox, NetBox, phpIPAM, BlueCat; it does not author records itself.",
         body="""
<h2>Supported backends</h2>
<ul>
<li>Infoblox Grid</li>
<li>Infoblox CSP</li>
<li>NetBox</li>
<li>phpIPAM</li>
<li>BlueCat</li>
<li>Spreadsheet (CSV / Google Sheets / Excel) for teams without a real IPAM</li>
</ul>
<p>Configure under <a href="../admin/integrations.html">Admin &rarr; Integrations &rarr; IPAM sources</a>.</p>

<h2>What you can do</h2>
<ul>
<li>Where is <code>10.1.2.0/24</code> allocated? — searches every source and merges results.</li>
<li>What subnets contain <code>10.1.2.42</code>? — reverse lookup through nested supernets.</li>
<li>Compare live subnet sweep vs IPAM records to find drift (addresses in use that IPAM doesn't know about, or IPAM entries for dead hosts).</li>
</ul>

<h2>Gotchas</h2>
<ul>
<li>Different backends name fields differently. The portal normalizes to a common shape — the <strong>Detail</strong> link on each result takes you to the canonical entry in the source of truth.</li>
<li>Spreadsheet backends are case-sensitive on column headers. Use <code>network</code>, <code>description</code>, <code>tags</code>.</li>
</ul>
"""),

    dict(path="user/directory.html", crumb="USER · DIRECTORY",
         title="Directory",
         subtitle="Active Directory / LDAP / Entra ID lookups. Read-only by default; write actions require the approval workflow.",
         body="""
<h2>User search</h2>
<p>Free-text search: sAMAccountName, UPN, display name, email. Returns group memberships, last-logon, account state (enabled / locked / password-expired / inactive-90d).</p>

<h2>Group search</h2>
<p>Group name &rarr; nested members, computed transitively. Useful for "who has X permission" audits.</p>

<h2>Stale-account report</h2>
<p>Scheduled job <code>stale-ad-report</code> (weekly) lists accounts inactive &gt; 90 days. Landing zone: <em>Admin &rarr; Users &rarr; AD drift</em>.</p>

<h2>Gotchas</h2>
<ul>
<li><strong>Write actions</strong> (disable user, reset password, add to group) require a second admin to approve. See <a href="approvals.html">Approvals</a>.</li>
<li>Entra ID uses Microsoft Graph; permission scope on the app registration must include <code>Directory.Read.All</code> at minimum.</li>
</ul>
"""),

    dict(path="user/files.html", crumb="USER · FILES",
         title="File Repo",
         subtitle="Per-user file storage. Scripts, pcaps, exports, docs. Quota-enforced; pinned files skip retention.",
         body="""
<h2>Quotas</h2>
<ul>
<li>Soft cap (default 500 MB): warnings in the UI, no writes blocked.</li>
<li>Hard cap (default 1 GB): writes blocked, 413.</li>
</ul>

<h2>Upload rules</h2>
<ul>
<li>Files are sniffed for magic bytes; mime mismatch rejected.</li>
<li>Executable extensions (.exe, .com, .bat, .msi, .scr, .ps1, .vbs, .js, .hta, .sh, .app, .dmg, .pkg, .jar, etc.) are blocked server-side with a 415.</li>
<li>SVG uploads are sanitized: <code>&lt;script&gt;</code> and event handlers stripped.</li>
</ul>

<h2>Pinning</h2>
<p>Pinned files are exempt from the retention cleanup job (<code>file-repo-quota</code>). Use pinning for long-lived references; clear the pin when you no longer need them — they still count against quota.</p>

<h2>Gotchas</h2>
<ul>
<li>Each file row shows the uploader and a SHA-256 fingerprint; you can prove to an auditor exactly what was stored.</li>
<li>Downloading a pcap from a packet capture is the same flow — pcaps land in File Repo automatically.</li>
</ul>
"""),

    dict(path="user/messages.html", crumb="USER · MESSAGES",
         title="Messages",
         subtitle="Direct messages between users · admin broadcasts · group-addressed notices.",
         body="""
<h2>Three channels</h2>
<ul>
<li><strong>Direct</strong> — one user &rarr; one user. Targets by username.</li>
<li><strong>Group</strong> — one user &rarr; every member of a group.</li>
<li><strong>Broadcast</strong> — admin only. Goes to every logged-in user.</li>
</ul>

<h2>Inbox behavior</h2>
<ul>
<li>Polls every 20 s while the tab is visible so new messages appear without refresh.</li>
<li>Unread messages are visually highlighted and count toward the nav badge.</li>
<li>Click any message to mark it read; "Mark all read" clears the unread set.</li>
</ul>

<h2>Deleting</h2>
<p>Only the original sender or an admin can delete a message. The <strong>&times;</strong> button next to the timestamp triggers delete; a 403 is returned (with explanation) if you're neither.</p>
"""),

    dict(path="user/approvals.html", crumb="USER · APPROVALS",
         title="Approvals",
         subtitle="Two-person sign-off for destructive or sensitive operations.",
         body="""
<h2>What goes through approvals</h2>
<p>Any admin operation tagged <code>requires_approval</code> — AD user disable, bulk DNS changes, runbook steps against production scopes, integration credential rotation, etc.</p>

<h2>Workflow</h2>
<ol>
<li>User A requests an approval: action name, target key, justification.</li>
<li>User B (different user, with <code>approvals.approve</code> permission) reviews + approves or denies.</li>
<li>User A has a limited window (default 60 min) to actually execute the action. Past the window, approval expires and must be re-requested.</li>
<li>Execution records both user IDs in the audit row.</li>
</ol>

<h2>Gotchas</h2>
<ul>
<li>You cannot approve your own request. Attempting to do so returns 403.</li>
<li>Denied approvals are kept for audit history; re-request if legitimate.</li>
</ul>
"""),

    dict(path="user/settings.html", crumb="USER · SETTINGS",
         title="User Settings",
         subtitle="Profile, sessions, password, MFA, account recovery, API tokens.",
         body="""
<h2>Tabs</h2>
<ul>
<li><strong>Profile</strong> — display name, timezone, phone (for SMS), SMS carrier gateway, idle-timeout override.</li>
<li><strong>Sessions</strong> — every device currently logged in as you; revoke individually or "revoke all others".</li>
<li><strong>Password</strong> — self-service password change. Requires current password; new must be &ge; 12 chars.</li>
<li><strong>Two-factor auth</strong> — TOTP enrollment (Google/Microsoft/Authy/Symantec VIP/etc). QR + secret + backup codes shown once.</li>
<li><strong>Account recovery</strong> — set 5 security questions; forgot-password prompts 3 of 5 randomly.</li>
<li><strong>API tokens</strong> — issue bearer tokens for scripts/CI with scoped permissions and rate limits.</li>
</ul>

<h2>Deep-linking</h2>
<p>Each tab has a stable hash URL — share them with a teammate or bookmark: <code>/ui/settings#profile</code>, <code>/ui/settings#mfa</code>, <code>/ui/settings#recovery</code>, etc.</p>

<h2>Gotchas</h2>
<ul>
<li><strong>Backup codes are shown once.</strong> Save them immediately when you enroll MFA; they are not persisted in a recoverable form.</li>
<li><strong>API tokens bypass MFA + idle timeout by design</strong> — that's what lets them work from unattended scripts. Scope them tightly.</li>
<li>Changing your password revokes all other active sessions as a security precaution.</li>
</ul>
"""),

    # --------------------------------------------------------------- admin
    dict(path="admin/overview.html", crumb="ADMIN · OVERVIEW",
         title="Admin overview",
         subtitle="System health, scheduled jobs, license, audit. Write operations require two-person approval.",
         body="""
<h2>What lives on the overview page</h2>
<ul>
<li><strong>Services</strong> — live systemd status of postgresql, nginx, bind9/named, valkey/redis, meridian-app/celery/beat, fail2ban. Only services present on this host are shown.</li>
<li><strong>Scheduled jobs</strong> — cron-style list from the <code>jobs</code> table with last-run status + next-run time.</li>
<li><strong>License</strong> — current tier + expiry. Unlicensed banner appears here and in the top bar.</li>
<li><strong>Recent audit</strong> — last 50 audit events across every user.</li>
</ul>

<h2>Navigating between admin sections</h2>
<p>Each admin sub-page has a tab row at the top: Users, Scope Manager, Integrations, Network Devices, Vulnerabilities, System Health, Updates, Webhooks, Branding. These are full-page links, not hash tabs.</p>

<h2>Gotchas</h2>
<ul>
<li>"Recent audit" pulls from <code>audit_events</code>, which has a row-hash chain. If a row fails integrity (see <a href="health.html">System Health &rarr; Integrity</a>), that row is flagged but kept.</li>
</ul>
"""),

    dict(path="admin/users.html", crumb="ADMIN · USERS",
         title="Users",
         subtitle="Create, enable, lock, reset. Every change audit-logged into the HMAC chain.",
         body="""
<h2>What you can do</h2>
<ul>
<li><strong>Create</strong> — username, email, role (<code>viewer</code>/<code>analyst</code>/<code>admin</code>/<code>super_admin</code>), temp password auto-generated. User must change on first login.</li>
<li><strong>Enable / Disable</strong> — toggles <code>users.enabled</code>. A disabled user's sessions are revoked.</li>
<li><strong>Lock / Unlock</strong> — <code>users.locked</code>. Locked accounts can't log in; fail2ban flips this automatically on brute force.</li>
<li><strong>Reset password</strong> — admin-driven reset. User gets a temp password + forced change at next login.</li>
</ul>

<h2>Roles</h2>
<ul>
<li><code>viewer</code> — read access to dashboards, monitors, directory lookups. No tool runs.</li>
<li><code>analyst</code> — tool runs, runbooks, monitor creation. No admin access.</li>
<li><code>admin</code> — add to above: integrations, scope, webhooks, branding, vuln management, updates.</li>
<li><code>super_admin</code> — add to above: users, system-level repairs, licensing, sensitive audit queries.</li>
</ul>

<h2>Gotchas</h2>
<ul>
<li>You cannot disable your own account. Super admins must demote themselves first by handing the role to another super admin.</li>
<li>Deleting a user is soft (<code>deleted_at</code> is set). Audit rows remain to preserve history.</li>
</ul>
"""),

    dict(path="admin/scope.html", crumb="ADMIN · SCOPE MANAGER",
         title="Scope Manager",
         subtitle="Override which networks count as internal/external, plus a hard deny list. Applies to every probe.",
         body="""
<h2>Default scope</h2>
<p>Set at install: <code>internal</code>, <code>external</code>, or <code>both</code>. Meridian uses it to prevent accidentally scanning a public address from an internal-only deployment (or vice versa).</p>

<h2>Per-network overrides</h2>
<ul>
<li>Add a CIDR + label. Example: <code>10.0.0.0/8</code> &rarr; <strong>internal</strong>; <code>203.0.113.0/24</code> &rarr; <strong>external</strong>.</li>
<li>Overlapping rules: most-specific prefix wins.</li>
</ul>

<h2>Deny list</h2>
<p>A second layer: CIDRs that are <em>always</em> rejected regardless of scope. Use for things you should never probe — link-local, cloud metadata endpoints (<code>169.254.169.254</code>), broadcast addresses, your own management VLAN.</p>

<h2>What enforces this</h2>
<p>Every tool in <a href="../user/network-tools.html">Network Tools</a> and <a href="../user/dns-tools.html">DNS Tools</a> calls <code>enforce_scope(host, scope)</code> before invoking the sandbox. Bypassing it requires code changes — not a config.</p>

<h2>Gotchas</h2>
<ul>
<li>Changing your install's default scope from <code>internal</code> to <code>both</code> is a policy change worth advertising to users — internal-tooling expectations may have developed.</li>
</ul>
"""),

    dict(path="admin/integrations.html", crumb="ADMIN · INTEGRATIONS",
         title="Integrations",
         subtitle="Configure DHCP / IPAM / Directory / Notifications backends. All secrets AES-256-GCM encrypted in the vault.",
         body="""
<h2>Four subtabs</h2>
<ul>
<li><strong>DHCP sources</strong> — Infoblox Grid, Infoblox CSP, ISC Kea, Microsoft DHCP, generic REST. Per-source credentials; validated on save.</li>
<li><strong>IPAM sources</strong> — Infoblox Grid, Infoblox CSP, NetBox, phpIPAM, BlueCat, spreadsheet.</li>
<li><strong>Directory</strong> — AD (LDAP bind), Entra ID (Microsoft Graph), generic LDAP. Read-only by default; write actions require approval.</li>
<li><strong>Notifications</strong> — email (SMTP), Slack / Teams incoming webhooks, generic HTTP webhook, PagerDuty Events v2, Twilio SMS, SMS-over-email gateway, in-app only. Kind-specific help shown inline.</li>
</ul>

<h2>Secrets</h2>
<p>API keys, passwords, bind credentials never appear in plaintext in the UI after save. They are written to the <code>secrets</code> vault with a domain-separated AES-256-GCM key derived from the master key.</p>

<h2>Test before enabling</h2>
<p>Each row has a <strong>Test</strong> button that makes a real probe call against the endpoint. Failures explain what went wrong (auth, DNS, connection, TLS).</p>
"""),

    dict(path="admin/devices.html", crumb="ADMIN · NETWORK DEVICES",
         title="Network Devices",
         subtitle="SSH-based config backup with change detection. Snapshots written only when the SHA-256 differs from the last.",
         body="""
<h2>Adding a device</h2>
<p>Hostname/IP, SSH port, credential (username + password or SSH key from the vault), platform (<code>ios</code>, <code>nxos</code>, <code>junos</code>, <code>eos</code>, <code>procurve</code>, <code>linux</code>). Optionally tags for grouping.</p>

<h2>Backup job</h2>
<p>Scheduled (<code>device-config-backup</code>, daily by default). For each device, connects over SSH, runs the platform-specific "show running" command, hashes the output. If the hash matches the previous snapshot, no new record is written — cosmetic refreshes do not pollute history.</p>

<h2>Retention</h2>
<p><code>device-retention</code> trims snapshots per <code>retention_rules.scope = device_snapshots</code>. Defaults to 12 months.</p>

<h2>Gotchas</h2>
<ul>
<li>Passwordless SSH keys are strongly preferred. Password auth works but triggers <code>sshpass</code> under the hood with a ProcessArgs env var that is wiped immediately.</li>
<li>Interactive prompts (MOTD, "accept new host key?") are handled via <code>StrictHostKeyChecking=accept-new</code> on first connect, then strict afterward.</li>
</ul>
"""),

    dict(path="admin/vulnerabilities.html", crumb="ADMIN · VULNERABILITIES",
         title="Vulnerabilities",
         subtitle="OSV.dev + NVD scan of installed apt + pip components. Bulk-suppress / open advisories.",
         body="""
<h2>How the scan runs</h2>
<p>Nightly (<code>vuln-scan</code> job). Enumerates <code>dpkg -l</code> + <code>pip freeze</code>, queries OSV.dev for known vulnerabilities per package+version, cross-references CVEs against NVD for CVSS.</p>

<h2>Finding statuses</h2>
<ul>
<li><code>open</code> — newly detected, not yet triaged.</li>
<li><code>fixed</code> — the scan no longer detects this package+version combination.</li>
<li><code>suppressed</code> — admin-dismissed ("known, accepted").</li>
<li><code>accepted_risk</code> — formally accepted with a required note.</li>
<li><code>false_positive</code> — reported but doesn't apply (e.g. feature not used).</li>
</ul>

<h2>Bulk actions</h2>
<p>Multi-select via checkbox; <strong>Suppress</strong>, <strong>Accept risk</strong>, <strong>Mark false positive</strong> apply to all selected. Required note is captured and audit-logged.</p>

<h2>Cross-references</h2>
<p>Each finding links to the primary sources: NVD, MITRE CVE, Debian security tracker, Ubuntu security, GitHub Security Advisories. For the manual-lookup case (researching a CVE from a vendor advisory), see the <a href="../user/network-tools.html">Network Tools &rarr; CVE lookup</a> tool.</p>
"""),

    dict(path="admin/health.html", crumb="ADMIN · SYSTEM HEALTH",
         title="System Health",
         subtitle="Live self-check of services, DB, keys, cert, disk, memory, integrity chain. Repair actions audited.",
         body="""
<h2>Checks</h2>
<p>Each row is <code>ok</code> / <code>warn</code> / <code>fail</code>. Warn and fail rows show a <strong>Repair</strong> button (when a remediation exists) and an <strong>Open &rarr;</strong> link to the admin page that owns the category.</p>

<h2>Categories</h2>
<ul>
<li><strong>service</strong> — systemd <code>is-active</code>. Non-existent units on this host are hidden, not failed.</li>
<li><strong>db</strong> — simple <code>SELECT 1</code>; also flags when the row-hash chain of <code>audit_events</code> is broken.</li>
<li><strong>resource</strong> — disk %, memory %. Warns at 85 %, fails at 95 %.</li>
<li><strong>cert</strong> — portal TLS cert presence + expiry.</li>
<li><strong>key</strong> — master key + row-HMAC key file perms (0400 mandatory).</li>
<li><strong>integrity</strong> — last <code>db-integrity-scan</code> job result and age.</li>
</ul>

<h2>Repair actions</h2>
<p>One-click repairs include restarting a stopped service, running a one-off integrity rescan, running a retention pass, attempting <code>rndc reload</code>, and <code>certbot renew</code>. Each is audit-logged with action + outcome + detail.</p>

<h2>Gotchas</h2>
<ul>
<li><strong>Destructive</strong> repairs (disabling a service) require two-person approval.</li>
<li>If <code>cert:renew</code> errors with "no Let's Encrypt certs registered", this install is using self-signed / Cloudflare origin certs — the repair is a no-op.</li>
</ul>
"""),

    dict(path="admin/updates.html", crumb="ADMIN · UPDATES",
         title="Updates",
         subtitle="Pending apt updates, pinned version manifest, drift, snapshot + history. Apply is a CLI-only operation.",
         body="""
<h2>Why apply isn't a button</h2>
<p>Silent auto-upgrades are explicitly not a feature. <code>meridian-nip upgrade</code> is a supervised CLI command that takes a snapshot first and refuses to proceed if any preflight check fails. The portal helps you <em>prepare</em> an upgrade; it does not perform one.</p>

<h2>Tabs</h2>
<ul>
<li><strong>Pending</strong> — live <code>apt list --upgradable</code>. Security updates highlighted.</li>
<li><strong>Drift</strong> — installed versions vs <code>version_manifest</code>. Warn / block severities — blocks are where the installed version is outside the pinned min/max range and may break the app.</li>
<li><strong>Snapshots</strong> — pg_dump + config tarballs from prior <code>pre-update-snapshot</code> job runs.</li>
<li><strong>Manifest</strong> — the pinned version table for this release.</li>
<li><strong>History</strong> — apt + manifest changes, timestamps, notes.</li>
</ul>

<h2>Rescan button</h2>
<p>Runs <code>apt-get update -qq</code> + reloads the summary. On a host with fresh mirrors this is &lt; 1 s. The button shows a toast so you know it ran even when nothing changed.</p>
"""),

    dict(path="admin/webhooks.html", crumb="ADMIN · WEBHOOKS",
         title="Webhooks",
         subtitle="HMAC-signed inbound receivers + outbound fan-out. Signing secrets shown exactly once.",
         body="""
<h2>Outbound</h2>
<p>Push Meridian events (monitor.incident.opened, runbook.run.completed, user.login.failed, etc.) into external systems. Receivers verify the <code>X-Meridian-Signature</code> HMAC-SHA256 over the raw body. Per-webhook event subscription is a chip row on the create form.</p>

<h2>Inbound</h2>
<p>Accept signed POSTs from external systems and route them into a handler. Useful for ingesting service-registry events, CI pipeline completions, or SIEM alerts. Each receiver has its own URL + secret; unsigned calls are rejected with 401.</p>

<h2>Event catalog</h2>
<p>The <strong>Events</strong> tab lists every event kind Meridian can emit, with a schema snippet per event. Use it to decide which events to subscribe to.</p>

<h2>Gotchas</h2>
<ul>
<li><strong>Secrets are shown once.</strong> Copy on creation; we store only the hash. Rotate = new secret, old one becomes immediately invalid.</li>
<li>Verifying the signature on the receiver side is mandatory; anything less defeats the point.</li>
</ul>
"""),

    dict(path="admin/branding.html", crumb="ADMIN · BRANDING",
         title="Branding &amp; identity",
         subtitle="Customer-level personalization applied site-wide. Logos, favicon, theme, legal text, outbound sender identity, license.",
         body="""
<h2>Assets</h2>
<ul>
<li>Logo, favicon, login background, PDF report header. Each is magic-byte-sniffed and SVGs are stripped of scripts.</li>
<li>Favicon preset picker: 5 bundled inline-SVG icons (shield / globe / network / radar / lock) for operators who don't have their own.</li>
</ul>

<h2>Legal</h2>
<p>Pre-login warning banner (legal-notice text shown above login), login banner text, AUP (acceptable use policy) body, AUP-require-first-login toggle, AUP re-prompt on change.</p>

<h2>Outbound communications</h2>
<p>Sender <em>identity</em> only — email from-name + from-address, email signature, Slack/Teams sender name, SMS sender identity, PDF report footer. Transport configuration (SMTP host, Slack webhook, etc.) lives in <a href="integrations.html">Integrations &rarr; Notifications</a>.</p>

<h2>License</h2>
<p>Paste-in box for <code>MRD-...</code> / <code>TRIAL-...</code> tokens. Validates offline (Ed25519) using the baked-in vendor public key. See <a href="licensing.html">Licensing</a> for how tokens are issued.</p>
"""),
]


# -----------------------------------------------------------------------------
# Driver.
# -----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--force", action="store_true",
                    help="overwrite existing stubs (default: skip)")
    args = ap.parse_args()

    wrote = 0
    skipped = 0
    for page in PAGES:
        out = DOCS_ROOT / page["path"]
        if out.exists() and not args.force:
            print(f"skip (exists)   : {page['path']}")
            skipped += 1
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        html = _render(
            title=page["title"],
            crumb=page["crumb"],
            subtitle=page["subtitle"],
            body=page["body"].strip(),
            rel_prefix="../",
        )
        out.write_text(html, encoding="utf-8")
        print(f"wrote           : {page['path']}")
        wrote += 1

    print()
    print(f"done: {wrote} written, {skipped} skipped (pass --force to overwrite)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
