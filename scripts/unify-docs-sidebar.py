#!/usr/bin/env python3
"""
Replaces the `<aside class="sidebar" id="sidebar">…</aside>` block in every
non-index HTML page under docs/ with the canonical full sidebar that lists
all user/* and admin/* pages. Idempotent.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

SIDEBAR_RE = re.compile(r'<aside class="sidebar"[^>]*>.*?</aside>', re.DOTALL)

LOGO_SVG = ('<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" '
            'stroke-linecap="round" stroke-width="1.6">'
            '<circle cx="24" cy="24" r="19" opacity=".4"/>'
            '<ellipse cx="24" cy="24" rx="19" ry="5.5" opacity=".3"/>'
            '<ellipse cx="24" cy="24" rx="11" ry="19" opacity=".45" transform="rotate(22 24 24)"/>'
            '<ellipse cx="24" cy="24" rx="6" ry="19"/>'
            '<ellipse cx="24" cy="24" rx="3" ry="19" opacity=".6" transform="rotate(-38 24 24)"/>'
            '<line x1="24" y1="5" x2="24" y2="43" stroke-width="1.3"/>'
            '<circle cx="24" cy="5" r="2" fill="currentColor" stroke="none"/>'
            '<circle cx="24" cy="43" r="2" fill="currentColor" stroke="none"/>'
            '<circle cx="30" cy="7.2" r="1.2" fill="currentColor" stroke="none"/>'
            '<circle cx="24" cy="24" r="2.5" fill="currentColor" stroke="none"/>'
            '</svg>')


def sidebar_html(prefix: str) -> str:
    """Return the canonical sidebar with all links rewritten to use `prefix`
    (e.g. '../' for pages one level deep, './' for index.html)."""
    p = prefix
    return f'''<aside class="sidebar" id="sidebar">
  <a class="logo" href="{p}index.html">
    <div class="logo-mark">{LOGO_SVG}</div>
    <div><div class="logo-text">MERIDIAN</div><div class="logo-sub">DOCUMENTATION</div></div>
  </a>
  <input class="search" id="docs-search" placeholder="search docs…" spellcheck="false">

  <h3>Installation</h3>
  <a href="{p}installation/overview.html">Install overview</a>
  <a href="{p}installation/prompts.html">Installer prompts</a>
  <a href="{p}installation/luks.html">LUKS setup</a>

  <h3>User · tools</h3>
  <a href="{p}user/getting-started.html">Getting started</a>
  <a href="{p}user/dashboard.html">Dashboard</a>
  <a href="{p}user/dns-tools.html">DNS Tools</a>
  <a href="{p}user/network-tools.html">Network Tools</a>
  <a href="{p}user/monitors.html">Monitors</a>
  <a href="{p}user/wizards.html">Wizards</a>
  <a href="{p}user/certificates.html">Certificates</a>
  <a href="{p}user/runbooks.html">Runbooks</a>
  <a href="{p}user/dhcp.html">DHCP</a>
  <a href="{p}user/ipam.html">IPAM</a>
  <a href="{p}user/directory.html">Directory</a>
  <a href="{p}user/files.html">File Repo</a>
  <a href="{p}user/messages.html">Messages</a>
  <a href="{p}user/approvals.html">Approvals</a>
  <a href="{p}user/settings.html">User Settings</a>

  <h3>Admin</h3>
  <a href="{p}admin/overview.html">Admin overview</a>
  <a href="{p}admin/users.html">Users</a>
  <a href="{p}admin/scope.html">Scope Manager</a>
  <a href="{p}admin/integrations.html">Integrations</a>
  <a href="{p}admin/devices.html">Network Devices</a>
  <a href="{p}admin/vulnerabilities.html">Vulnerabilities</a>
  <a href="{p}admin/health.html">System Health</a>
  <a href="{p}admin/updates.html">Updates</a>
  <a href="{p}admin/webhooks.html">Webhooks</a>
  <a href="{p}admin/branding.html">Branding &amp; identity</a>
  <a href="{p}admin/security.html">Database security</a>
  <a href="{p}admin/scheduled-jobs.html">Scheduled jobs</a>
  <a href="{p}admin/backup-restore.html">Backup &amp; restore</a>

  <h3>Reference</h3>
  <a href="{p}reference/cli.html">meridian-nip CLI</a>

  <h3>Legal</h3>
  <a href="{p}legal/terms.html">Terms of use</a>
  <a href="{p}legal/aup-template.html">AUP template</a>
  <a href="{p}legal/oss.html">Open-source licenses</a>
</aside>'''


def process(fp: Path) -> str:
    rel = fp.relative_to(DOCS)
    if rel.parts[0] in ("assets", "css"):
        return "skip (asset)"
    prefix = "" if len(rel.parts) == 1 else "../"
    src = fp.read_text()
    if not SIDEBAR_RE.search(src):
        return "skip (no sidebar block)"
    new = SIDEBAR_RE.sub(sidebar_html(prefix), src, count=1)
    if new == src:
        return "skip (no change)"
    fp.write_text(new)
    return "updated"


def main() -> int:
    files = sorted(DOCS.rglob("*.html"))
    for fp in files:
        rel = fp.relative_to(DOCS)
        print(f"{str(rel):45s}  {process(fp)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
