#!/usr/bin/env python3
"""
Ensure every portal template has the `_page_docs_link.html` include sitting
as the **last direct child** of its `<div class="page-head">` container.

Strategy:
  1. Strip any existing `{% with docs_path=... %}{% include ... %}{% endwith %}`
     line from the template (wherever it landed previously).
  2. Locate `<div class="page-head">`, walk `<div>` / `</div>` depth to find
     its matching close, and insert the include immediately before it.

Idempotent.
"""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "app" / "templates"

MAPPING = {
    "dashboard.html":          "user/dashboard.html",
    "dns_tools.html":          "user/dns-tools.html",
    "network_tools.html":      "user/network-tools.html",
    "monitors.html":           "user/monitors.html",
    "wizards.html":            "user/wizards.html",
    "certificates.html":       "user/certificates.html",
    "runbooks.html":           "user/runbooks.html",
    "dhcp.html":               "user/dhcp.html",
    "ipam.html":               "user/ipam.html",
    "directory.html":          "user/directory.html",
    "files.html":              "user/files.html",
    "messages.html":           "user/messages.html",
    "approvals.html":          "user/approvals.html",
    "settings.html":           "user/settings.html",
    "admin.html":              "admin/overview.html",
    "admin_users.html":        "admin/users.html",
    "admin_scope.html":        "admin/scope.html",
    "admin_integrations.html": "admin/integrations.html",
    "admin_devices.html":      "admin/devices.html",
    "admin_vuln.html":         "admin/vulnerabilities.html",
    "admin_health.html":       "admin/health.html",
    "admin_updates.html":      "admin/updates.html",
    "admin_webhooks.html":     "admin/webhooks.html",
    "admin_branding.html":     "admin/branding.html",
}

# Matches an entire include line (with optional surrounding whitespace + newline).
INCLUDE_LINE_RE = re.compile(
    r'^[ \t]*\{%\s*with\s+docs_path="[^"]+"\s*%\}\{%\s*include\s+"_page_docs_link\.html"\s*%\}\{%\s*endwith\s*%\}[ \t]*\r?\n',
    re.MULTILINE,
)

PAGE_HEAD_OPEN_RE = re.compile(r'<div class="page-head">')
DIV_OPEN_RE       = re.compile(r'<div\b')
DIV_CLOSE_RE      = re.compile(r'</div>')


def find_page_head_close(src: str, open_start: int) -> int:
    """Given the position *after* `<div class="page-head">` opens, walk div
    depth forward until we find the matching `</div>`. Returns the char index
    of the start of that closing tag. Returns -1 if not found."""
    depth = 1
    # start scanning from just past the opening tag
    i = open_start
    while i < len(src) and depth > 0:
        open_m  = DIV_OPEN_RE.search(src, i)
        close_m = DIV_CLOSE_RE.search(src, i)
        if not close_m:
            return -1
        if open_m and open_m.start() < close_m.start():
            depth += 1
            i = open_m.end()
        else:
            depth -= 1
            if depth == 0:
                return close_m.start()
            i = close_m.end()
    return -1


def fix(fp: Path, docs_path: str) -> str:
    src = fp.read_text()

    # 1. Strip any existing include lines for this template.
    stripped, n_stripped = INCLUDE_LINE_RE.subn('', src)

    # 2. Find <div class="page-head"> and its matching </div>.
    m = PAGE_HEAD_OPEN_RE.search(stripped)
    if not m:
        return "skip (no .page-head)"
    close_at = find_page_head_close(stripped, m.end())
    if close_at < 0:
        return "skip (unbalanced .page-head)"

    # 3. Insert the include as the last direct child.
    include = (
        f'  {{% with docs_path="{docs_path}" %}}'
        f'{{% include "_page_docs_link.html" %}}{{% endwith %}}\n'
    )
    # close_at points to the `<` of `</div>`. We want to insert the include on
    # its own line immediately before that `</div>`. Also ensure the `</div>`
    # lands on its own line with no leading whitespace eaten.
    #
    # Slice the source: everything up to close_at might end with whitespace +
    # indentation for the closing </div>. We strip trailing whitespace before
    # close_at and rebuild with a clean newline + 2-space indent.
    before = stripped[:close_at].rstrip(' \t')
    if not before.endswith('\n'):
        before += '\n'
    after = stripped[close_at:]  # starts with "</div>"
    new = before + include + '</div>' + after[len('</div>'):]

    fp.write_text(new)
    return f"fixed (stripped {n_stripped} prior include line{'s' if n_stripped != 1 else ''})"


def main() -> int:
    for name, docs in MAPPING.items():
        fp = TEMPLATES / name
        if not fp.exists():
            print(f"{name:30s}  MISSING")
            continue
        print(f"{name:30s}  {fix(fp, docs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
