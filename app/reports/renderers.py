"""Rows + summary → bytes + mimetype. CSV for ingest, HTML for a
human-readable artifact (usable as a print-to-PDF source)."""
from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any


def _html_escape(s: Any) -> str:
    return (str("" if s is None else s)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


def render_csv(report_type: str, summary: dict, headers: list[str],
               rows: list[list]) -> tuple[bytes, str]:
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    w.writerow([f"# report", report_type])
    w.writerow([f"# generated", datetime.utcnow().isoformat() + "Z"])
    for k, v in summary.items():
        w.writerow([f"# {k}", v])
    w.writerow([])
    w.writerow(headers)
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8"), "text/csv"


def render_html(report_type: str, summary: dict, headers: list[str],
                rows: list[list], *, title: str | None = None) -> tuple[bytes, str]:
    title = title or report_type.replace("_", " ").title()
    summary_html = "\n".join(
        f"  <dt>{_html_escape(k)}</dt><dd>{_html_escape(v)}</dd>"
        for k, v in summary.items()
    )
    head_html = "".join(f"<th>{_html_escape(h)}</th>" for h in headers)
    body_html = "\n".join(
        "<tr>" + "".join(f"<td>{_html_escape(c)}</td>" for c in r) + "</tr>"
        for r in rows
    )
    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{_html_escape(title)}</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif; margin: 24px; color:#111; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color:#666; font-size: 11px; margin-bottom: 18px; }}
  dl {{ display: grid; grid-template-columns: auto 1fr; gap: 4px 16px; font-size: 12px; margin: 0 0 16px; }}
  dt {{ color: #555; }}
  dd {{ margin: 0; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
  th, td {{ padding: 6px 10px; border-bottom: 1px solid #e5e7eb; text-align: left; }}
  th {{ background: #f3f4f6; font-weight: 600; }}
  tr:nth-child(even) td {{ background: #fafafa; }}
  @media print {{ tr {{ page-break-inside: avoid; }} }}
</style></head><body>
<h1>{_html_escape(title)}</h1>
<div class="meta">Generated {datetime.utcnow().isoformat(timespec="seconds")}Z · report: {_html_escape(report_type)}</div>
<dl>
{summary_html}
</dl>
<table>
  <thead><tr>{head_html}</tr></thead>
  <tbody>
{body_html}
  </tbody>
</table>
</body></html>
"""
    return doc.encode("utf-8"), "text/html"


def render(report_type: str, summary: dict, headers: list[str],
           rows: list[list], fmt: str) -> tuple[bytes, str]:
    if fmt == "csv":
        return render_csv(report_type, summary, headers, rows)
    if fmt == "html":
        return render_html(report_type, summary, headers, rows)
    raise ValueError(f"Unknown format {fmt!r}")
