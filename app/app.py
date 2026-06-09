#!/usr/bin/env python3
"""
CVE Explorer - UI Application Layer

A tiny web app that lets a user explore the CVEs collected by data/scrape.py.
It reads the same SQLite database and serves three things:

    /                     list page: search box + severity filter + sortable table
    /cve/CVE-2024-1234    detail page for one CVE
    /api/cves?...         JSON endpoint (same data, for anyone who wants raw data)

Design notes (matches the scraper's philosophy):
    - Zero dependencies. Uses only Python's standard library (http.server +
      sqlite3), so the whole project runs with just `python3`, no pip installs.
    - Read-only. The UI never writes to the DB; the scraper owns writes.
    - The DB path defaults to ../data/cves.db so it "just works" from the repo.

Usage:
    python3 app/app.py                      # serve on http://localhost:8000
    python3 app/app.py --port 5000
    python3 app/app.py --db path/to/cves.db
"""

import argparse
import html
import json
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Default DB location: ../data/cves.db relative to this file, so it works
# no matter what directory you launch from.
DEFAULT_DB = os.path.join(os.path.dirname(__file__), "..", "data", "cves.db")

# Severities we offer as filter buttons, plus a CSS color for each badge.
SEVERITY_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b91c1c",
    "MEDIUM": "#b45309",
    "LOW": "#15803d",
}

# Set once in main() so request handlers can reach it.
DB_PATH = DEFAULT_DB


# ---------------------------------------------------------------------------
# DATA ACCESS  (read-only queries against the scraper's table)
# ---------------------------------------------------------------------------
def get_conn():
    """Open a fresh read-only connection. row_factory lets us use column names."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def query_cves(search="", severity="", vendor="", sort="cvss_score", limit=500):
    """Return a list of CVE rows, filtered/sorted by the UI's controls.

    Built with parameterized queries (the ? placeholders) so user input can
    never inject SQL.
    """
    # Whitelist sort columns — never interpolate raw user input into SQL.
    sort_columns = {
        "cvss_score": "cvss_score DESC",
        "published_date": "published_date DESC",
        "cve_id": "cve_id DESC",
    }
    order_by = sort_columns.get(sort, "cvss_score DESC")

    where = []
    params = []
    if search:
        where.append("(cve_id LIKE ? OR description LIKE ?)")
        params += [f"%{search}%", f"%{search}%"]
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if vendor:
        # Match the affected vendor or product (both stored as text).
        where.append("(vendors LIKE ? OR products LIKE ?)")
        params += [f"%{vendor}%", f"%{vendor}%"]

    sql = ("SELECT cve_id, title, description, severity, cvss_score, "
           "published_date, vendors, products FROM cves")
    if where:
        sql += " WHERE " + " AND ".join(where)
    # NULL cvss_score sorts last so the worst CVEs surface first.
    sql += f" ORDER BY {order_by} LIMIT ?"
    params.append(limit)

    conn = get_conn()
    try:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def get_cve(cve_id):
    """Return one CVE as a dict, or None if not found."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT cve_id, title, description, severity, cvss_score, "
            "published_date, vendors, products FROM cves WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_stats():
    """Summary numbers for the dashboard strip at the top of the list page."""
    conn = get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        by_sev = {
            r["severity"]: r["n"]
            for r in conn.execute(
                "SELECT severity, COUNT(*) AS n FROM cves GROUP BY severity"
            ).fetchall()
        }
        return {"total": total, "by_severity": by_sev}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTML RENDERING  (plain string templates — no template engine needed)
# ---------------------------------------------------------------------------
def severity_badge(severity):
    """A small colored pill for a severity value."""
    if not severity:
        return '<span class="badge badge-unknown">UNRATED</span>'
    color = SEVERITY_COLORS.get(severity, "#475569")
    return f'<span class="badge" style="background:{color}">{html.escape(severity)}</span>'


PAGE_CSS = """
:root { font-family: -apple-system, system-ui, sans-serif; }
body { margin: 0; background: #0f172a; color: #e2e8f0; }
.wrap { max-width: 960px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { margin: 0 0 4px; font-size: 24px; }
.sub { color: #94a3b8; margin: 0 0 20px; font-size: 14px; }
a { color: #60a5fa; text-decoration: none; }
a:hover { text-decoration: underline; }
.stats { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
.stat { background: #1e293b; border-radius: 8px; padding: 10px 14px; min-width: 80px; }
.stat .num { font-size: 22px; font-weight: 700; }
.stat .lbl { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }
form.controls { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
input[type=text], select { background: #1e293b; color: #e2e8f0; border: 1px solid #334155;
    border-radius: 6px; padding: 8px 10px; font-size: 14px; }
input[type=text] { flex: 1; min-width: 200px; }
button { background: #2563eb; color: #fff; border: 0; border-radius: 6px;
    padding: 8px 16px; font-size: 14px; cursor: pointer; }
button:hover { background: #1d4ed8; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid #1e293b; font-size: 14px; }
th { color: #94a3b8; font-weight: 600; font-size: 12px; text-transform: uppercase; }
td.score { font-variant-numeric: tabular-nums; font-weight: 600; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px;
    font-weight: 700; color: #fff; letter-spacing: .03em; }
.badge-unknown { background: #475569; }
.desc { color: #cbd5e1; }
td.vendor { color: #a5b4fc; font-size: 13px; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; }
.chip { background: #312e81; color: #c7d2fe; border-radius: 6px; padding: 2px 8px; font-size: 12px; }
.detail-card { background: #1e293b; border-radius: 10px; padding: 24px; margin-top: 16px; }
.detail-card .id { font-size: 28px; font-weight: 700; margin: 0 0 8px; }
.meta { display: flex; gap: 24px; flex-wrap: wrap; margin: 16px 0; }
.meta div { font-size: 14px; }
.meta .k { color: #94a3b8; font-size: 11px; text-transform: uppercase; }
.empty { text-align: center; color: #94a3b8; padding: 40px; }
"""


def render_list(rows, stats, search, severity, vendor, sort):
    sev = stats["by_severity"]
    stat_cells = "".join(
        f'<div class="stat"><div class="num">{sev.get(s, 0)}</div>'
        f'<div class="lbl">{s.title()}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

    sev_options = '<option value="">All severities</option>'
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        selected = " selected" if s == severity else ""
        sev_options += f'<option value="{s}"{selected}>{s.title()}</option>'

    sort_options = ""
    for value, label in (
        ("cvss_score", "Highest score"),
        ("published_date", "Most recent"),
        ("cve_id", "CVE ID"),
    ):
        selected = " selected" if value == sort else ""
        sort_options += f'<option value="{value}"{selected}>{label}</option>'

    if rows:
        body_rows = ""
        for r in rows:
            score = "—" if r["cvss_score"] is None else f'{r["cvss_score"]:.1f}'
            pub = (r["published_date"] or "")[:10]
            title = html.escape(r["title"] or "")
            # Show the affected vendor(s); truncate if there are many.
            vend = r["vendors"] or ""
            vend_short = html.escape(vend[:40] + ("…" if len(vend) > 40 else "")) or "—"
            body_rows += (
                f"<tr>"
                f'<td><a href="/cve/{html.escape(r["cve_id"])}">{html.escape(r["cve_id"])}</a></td>'
                f"<td>{severity_badge(r['severity'])}</td>"
                f'<td class="score">{score}</td>'
                f'<td class="desc">{title}</td>'
                f'<td class="vendor">{vend_short}</td>'
                f"<td>{pub}</td>"
                f"</tr>"
            )
        table = f"""
        <table>
          <thead><tr><th>CVE</th><th>Severity</th><th>Score</th><th>Summary</th><th>Affected</th><th>Published</th></tr></thead>
          <tbody>{body_rows}</tbody>
        </table>
        <p class="sub">Showing {len(rows)} result(s).</p>
        """
    else:
        table = '<div class="empty">No CVEs match your filters.</div>'

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>CVE Explorer</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{PAGE_CSS}</style></head>
<body><div class="wrap">
  <h1>CVE Explorer</h1>
  <p class="sub">{stats['total']} vulnerabilities collected from the NVD public feed.</p>
  <div class="stats">
    <div class="stat"><div class="num">{stats['total']}</div><div class="lbl">Total</div></div>
    {stat_cells}
  </div>
  <form class="controls" method="get" action="/">
    <input type="text" name="q" placeholder="Search by CVE ID or keyword..." value="{html.escape(search)}">
    <input type="text" name="vendor" placeholder="Vendor / product (e.g. apache)" value="{html.escape(vendor)}">
    <select name="severity">{sev_options}</select>
    <select name="sort">{sort_options}</select>
    <button type="submit">Search</button>
  </form>
  {table}
</div></body></html>"""


def render_detail(cve):
    score = "Unrated" if cve["cvss_score"] is None else f'{cve["cvss_score"]:.1f} / 10'

    # Affected software as clickable chips (each links back to a filtered list).
    affected = ""
    products = [p.strip() for p in (cve["products"] or "").split(",") if p.strip()]
    if products:
        chips = "".join(
            f'<a class="chip" href="/?vendor={urllib.parse.quote(p)}">{html.escape(p)}</a>'
            for p in products[:20]
        )
        affected = f'<div class="k">Affected products</div><div class="chips">{chips}</div>'
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{html.escape(cve['cve_id'])} — CVE Explorer</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>{PAGE_CSS}</style></head>
<body><div class="wrap">
  <p><a href="/">&larr; Back to all CVEs</a></p>
  <div class="detail-card">
    <p class="id">{html.escape(cve['cve_id'])}</p>
    <div>{severity_badge(cve['severity'])}</div>
    <div class="meta">
      <div><div class="k">CVSS score</div>{score}</div>
      <div><div class="k">Published</div>{html.escape((cve['published_date'] or '')[:10])}</div>
    </div>
    <div class="k">Description</div>
    <p class="desc">{html.escape(cve['description'] or 'No description available.')}</p>
    {affected}
    <p class="sub">
      <a href="https://nvd.nist.gov/vuln/detail/{html.escape(cve['cve_id'])}" target="_blank">
        View on NVD &rarr;</a>
    </p>
  </div>
</div></body></html>"""


def render_404(message="Not found"):
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Not found</title><style>{PAGE_CSS}</style></head>
<body><div class="wrap"><h1>404</h1><p class="sub">{html.escape(message)}</p>
<p><a href="/">&larr; Back to CVE Explorer</a></p></div></body></html>"""


# ---------------------------------------------------------------------------
# HTTP HANDLER
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def _send(self, body, status=200, content_type="text/html; charset=utf-8"):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        def p(name, default=""):
            return params.get(name, [default])[0]

        # ---- list page ----
        if path == "/":
            search = p("q").strip()
            severity = p("severity").strip()
            vendor = p("vendor").strip()
            sort = p("sort", "cvss_score").strip()
            rows = query_cves(search, severity, vendor, sort)
            self._send(render_list(rows, get_stats(), search, severity, vendor, sort))
            return

        # ---- JSON API (bonus: raw data for other tools) ----
        if path == "/api/cves":
            rows = query_cves(p("q").strip(), p("severity").strip(),
                              p("vendor").strip(), p("sort", "cvss_score").strip())
            self._send(json.dumps(rows, indent=2), content_type="application/json")
            return

        # ---- detail page ----
        if path.startswith("/cve/"):
            cve_id = urllib.parse.unquote(path[len("/cve/"):])
            cve = get_cve(cve_id)
            if cve:
                self._send(render_detail(cve))
            else:
                self._send(render_404(f"No CVE named {cve_id}"), status=404)
            return

        self._send(render_404(), status=404)

    def log_message(self, fmt, *args):
        # Quieter, single-line logging (bonus: basic request logging).
        print(f"{self.address_string()} {fmt % args}")


def main():
    global DB_PATH
    parser = argparse.ArgumentParser(description="Serve the CVE Explorer UI.")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--db", default=DEFAULT_DB, help="SQLite DB to read (default: ../data/cves.db)")
    args = parser.parse_args()

    DB_PATH = args.db
    if not os.path.exists(DB_PATH):
        raise SystemExit(
            f"Database not found: {DB_PATH}\n"
            "Run the scraper first:  python3 data/scrape.py"
        )

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"CVE Explorer running at  http://localhost:{args.port}")
    print(f"Reading database:        {DB_PATH}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
