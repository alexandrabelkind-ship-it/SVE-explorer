#!/usr/bin/env python3
"""
CVE Explorer - Data Layer (multi-source scraper)

Collects CVEs from several public sources and merges them into one SQLite DB:

    nvd     National Vulnerability Database  - broad feed, CVSS, CPE vendors/products
    cveorg  MITRE CVE Services (CVE JSON 5.0) - the authoritative record + references
    ghsa    GitHub Advisory Database          - affected packages per ecosystem (npm, PyPI...)

Records are keyed on cve_id and merged across sources, so each CVE ends up with the
richest combined view. Re-running is safe: existing CVEs are updated, new ones
inserted (upsert).

Usage:
    python3 scrape.py                          # nvd, 200 CVEs (default)
    python3 scrape.py --source all             # nvd + ghsa, then enrich via cve.org
    python3 scrape.py --source ghsa            # GitHub advisories only
    python3 scrape.py --source nvd,ghsa        # pick specific sources
    python3 scrape.py --count 500              # fetch more per source
    python3 scrape.py --since                  # incremental (nvd): only changed since last run
    python3 scrape.py --since 2024-01-01       # incremental from a date
    python3 scrape.py --enrich-cveorg          # also look up each CVE in cve.org

No API key needed. Stdlib only. A GH_TOKEN/GITHUB_TOKEN env var is used for GHSA if set.
"""

import argparse
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

from sources import SOURCES, cveorg

# Fields stored per CVE, in column order. The merge and upsert both use this list.
COLUMNS = [
    "cve_id", "title", "description", "severity", "cvss_score",
    "published_date", "last_modified", "vendors", "products",
    "affected_packages", "ghsa_id", "references", "source",
]


# ---------------------------------------------------------------------------
# DATABASE
# ---------------------------------------------------------------------------
def init_db(db_path):
    """Create the file/table if needed and migrate older DBs. Returns a connection."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id            TEXT PRIMARY KEY,
            title             TEXT,
            description       TEXT,
            severity          TEXT,
            cvss_score        REAL,
            published_date    TEXT,
            last_modified     TEXT,
            vendors           TEXT,
            products          TEXT,
            affected_packages TEXT,   -- "ecosystem:name, ..." (mainly GHSA)
            ghsa_id           TEXT,   -- GitHub advisory id, if any
            "references"      TEXT,   -- comma-separated reference URLs
            source            TEXT    -- which feeds contributed, e.g. "nvd,ghsa"
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score);")
    # Migrate DBs created before the multi-source columns existed.
    for name, col_type in (
        ("last_modified", "TEXT"), ("vendors", "TEXT"), ("products", "TEXT"),
        ("affected_packages", "TEXT"), ("ghsa_id", "TEXT"),
        ('"references"', "TEXT"), ("source", "TEXT"),
    ):
        _add_column_if_missing(conn, name, col_type)
    conn.commit()
    return conn


def _add_column_if_missing(conn, name, col_type):
    existing = {row[1] for row in conn.execute("PRAGMA table_info(cves)").fetchall()}
    if name.strip('"') not in existing:
        conn.execute(f"ALTER TABLE cves ADD COLUMN {name} {col_type}")


def newest_last_modified(conn):
    """Most recent last_modified stored, or None. Drives bare --since."""
    row = conn.execute(
        "SELECT MAX(last_modified) FROM cves WHERE last_modified IS NOT NULL"
    ).fetchone()
    return row[0] if row and row[0] else None


# ---------------------------------------------------------------------------
# MERGE  (combine rows for the same CVE coming from different sources)
# ---------------------------------------------------------------------------
def merge_rows(all_rows):
    """Merge a flat list of source rows into one dict per cve_id.

    Strategy: first source to provide a non-empty value wins for most fields, but
    sources are passed in priority order (authoritative first). `source` accumulates
    every feed that contributed, and list-ish fields (packages/references) union.
    """
    merged = {}
    for row in all_rows:
        cid = row.get("cve_id")
        if not cid:
            continue
        if cid not in merged:
            merged[cid] = {c: row.get(c) for c in COLUMNS}
            merged[cid]["source"] = row.get("source") or ""
            continue

        existing = merged[cid]
        # Track contributing sources.
        srcs = {s for s in existing["source"].split(",") if s}
        if row.get("source"):
            srcs.add(row["source"])
        existing["source"] = ",".join(sorted(srcs))

        for col in COLUMNS:
            if col == "source":
                continue
            new_val = row.get(col)
            if not new_val:
                continue
            cur = existing.get(col)
            if col in ("affected_packages", "references", "vendors", "products"):
                # Union comma-separated lists across sources.
                parts = {p.strip() for p in (cur or "").split(",") if p.strip()}
                parts |= {p.strip() for p in str(new_val).split(",") if p.strip()}
                existing[col] = ", ".join(sorted(parts))
            elif not cur:
                # Scalar: fill only if we don't already have one.
                existing[col] = new_val
    return list(merged.values())


# ---------------------------------------------------------------------------
# UPSERT
# ---------------------------------------------------------------------------
def upsert_cves(conn, rows):
    """Insert new CVEs; update existing ones (dedup on cve_id).

    `references` is a SQL keyword, so it's quoted as a column but bound via the
    safe param name `references_` (named params can't contain quotes).
    """
    cols_sql = ", ".join(f'"{c}"' if c == "references" else c for c in COLUMNS)
    placeholders = ", ".join(f":references_" if c == "references" else f":{c}" for c in COLUMNS)
    updates = ", ".join(
        f'"{c}" = excluded."{c}"' if c == "references" else f"{c} = excluded.{c}"
        for c in COLUMNS if c != "cve_id"
    )
    norm_rows = []
    for r in rows:
        nr = dict(r)
        nr["references_"] = nr.pop("references", "")
        norm_rows.append(nr)

    sql = (
        f"INSERT INTO cves ({cols_sql}) VALUES ({placeholders}) "
        f"ON CONFLICT(cve_id) DO UPDATE SET {updates}"
    )
    conn.executemany(sql, norm_rows)
    conn.commit()


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Scrape CVEs from multiple sources into SQLite.")
    parser.add_argument("--source", default="nvd",
                        help="Comma-separated sources or 'all'. Options: nvd, ghsa. "
                             "(cve.org is enrichment-only; use --enrich-cveorg.)")
    parser.add_argument("--count", type=int, default=200,
                        help="How many CVEs to fetch per source (default: 200)")
    parser.add_argument("--db", default="cves.db",
                        help="SQLite file to write (default: cves.db)")
    parser.add_argument("--since", nargs="?", const="auto", metavar="ISO_DATE",
                        help="Incremental (nvd): only CVEs modified since this date. "
                             "Bare --since resumes from the newest stored CVE.")
    parser.add_argument("--enrich-cveorg", action="store_true",
                        help="After fetching, look up every CVE in MITRE CVE Services "
                             "to add the authoritative description and references.")
    args = parser.parse_args()

    # Resolve which sources to fetch from.
    if args.source.lower() == "all":
        selected = ["nvd", "ghsa"]
        args.enrich_cveorg = True
    else:
        selected = [s.strip().lower() for s in args.source.split(",") if s.strip()]
    unknown = [s for s in selected if s not in SOURCES or s == "cveorg"]
    if unknown:
        parser.error(f"Unknown/unsupported source(s): {', '.join(unknown)}. "
                     f"Fetchable: nvd, ghsa. (cve.org via --enrich-cveorg)")

    conn = init_db(args.db)
    print(f"DB ready: {args.db}")

    # Work out the NVD incremental window if --since was used.
    since = None
    if args.since == "auto":
        since = newest_last_modified(conn)
        if since:
            print(f"Incremental: NVD CVEs modified since {since[:10]}.")
        else:
            since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
            print(f"Incremental: empty DB, defaulting to last 7 days ({since[:10]}).")
    elif args.since:
        since = args.since if "T" in args.since else f"{args.since}T00:00:00.000"
        print(f"Incremental: NVD CVEs modified since {since[:10]}.")

    # ---- Fetch from each selected source. ----
    all_rows = []
    for name in selected:
        module = SOURCES[name]
        print(f"\n=== Source: {name} ===")
        try:
            all_rows.extend(module.fetch(count=args.count, since=since))
        except Exception as e:
            print(f"  [{name}] ERROR: {e} (continuing with other sources)")

    # ---- Optional cve.org enrichment for the CVEs we just gathered. ----
    if args.enrich_cveorg and all_rows:
        cve_ids = sorted({r["cve_id"] for r in all_rows if r.get("cve_id")})
        print(f"\n=== Enrich: cve.org ({len(cve_ids)} CVEs) ===")
        try:
            all_rows.extend(cveorg.fetch(cve_ids=cve_ids))
        except Exception as e:
            print(f"  [cveorg] ERROR: {e}")

    if not all_rows:
        print("\nNothing fetched. Nothing to store.")
        conn.close()
        return

    # ---- Merge across sources, then upsert. ----
    merged = merge_rows(all_rows)
    print(f"\nMerged {len(all_rows)} source rows into {len(merged)} unique CVEs.")
    upsert_cves(conn, merged)

    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    by_src = conn.execute(
        "SELECT source, COUNT(*) FROM cves GROUP BY source ORDER BY COUNT(*) DESC"
    ).fetchall()
    print(f"\nDone. Database now holds {total} unique CVEs in {args.db}")
    for src, n in by_src:
        print(f"   {src or '(none)'}: {n}")
    conn.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
