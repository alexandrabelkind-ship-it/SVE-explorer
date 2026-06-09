#!/usr/bin/env python3
"""
CVE Explorer - Data Layer (Person 1)

Scrapes recent CVEs from the NVD public API and stores them in a SQLite DB.
Re-running is safe: existing CVEs are updated, new ones inserted (upsert).

Usage:
    python3 scrape.py                 # fetch 200 recent CVEs (default)
    python3 scrape.py --count 500     # fetch 500
    python3 scrape.py --db other.db   # write to a different DB file

No API key needed. No pip installs needed (uses only the standard library).
"""

import argparse
import json
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# NVD's public REST API. Returns clean JSON, no auth required.
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD caps each request at 2000 results. We page through in chunks this size.
PAGE_SIZE = 200


# ---------------------------------------------------------------------------
# 1. DATABASE SETUP
# ---------------------------------------------------------------------------
def init_db(db_path):
    """Create the SQLite file + table if they don't exist yet, and return
    an open connection."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
            cve_id         TEXT PRIMARY KEY,   -- e.g. "CVE-2024-1234" (unique => enables upsert)
            title          TEXT,
            description    TEXT,
            severity       TEXT,               -- LOW / MEDIUM / HIGH / CRITICAL
            cvss_score     REAL,               -- numeric score 0.0 - 10.0
            published_date TEXT                -- ISO date string
        )
        """
    )
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# 2. FETCH FROM THE API
# ---------------------------------------------------------------------------
def fetch_page(start_index, page_size):
    """Fetch one page of CVEs from NVD. Returns the parsed JSON dict."""
    params = urllib.parse.urlencode(
        {"resultsPerPage": page_size, "startIndex": start_index}
    )
    url = f"{NVD_API_URL}?{params}"

    # NVD asks for a User-Agent header; without one you sometimes get blocked.
    req = urllib.request.Request(url, headers={"User-Agent": "cve-explorer/1.0"})

    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# 3. PARSE ONE RAW CVE INTO OUR FLAT SHAPE
# ---------------------------------------------------------------------------
def parse_cve(item):
    """Turn one raw NVD record into the 6 fields our table needs.

    The NVD JSON is deeply nested, so this function digs out just what we
    care about and gives safe defaults when a field is missing.
    """
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Description: NVD ships a list of localized descriptions; grab the English one.
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    # Title: NVD records don't have a real "title" field, so we make one from
    # the first sentence of the description (good enough for a list view).
    title = description.split(". ")[0][:120] if description else cve_id

    # Severity + CVSS score live under "metrics". NVD has several CVSS versions;
    # we try v3.1, then v3.0, then v2, taking whichever exists first.
    severity = None
    cvss_score = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss_score = data.get("baseScore")
            # v3 puts severity in cvssData; v2 puts it one level up.
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break

    published_date = cve.get("published", "")

    return {
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "published_date": published_date,
    }


# ---------------------------------------------------------------------------
# 4. UPSERT INTO THE DB
# ---------------------------------------------------------------------------
def upsert_cves(conn, rows):
    """Insert new CVEs; update existing ones. This is the dedup logic.

    Because cve_id is the PRIMARY KEY, 'ON CONFLICT(cve_id) DO UPDATE'
    means: if we've seen this CVE before, overwrite its fields with the
    freshest data instead of creating a duplicate row.
    """
    conn.executemany(
        """
        INSERT INTO cves (cve_id, title, description, severity, cvss_score, published_date)
        VALUES (:cve_id, :title, :description, :severity, :cvss_score, :published_date)
        ON CONFLICT(cve_id) DO UPDATE SET
            title          = excluded.title,
            description    = excluded.description,
            severity       = excluded.severity,
            cvss_score     = excluded.cvss_score,
            published_date = excluded.published_date
        """,
        rows,
    )
    conn.commit()


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Scrape CVEs from NVD into SQLite.")
    parser.add_argument("--count", type=int, default=200,
                        help="How many CVEs to fetch (default: 200)")
    parser.add_argument("--db", default="cves.db",
                        help="SQLite file to write to (default: cves.db)")
    args = parser.parse_args()

    conn = init_db(args.db)
    print(f"DB ready: {args.db}")

    fetched = 0
    start_index = 0
    while fetched < args.count:
        page_size = min(PAGE_SIZE, args.count - fetched)
        print(f"Fetching {page_size} CVEs starting at index {start_index}...")

        try:
            data = fetch_page(start_index, page_size)
        except urllib.error.HTTPError as e:
            # 403/429 usually means rate-limited. NVD allows ~5 requests / 30s
            # without a key, so we back off and retry once.
            if e.code in (403, 429):
                print("  Rate limited by NVD, waiting 30s then retrying...")
                time.sleep(30)
                data = fetch_page(start_index, page_size)
            else:
                raise

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print("No more results from NVD.")
            break

        rows = [parse_cve(v) for v in vulns]
        upsert_cves(conn, rows)
        fetched += len(rows)
        start_index += len(rows)
        print(f"  Stored {len(rows)} (total {fetched}).")

        # Be polite to the public API: pause between pages to avoid rate limits.
        if fetched < args.count:
            time.sleep(6)

    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    print(f"\nDone. Database now holds {total} unique CVEs in {args.db}")
    conn.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
