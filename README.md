# CVE Explorer — Data Layer (Person 1)

Scrapes recent CVEs from the [NVD public API](https://nvd.nist.gov/developers/vulnerabilities)
and stores them in a local SQLite database. Re-running is safe (upsert — no duplicates).

## What's here

- `scrape.py` — the scraper + storage script
- `cves.db` — the SQLite database (the deliverable; rebuildable by running the script)

## How to run

No installs needed — uses only Python 3's standard library.

```bash
python3 scrape.py              # fetch 200 recent CVEs into cves.db
python3 scrape.py --count 500  # fetch more
python3 scrape.py --db my.db   # write to a different file
```

## Database schema

Table `cves`, one row per CVE:

| column           | type | notes                                   |
|------------------|------|-----------------------------------------|
| `cve_id`         | TEXT | primary key, e.g. `CVE-2024-1234`       |
| `title`          | TEXT | short label (first sentence of desc)    |
| `description`    | TEXT | full English description                |
| `severity`       | TEXT | LOW / MEDIUM / HIGH / CRITICAL          |
| `cvss_score`     | REAL | 0.0–10.0                                |
| `published_date` | TEXT | ISO date string                         |

## For the backend dev (Person 2)

Just open `cves.db` with Python's `sqlite3` and query the `cves` table. Example:

```python
import sqlite3
conn = sqlite3.connect("cves.db")
rows = conn.execute(
    "SELECT cve_id, title, severity, cvss_score FROM cves "
    "WHERE severity = ? ORDER BY cvss_score DESC", ("HIGH",)
).fetchall()
```

## Notes

- The NVD API has no auth but rate-limits to ~5 requests / 30s without a key,
  so the script pauses 6s between pages and retries on 429/403.
- `cve_id` is the primary key, so re-running updates existing rows instead of
  duplicating them.
