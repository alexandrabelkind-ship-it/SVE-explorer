# CVE Explorer
An end-to-end system for collecting public CVE vulnerability data, storing it, and exploring it through a web UI and a REST API.

---

## The Problem

Security teams need to track CVEs (Common Vulnerabilities and Exposures) — but public data is buried in deeply nested API responses, hard to filter, and hard to explore.

CVE Explorer solves this: collect once, store clean, explore easily.

---

## System Architecture

Four layers, two entry points:

- **Data collection** — scrape.py fetches CVEs from the NVD public API
- **Data storage** — SQLite database, one row per CVE
- **Web UI** — zero-dependency Python app for humans to explore CVEs
- **REST API** — FastAPI service for programmatic access and integrations

The Web UI and REST API are independent — both read from the same database.

---

## Data Collection — scrape.py

Fetches CVEs from the NVD public API. No API key needed. No external dependencies — pure Python standard library.

**What we store per CVE:**
- CVE ID, title, full description
- Severity (LOW / MEDIUM / HIGH / CRITICAL) and CVSS score (0–10)
- Published date and last-modified date
- Affected vendors and products (parsed from CPE strings)

**Key features:**
- Safe to re-run — existing CVEs are updated, not duplicated (upsert)
- Incremental updates with `--since`: only fetch CVEs changed since the last run
- Rate-limit handling: pauses between pages, retries on HTTP 429

---

## Data Storage — SQLite

A single self-contained file (`cves.db`). No server. No setup.

- Trivially queryable from any language
- Rebuildable anytime by re-running the scraper
- Not committed to git — it's a build artifact

---

## Web UI — app.py

A self-contained web app. Zero dependencies — runs anywhere Python does.

**Features:**
- List view — table of CVEs with ID, severity, score, summary, affected software, date
- Detail view — click any CVE for the full description and a link to its NVD page
- Search — by CVE ID or keyword
- Filter — by severity, vendor, or product
- Sort — by score, date, or ID
- Stats strip — totals and counts per severity level

---

## REST API — main.py

A FastAPI service with auto-generated Swagger docs at `/docs`. CORS enabled for direct browser access.

**Endpoints:**
- `GET /cves` — list CVEs with severity filter, search, pagination
- `GET /cves/{cve_id}` — fetch a single CVE
- `GET /stats` — totals and per-severity breakdown
- `GET /health` — liveness check with uptime and data source

---

## Design Decisions

**Two independent front-ends.** The stdlib UI runs anywhere Python does — no install needed. The FastAPI service is for programmatic access with docs generated for free. Pick whichever fits the use case.

**Scraper writes; readers are read-only.** Clean separation: you can re-scrape while a front-end is live, and a reader can never corrupt the data.

**SQLite for storage.** A single file is perfect for this scale — no server to set up, trivially queryable from any language, easily portable.

**Safe by construction.** All queries are parameterized and sort columns are whitelisted — user input can't inject SQL.

---

## Challenges

- **NVD JSON is deeply nested** — extracting severity, affected vendors, and products required careful parsing across multiple CVSS versions (v2, v3.0, v3.1)
- **Rate limiting** — NVD caps unauthenticated requests at ~5/30s; the scraper handles this with automatic backoff and retry
- **Incremental updates** — implemented `--since` mode so the database stays fresh without re-fetching everything each time

---

## Demo

1. Run the scraper → database populated with real CVEs
2. Open the web UI → filter by CRITICAL severity
3. Click a CVE → full detail view with affected products
4. Hit the API → same data as JSON, ready for integrations
