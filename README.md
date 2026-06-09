# 🏄 CVE Explorer

**Live CVE intelligence — collected, stored, and explored end to end.**

CVE Explorer is a complete vulnerability-intelligence system. It pulls real CVE data from the National Vulnerability Database (NVD), stores it in a clean local database, serves it through a modern REST API, and presents it in a polished React dashboard — with AI-powered, plain-English remediation built in.

---

## The Problem

Security teams need to track CVEs (Common Vulnerabilities and Exposures), but the public data is painful to work with:

- It's buried in **deeply nested API responses** spanning multiple CVSS versions.
- It's **hard to filter, sort, and search** across thousands of records.
- The raw descriptions are **dense and technical** — not built for fast triage.

**CVE Explorer solves this:** collect once, store clean, explore beautifully, and let AI explain what each vulnerability actually means.

---

## System Architecture

Four cooperating layers built around one shared database.

| Layer | Folder | What it does | Stack |
|-------|--------|--------------|-------|
| **Data collection** | [`data/`](data/) | `scrape.py` fetches CVEs from the NVD public API | Python stdlib |
| **Data storage** | `data/cves.db` | A single SQLite file — one row per CVE | SQLite |
| **REST API** | [`api/`](api/) | FastAPI service with AI remediation, stats, trends, timelines | FastAPI + Azure OpenAI |
| **React dashboard** | [`frontend/`](frontend/) | A modern SPA for exploring CVEs visually | React + Vite |
| **Stdlib web UI** | [`app/`](app/) | A zero-dependency Python web app — runs anywhere Python does | Python stdlib |

Every reader (the API, the React app, and the stdlib UI) reads the **same database**. Only the scraper writes — so a reader can never corrupt the data, and you can re-scrape while a front-end is live.

---

## 1. Data Collection — `data/scrape.py` (multi-source)

A **multi-source** scraper that pulls from several authoritative feeds and merges them into one database, so each CVE ends up with the richest combined view. **No API key needed. No pip installs** — pure Python standard library.

### Sources

| Source | Module | What it contributes |
|--------|--------|--------------------|
| **NVD** | `sources/nvd.py` | Broad baseline feed, CVSS scores, CPE-derived vendors/products |
| **CVE.org** (MITRE) | `sources/cveorg.py` | The *authoritative* CVE JSON 5.0 record + references — often fresher than NVD |
| **GitHub Advisory** (GHSA) | `sources/github_advisory.py` | **Affected packages per ecosystem** (npm, PyPI, Maven, Go…) — data NVD doesn't carry |

Each source returns the same flat shape; the orchestrator **merges by `cve_id`** — scalar fields take the first authoritative value, while lists (packages, references, vendors) are unioned. A `source` column records every feed that contributed to each row (e.g. `nvd,ghsa`).

**What we store per CVE:**
- CVE ID, title, and full description
- Severity (`LOW` / `MEDIUM` / `HIGH` / `CRITICAL`) and CVSS score (0.0–10.0)
- Published date and last-modified date
- Affected vendors and products (from CPE) **and affected packages** (from GHSA)
- GHSA advisory ID, reference URLs, and the contributing source list

**Key features:**
- **Multi-source merge** — cross-references NVD, CVE.org, and GitHub Advisory into one record.
- **Safe to re-run** — existing CVEs are updated, never duplicated (upsert on primary key).
- **Incremental updates** with `--since` — only fetch CVEs changed since the last run.
- **Resilient** — if one source fails, the others still run; rate limits trigger automatic backoff.
- **Self-migrating schema** — older databases are upgraded with new columns on the fly.

```bash
python3 data/scrape.py                       # NVD, 200 CVEs (default)
python3 data/scrape.py --source all          # NVD + GHSA, then enrich via CVE.org
python3 data/scrape.py --source ghsa         # GitHub advisories only (affected packages)
python3 data/scrape.py --source nvd,ghsa     # pick specific sources
python3 data/scrape.py --enrich-cveorg       # add CVE.org's authoritative record to each CVE
python3 data/scrape.py --since               # incremental: only what changed since last run
```

> GHSA works unauthenticated (60 requests/hour). Set a `GH_TOKEN` env var to raise that to 5,000/hour.

---

## 2. Data Storage — SQLite

A single self-contained file, `data/cves.db`. No server. No setup.

- Trivially queryable from **any language**.
- **Rebuildable** at any time by re-running the scraper.
- Indexed on severity and CVSS score for fast filtering.

| Column | Type | Notes |
|--------|------|-------|
| `cve_id` | TEXT | Primary key, e.g. `CVE-2024-1234` |
| `title` | TEXT | Short label (first sentence of the description) |
| `description` | TEXT | Full English description |
| `severity` | TEXT | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `cvss_score` | REAL | 0.0–10.0 |
| `published_date` | TEXT | ISO date string |
| `last_modified` | TEXT | ISO date the source last changed the CVE (drives `--since`) |
| `vendors` | TEXT | Comma-separated affected vendors (from CPE) |
| `products` | TEXT | Comma-separated affected products (from CPE) |
| `affected_packages` | TEXT | Comma-separated `ecosystem:name` (from GHSA) |
| `ghsa_id` | TEXT | GitHub advisory ID, if any |
| `references` | TEXT | Comma-separated reference URLs |
| `source` | TEXT | Which feeds contributed, e.g. `nvd,ghsa` |

---

## 3. REST API — `api/main.py`

A **FastAPI** service (v2.0.0) with auto-generated Swagger docs at `/docs` and CORS enabled for direct browser access. Powers the React dashboard and any external integration.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/cves` | List CVEs — filter by severity, full-text search, date range, sort, paginate |
| `GET` | `/cves/{cve_id}` | Fetch one CVE (add `?remediation=true` for an AI fix recommendation) |
| `GET` | `/cves/summary` | Severity breakdown with percentages + the 10 most dangerous CVEs |
| `GET` | `/cves/trending` | Most recent CVEs, surfaced by severity |
| `GET` | `/cves/timeline` | CVE counts grouped by month, split by severity |
| `GET` | `/cves/{cve_id}/similar` | Find related CVEs by keyword overlap |
| `GET` | `/cves/{cve_id}/explore` | **Search Explorer** — cross-references the CVE across NVD, CVE.org, MITRE, a live GitHub Advisory lookup, and web search link-outs |
| `GET` | `/stats` | Totals, average/max CVSS, and per-severity counts |
| `GET` | `/health` | Liveness check — uptime, data source, cache size |
| `GET` | `/cache/stats` | Inspect the AI remediation cache |

### AI-Powered Remediation

The API integrates with **Azure OpenAI** (via [`api/azure_client.py`](api/azure_client.py)) to turn dense CVE descriptions into **concise, actionable remediation steps** — and caches each result so repeat lookups are instant and free.

```bash
cd api
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
# Swagger UI → http://localhost:8000/docs
```

> AI features read `AZURE_OPENAI_MONITORING_KEY` and `AZURE_OPENAI_ENDPOINT` from your environment (or a `.env` file). The rest of the API works fully without them.

---

## 4. React Dashboard — `frontend/`

A polished, Apple-inspired single-page app built with **React + Vite**. This is the primary way humans explore CVE Explorer.

**Features:**
- **Live severity dashboard** — Critical / High / Medium / Low / Total cards at a glance.
- **Instant search** — debounced search by CVE ID, keyword, or technology.
- **Filter & sort** — by severity, alphabetically, or by date.
- **Detail modals** — full description, CVSS score bar, published date, NVD link.
- **AI plain-English summaries** — one click to understand any CVE in human terms.
- **Search Explorer** — every CVE detail view cross-references the CVE live across NVD, CVE.org, MITRE, GitHub Advisories (with affected packages), and web search.
- **"Ask GPT"** — open a ready-made remediation prompt in ChatGPT for any CVE.
- Loading skeletons, empty states, and graceful error handling throughout.

```bash
cd frontend
npm install
npm run dev      # → http://localhost:5173
```

---

## 5. Zero-Dependency Web UI — `app/app.py`

A complete alternative web UI built on **nothing but the Python standard library** (`http.server` + `sqlite3`). Perfect for environments where you can't install anything.

- **List page** — search box, severity filter, vendor/product filter, sortable table.
- **Detail page** — full description, affected products as clickable chips, NVD link.
- **JSON endpoint** — `/api/cves` serves the same data as raw JSON.
- **Read-only by design** — the UI never writes to the database.

```bash
python3 app/app.py                  # → http://localhost:8000
python3 app/app.py --port 5000
python3 app/app.py --db path/to/cves.db
```

---

## Design Decisions

- **Multiple front-ends, one source of truth.** The React dashboard is the showcase; the FastAPI service powers integrations; the stdlib UI runs anywhere Python does. All three read the same database — pick whichever fits.
- **Scraper writes; readers are read-only.** Clean separation means you can re-scrape while a front-end is live, and no reader can ever corrupt the data.
- **SQLite for storage.** A single file is ideal at this scale — no server to manage, trivially portable, queryable from any language.
- **Safe by construction.** All queries are parameterized and sort columns are whitelisted — user input can never inject SQL.
- **AI where it adds value.** Caching keeps AI remediation fast and cheap; the system stays fully functional without it.

---

## Challenges We Solved

- **Deeply nested NVD JSON** — extracting severity, CVSS scores, and affected vendors/products required careful parsing across CVSS v2, v3.0, and v3.1.
- **Rate limiting** — NVD caps unauthenticated requests at ~5 per 30 seconds; the scraper handles this with automatic backoff and retry.
- **Incremental updates** — `--since` mode keeps the database fresh without re-fetching everything every run.
- **Making CVEs human-readable** — AI summaries and remediation turn jargon-heavy records into something a team can act on immediately.

---

## Quick Start (Full Stack)

```bash
# 1. Collect data
python3 data/scrape.py --count 200

# 2. Start the API
cd api && pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# 3. Start the dashboard (in a second terminal)
cd frontend && npm install && npm run dev

# 4. Open http://localhost:5173 and start exploring 🏄
```

---

## Running with Docker (Optional)

Docker isn't required — the whole system runs with just `python3` and `npm`. But for a one-command setup, the API and dashboard can be wrapped in containers and orchestrated with **Docker Compose**, so a single command brings the whole stack up:

```bash
docker compose up --build
# API       → http://localhost:8000  (docs at /docs)
# Dashboard → http://localhost:5173
```

**Why bother?** It removes the "install Python *and* Node at the right versions, then run three terminals" friction — one command, and the stack is live. The shared `data/cves.db` is mounted as a volume so the scraper, API, and UI all see the same data.

> This is a convenience layer, not a dependency. The lightweight, server-free design is intentional — Docker just makes the full stack trivial to spin up for a demo.

---

## Demo Flow

1. **Run the scraper** → the database fills with real, recent CVEs.
2. **Open the dashboard** → see the live severity breakdown, filter to `CRITICAL`.
3. **Click a CVE** → full detail modal with CVSS score bar and description.
4. **Hit "Explain in plain English"** → AI turns the jargon into a clear summary.
5. **Call the API** → the same data as JSON, ready for any integration.

---

> `data/cves.db` is a build artifact — regenerate it anytime by running the scraper. Commit the code, not the data.
