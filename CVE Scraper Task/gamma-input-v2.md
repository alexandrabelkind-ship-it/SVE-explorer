# CVE Explorer
Live CVE intelligence — collected, stored, and explored end to end.

---

## The Problem

Security teams need to track CVEs, but the public data is painful:
- Buried in deeply nested API responses across multiple CVSS versions
- Hard to filter, sort, and search across thousands of records
- Dense technical descriptions — not built for fast triage

**CVE Explorer solves this:** collect once, store clean, explore beautifully, and let AI explain what each vulnerability actually means.

---

## System Architecture

Four cooperating layers, one shared database.

| Layer | What it does | Stack |
|---|---|---|
| Data collection | Fetches CVEs from the NVD public API | Python stdlib |
| Data storage | SQLite — one row per CVE | SQLite |
| REST API | AI remediation, stats, trends, timelines | FastAPI + Azure OpenAI |
| React dashboard | Modern SPA for exploring CVEs visually | React + Vite |

Only the scraper writes. Every reader reads the same database — a reader can never corrupt the data.

---

## Data Collection

Fetches from the NVD public API. No API key. No pip installs — pure Python standard library.

**What we store per CVE:**
- CVE ID, title, full description
- Severity (LOW / MEDIUM / HIGH / CRITICAL) and CVSS score (0–10)
- Published and last-modified dates
- Affected vendors and products (parsed from CPE strings)

**Key features:**
- Safe to re-run — upsert on primary key, never duplicates
- Incremental updates with `--since` — only fetch what changed
- Auto rate-limit handling — pauses and retries on HTTP 429

---

## Data Storage — SQLite

A single self-contained file. No server. No setup.

- Trivially queryable from any language
- Rebuildable anytime by re-running the scraper
- Indexed on severity and CVSS score for fast filtering

---

## REST API

FastAPI service with auto-generated Swagger docs. Powers the React dashboard and any external integration.

**Key endpoints:**
- `GET /cves` — filter by severity, full-text search, date range, sort, paginate
- `GET /cves/{id}?remediation=true` — one CVE + AI fix recommendation
- `GET /cves/summary` — severity breakdown + 10 most dangerous CVEs
- `GET /cves/trending` — most recent CVEs by severity
- `GET /cves/timeline` — CVE counts by month, split by severity
- `GET /stats` — totals, average/max CVSS, per-severity counts

---

## AI-Powered Remediation

Integrates with Azure OpenAI to turn dense CVE descriptions into concise, actionable remediation steps.

- Results are cached — repeat lookups are instant and free
- The full system works without AI if no key is configured

---

## React Dashboard

A polished, Apple-inspired single-page app. The primary way humans explore CVE Explorer.

**Features:**
- Live severity cards — Critical / High / Medium / Low at a glance
- Instant debounced search — by CVE ID, keyword, or technology
- Filter and sort — by severity, alphabetically, by date
- Detail modals — full description, CVSS score bar, NVD link
- AI plain-English summaries — one click to understand any CVE
- "Ask GPT" — opens a ready-made remediation prompt in ChatGPT

---

## Challenges We Solved

- **Deeply nested NVD JSON** — severity and affected products required parsing across CVSS v2, v3.0, and v3.1
- **Rate limiting** — NVD caps unauthenticated requests at ~5/30s; handled with automatic backoff and retry
- **Incremental updates** — `--since` mode keeps the DB fresh without re-fetching everything
- **Making CVEs human-readable** — AI summaries turn jargon-heavy records into something a team can act on immediately

---

## Design Decisions

**Multiple front-ends, one source of truth.** React dashboard for exploration, FastAPI for integrations, stdlib UI for anywhere Python runs. All three read the same DB.

**Scraper writes; readers are read-only.** You can re-scrape while a front-end is live. No reader can corrupt the data.

**SQLite for storage.** No server to manage. Trivially portable. Queryable from any language.

**AI where it adds value.** Caching keeps it fast and cheap. The system is fully functional without it.

---

## Demo

1. Run the scraper → database fills with real, recent CVEs
2. Open the dashboard → live severity breakdown, filter to CRITICAL
3. Click a CVE → full detail modal with CVSS score bar
4. Hit "Explain in plain English" → AI turns jargon into a clear summary
5. Call the API → same data as JSON, ready for any integration
