from __future__ import annotations
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from datetime import datetime, timedelta
import sqlite3
import os
import time
import json
import hashlib
import urllib.parse
import urllib.request
from dotenv import load_dotenv

load_dotenv()

from azure_client import AzureAIFoundryClient

def get_db_hash():
    db_path = "../data/cves.db"
    if os.path.exists(db_path):
        with open(db_path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    return None

db_hash = get_db_hash()

START_TIME = time.time()
ai_client = AzureAIFoundryClient()
DEPLOYMENT = "gpt-5.4"
remediation_cache: dict = {}

app = FastAPI(
    title="CVE Explorer API",
    description="API for exploring CVE vulnerability data with AI-powered remediation",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MOCK_CVES = [
    {"cve_id": "CVE-2024-1234", "title": "Apache Buffer Overflow", "description": "Buffer overflow in Apache HTTP Server allows remote code execution.", "severity": "CRITICAL", "cvss_score": 9.8, "published_date": "2024-01-15", "source": "nvd"},
    {"cve_id": "CVE-2024-5678", "title": "MySQL SQL Injection", "description": "SQL injection vulnerability in MySQL allows data exfiltration.", "severity": "HIGH", "cvss_score": 7.5, "published_date": "2024-02-20", "source": "nvd"},
    {"cve_id": "CVE-2024-9999", "title": "Nginx XSS", "description": "Cross-site scripting in nginx web server.", "severity": "MEDIUM", "cvss_score": 5.3, "published_date": "2024-03-10", "source": "ghsa"},
    {"cve_id": "CVE-2024-0001", "title": "OpenSSL Info Disclosure", "description": "Information disclosure in OpenSSL.", "severity": "LOW", "cvss_score": 2.1, "published_date": "2024-04-01", "source": "cveorg"},
    {"cve_id": "CVE-2024-3333", "title": "Log4j RCE", "description": "Remote code execution in Log4j library affects millions of systems.", "severity": "CRITICAL", "cvss_score": 10.0, "published_date": "2024-05-05", "source": "nvd,ghsa"},
]

def get_cves_from_source():
    db_path = "../data/cves.db"
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cves")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows], "sqlite"
    return MOCK_CVES, "mock"

def get_available_sources():
    """Get all unique sources from the DB."""
    db_path = "../data/cves.db"
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT source FROM cves WHERE source IS NOT NULL")
        rows = cursor.fetchall()
        conn.close()
        sources = set()
        for row in rows:
            if row[0]:
                for s in row[0].split(","):
                    sources.add(s.strip())
        return sorted(sources)
    return ["nvd", "ghsa", "cveorg"]

def generate_remediation(cve_id: str, description: str, severity: str) -> str:
    if cve_id in remediation_cache:
        print(f"[AI] Cache hit for {cve_id}")
        return remediation_cache[cve_id]
    try:
        print(f"[AI] Generating remediation for {cve_id}...")
        prompt = f"""You are a cybersecurity expert. Given the following CVE, provide a concise and practical remediation recommendation in 3-5 bullet points.

CVE ID: {cve_id}
Severity: {severity}
Description: {description}

Respond with ONLY the bullet points, no intro text. Each bullet should be actionable and specific."""
        result = ai_client.generate_completion(
            deployment_name=DEPLOYMENT,
            prompt=prompt,
            max_tokens=300,
            temperature=0.3,
        )
        print(f"[AI] Result: {result}")
        if result:
            remediation_cache[cve_id] = result
        return result or "Remediation could not be generated at this time."
    except Exception as e:
        print(f"[AI] ERROR: {str(e)}")
        return f"Remediation unavailable: {str(e)}"

@app.get("/")
def root():
    return {
        "message": "CVE Explorer API is running!",
        "docs": "/docs",
        "version": "3.0.0",
        "sources": get_available_sources()
    }

@app.get("/health")
def health():
    _, source = get_cves_from_source()
    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "data_source": source,
        "cached_remediations": len(remediation_cache),
        "db_hash": db_hash,
        "available_sources": get_available_sources(),
    }

@app.get("/stats")
def get_stats():
    cves, source = get_cves_from_source()
    scores = [c["cvss_score"] for c in cves if c.get("cvss_score") is not None]
    by_source = {}
    for cve in cves:
        src = cve.get("source") or "unknown"
        for s in src.split(","):
            s = s.strip()
            by_source[s] = by_source.get(s, 0) + 1
    return {
        "total": len(cves),
        "data_source": source,
        "average_cvss_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "max_cvss_score": max(scores) if scores else 0,
        "by_severity": {s: len([c for c in cves if c.get("severity") == s]) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "by_source": by_source,
    }

@app.get("/cache/stats")
def cache_stats():
    return {
        "cached_remediations": len(remediation_cache),
        "cached_cve_ids": list(remediation_cache.keys())
    }

@app.post("/refresh")
def refresh():
    global db_hash, remediation_cache
    new_hash = get_db_hash()
    if new_hash != db_hash:
        db_hash = new_hash
        remediation_cache.clear()
        cves, source = get_cves_from_source()
        return {"status": "refreshed", "total_cves": len(cves), "source": source}
    return {"status": "no_changes"}

@app.get("/cves")
def get_cves(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    source: Optional[str] = Query(None, description="Filter by source: nvd, ghsa, cveorg"),
    search: Optional[str] = Query(None, description="Search in CVE ID, title or description"),
    sort: Optional[str] = Query("date_desc", description="Sort: score_desc, score_asc, date_desc, date_asc"),
    from_date: Optional[str] = Query(None, description="Filter from date: YYYY-MM-DD"),
    to_date: Optional[str] = Query(None, description="Filter to date: YYYY-MM-DD"),
    vendor: Optional[str] = Query(None, description="Filter by vendor name"),
    limit: int = Query(50, description="Max results to return"),
    offset: int = Query(0, description="Pagination offset")
):
    cves, db_source = get_cves_from_source()

    if severity:
        cves = [c for c in cves if (c.get("severity") or "").upper() == severity.upper()]

    if source:
        cves = [c for c in cves if source.lower() in (c.get("source") or "").lower()]

    if vendor:
        cves = [c for c in cves if vendor.lower() in (c.get("vendors") or "").lower()]

    if search:
        cves = [c for c in cves if
                search.lower() in c["cve_id"].lower() or
                search.lower() in (c.get("title") or "").lower() or
                search.lower() in (c.get("description") or "").lower() or
                search.lower() in (c.get("vendors") or "").lower() or
                search.lower() in (c.get("products") or "").lower() or
                search.lower() in (c.get("affected_packages") or "").lower()]

    if from_date:
        cves = [c for c in cves if (c.get("published_date") or "") >= from_date]

    if to_date:
        cves = [c for c in cves if (c.get("published_date") or "") <= to_date]

    if sort == "score_desc":
        cves = sorted(cves, key=lambda x: x.get("cvss_score") or 0, reverse=True)
    elif sort == "score_asc":
        cves = sorted(cves, key=lambda x: x.get("cvss_score") or 0)
    elif sort == "date_asc":
        cves = sorted(cves, key=lambda x: x.get("published_date") or "")
    else:
        cves = sorted(cves, key=lambda x: x.get("published_date") or "", reverse=True)

    total = len(cves)
    cves = cves[offset:offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "data_source": db_source, "data": cves}

@app.get("/cves/summary")
def get_summary():
    cves, source = get_cves_from_source()
    total = len(cves)
    by_severity = {}
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len([c for c in cves if c.get("severity") == severity])
        by_severity[severity] = {
            "count": count,
            "percentage": round((count / total * 100), 1) if total > 0 else 0
        }
    top_10 = sorted(cves, key=lambda x: x.get("cvss_score") or 0, reverse=True)[:10]
    return {"total": total, "data_source": source, "by_severity": by_severity, "top_10_most_dangerous": top_10}

@app.get("/cves/trending")
def get_trending():
    cves, source = get_cves_from_source()
    sorted_by_date = sorted(cves, key=lambda x: x.get("published_date") or "", reverse=True)
    recent = sorted_by_date[:50]
    trending = sorted(recent, key=lambda x: x.get("cvss_score") or 0, reverse=True)
    return {"total": len(trending), "description": "Most recent CVEs sorted by severity", "data": trending}

@app.get("/cves/timeline")
def get_timeline():
    cves, source = get_cves_from_source()
    timeline = {}
    for cve in cves:
        date = cve.get("published_date", "")
        if date:
            month = date[:7]
            if month not in timeline:
                timeline[month] = {"month": month, "total": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            timeline[month]["total"] += 1
            severity = cve.get("severity", "")
            if severity in timeline[month]:
                timeline[month][severity] += 1
    sorted_timeline = sorted(timeline.values(), key=lambda x: x["month"])
    return {"total_months": len(sorted_timeline), "data": sorted_timeline}

@app.get("/cves/{cve_id}/similar")
def get_similar(cve_id: str):
    cves, _ = get_cves_from_source()
    target = None
    for cve in cves:
        if cve["cve_id"].upper() == cve_id.upper():
            target = cve
            break
    if not target:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    keywords = [w.lower() for w in (target.get("description") or "").split() if len(w) > 5]
    similar = []
    for cve in cves:
        if cve["cve_id"] == target["cve_id"]:
            continue
        desc = (cve.get("description") or "").lower()
        matches = sum(1 for k in keywords if k in desc)
        if matches >= 3:
            similar.append({**cve, "similarity_score": matches})
    similar = sorted(similar, key=lambda x: x["similarity_score"], reverse=True)[:10]
    return {"cve_id": cve_id, "total_similar": len(similar), "data": similar}

def fetch_ghsa_for_cve(cve_id: str) -> list:
    url = f"https://api.github.com/advisories?{urllib.parse.urlencode({'cve_id': cve_id})}"
    headers = {"User-Agent": "cve-explorer/2.0", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            advisories = json.loads(resp.read().decode("utf-8"))
        out = []
        for adv in advisories:
            packages = []
            for v in adv.get("vulnerabilities", []) or []:
                pkg = v.get("package") or {}
                if pkg.get("ecosystem") and pkg.get("name"):
                    packages.append(f"{pkg['ecosystem']}:{pkg['name']}")
            out.append({
                "ghsa_id": adv.get("ghsa_id"),
                "summary": adv.get("summary"),
                "severity": (adv.get("severity") or "").upper(),
                "packages": packages,
                "url": adv.get("html_url"),
            })
        return out
    except Exception as e:
        print(f"[explore] GHSA lookup failed for {cve_id}: {e}")
        return []

@app.get("/cves/{cve_id}/explore")
def explore_cve(cve_id: str):
    cid = cve_id.upper()
    return {
        "cve_id": cid,
        "sources": {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "cveorg": f"https://www.cve.org/CVERecord?id={cid}",
            "mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cid}",
        },
        "ghsa": fetch_ghsa_for_cve(cid),
        "web": [
            {"label": "Google", "url": f"https://www.google.com/search?q={urllib.parse.quote(cid)}"},
            {"label": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={urllib.parse.quote(cid)}"},
            {"label": "Exploit-DB", "url": f"https://www.exploit-db.com/search?cve={urllib.parse.quote(cid)}"},
        ],
    }

@app.get("/cves/{cve_id}")
def get_cve(cve_id: str, remediation: bool = Query(False, description="Include AI remediation recommendation")):
    cves, _ = get_cves_from_source()
    for cve in cves:
        if cve["cve_id"].upper() == cve_id.upper():
            result = dict(cve)
            if remediation:
                result["remediation"] = generate_remediation(
                    cve["cve_id"],
                    cve.get("description") or "",
                    cve.get("severity") or "UNKNOWN"
                )
            return result
    raise HTTPException(status_code=404, detail=f"{cve_id} not found")