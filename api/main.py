from __future__ import annotations
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import sqlite3
import os
import time
from dotenv import load_dotenv

load_dotenv()

from azure_client import AzureAIFoundryClient

START_TIME = time.time()
ai_client = AzureAIFoundryClient()
DEPLOYMENT = "gpt-5.4"

# Simple in-memory cache for AI remediation results
remediation_cache: dict = {}

app = FastAPI(
    title="CVE Explorer API",
    description="API for exploring CVE vulnerability data with AI-powered remediation",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MOCK_CVES = [
    {"cve_id": "CVE-2024-1234", "title": "Apache Buffer Overflow", "description": "Buffer overflow in Apache HTTP Server allows remote code execution.", "severity": "CRITICAL", "cvss_score": 9.8, "published_date": "2024-01-15"},
    {"cve_id": "CVE-2024-5678", "title": "MySQL SQL Injection", "description": "SQL injection vulnerability in MySQL allows data exfiltration.", "severity": "HIGH", "cvss_score": 7.5, "published_date": "2024-02-20"},
    {"cve_id": "CVE-2024-9999", "title": "Nginx XSS", "description": "Cross-site scripting in nginx web server.", "severity": "MEDIUM", "cvss_score": 5.3, "published_date": "2024-03-10"},
    {"cve_id": "CVE-2024-0001", "title": "OpenSSL Info Disclosure", "description": "Information disclosure in OpenSSL.", "severity": "LOW", "cvss_score": 2.1, "published_date": "2024-04-01"},
    {"cve_id": "CVE-2024-3333", "title": "Log4j RCE", "description": "Remote code execution in Log4j library affects millions of systems.", "severity": "CRITICAL", "cvss_score": 10.0, "published_date": "2024-05-05"},
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

def generate_remediation(cve_id: str, description: str, severity: str) -> str:
    # Check cache first
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
    return {"message": "CVE Explorer API is running!", "docs": "/docs", "version": "2.0.0"}

@app.get("/health")
def health():
    _, source = get_cves_from_source()
    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "data_source": source,
        "cached_remediations": len(remediation_cache),
    }

@app.get("/cves")
def get_cves(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    search: Optional[str] = Query(None, description="Search in CVE ID, title or description"),
    sort: Optional[str] = Query("date_desc", description="Sort: score_desc, score_asc, date_desc, date_asc"),
    from_date: Optional[str] = Query(None, description="Filter from date: YYYY-MM-DD"),
    to_date: Optional[str] = Query(None, description="Filter to date: YYYY-MM-DD"),
    limit: int = Query(50, description="Max results to return"),
    offset: int = Query(0, description="Pagination offset")
):
    cves, source = get_cves_from_source()

    if severity:
        cves = [c for c in cves if c["severity"].upper() == severity.upper()]

    if search:
        cves = [c for c in cves if
                search.lower() in c["cve_id"].lower() or
                search.lower() in c.get("title", "").lower() or
                search.lower() in c["description"].lower()]

    if from_date:
        cves = [c for c in cves if c["published_date"] >= from_date]

    if to_date:
        cves = [c for c in cves if c["published_date"] <= to_date]

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

    return {"total": total, "offset": offset, "limit": limit, "data_source": source, "data": cves}

@app.get("/cves/summary")
def get_summary():
    cves, source = get_cves_from_source()
    total = len(cves)
    by_severity = {}
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = len([c for c in cves if c["severity"] == severity])
        by_severity[severity] = {
            "count": count,
            "percentage": round((count / total * 100), 1) if total > 0 else 0
        }
    top_10 = sorted(cves, key=lambda x: x.get("cvss_score") or 0, reverse=True)[:10]
    return {"total": total, "data_source": source, "by_severity": by_severity, "top_10_most_dangerous": top_10}

@app.get("/cves/{cve_id}")
def get_cve(cve_id: str, remediation: bool = Query(False, description="Include AI remediation recommendation")):
    cves, _ = get_cves_from_source()
    for cve in cves:
        if cve["cve_id"].upper() == cve_id.upper():
            result = dict(cve)
            if remediation:
                result["remediation"] = generate_remediation(
                    cve["cve_id"],
                    cve["description"],
                    cve["severity"]
                )
            return result
    raise HTTPException(status_code=404, detail=f"{cve_id} not found")

@app.get("/stats")
def get_stats():
    cves, source = get_cves_from_source()
    scores = [c["cvss_score"] for c in cves if c.get("cvss_score") is not None]
    return {
        "total": len(cves),
        "data_source": source,
        "average_cvss_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "max_cvss_score": max(scores) if scores else 0,
        "by_severity": {s: len([c for c in cves if c["severity"] == s]) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    }

@app.get("/cache/stats")
def cache_stats():
    return {
        "cached_remediations": len(remediation_cache),
        "cached_cve_ids": list(remediation_cache.keys())
    }