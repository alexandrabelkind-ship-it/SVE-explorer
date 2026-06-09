from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import sqlite3
import os
import time

START_TIME = time.time()

app = FastAPI(
    title="CVE Explorer API",
    description="API for exploring CVE vulnerability data",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MOCK_CVES = [
    {"cve_id": "CVE-2024-1234", "description": "Buffer overflow in Apache HTTP Server allows remote code execution.", "severity": "CRITICAL", "cvss_score": 9.8, "published_date": "2024-01-15"},
    {"cve_id": "CVE-2024-5678", "description": "SQL injection vulnerability in MySQL allows data exfiltration.", "severity": "HIGH", "cvss_score": 7.5, "published_date": "2024-02-20"},
    {"cve_id": "CVE-2024-9999", "description": "Cross-site scripting in nginx web server.", "severity": "MEDIUM", "cvss_score": 5.3, "published_date": "2024-03-10"},
    {"cve_id": "CVE-2024-0001", "description": "Information disclosure in OpenSSL.", "severity": "LOW", "cvss_score": 2.1, "published_date": "2024-04-01"},
    {"cve_id": "CVE-2024-3333", "description": "Remote code execution in Log4j library affects millions of systems.", "severity": "CRITICAL", "cvss_score": 10.0, "published_date": "2024-05-05"},
]

def get_cves_from_source():
    db_path = "../cve.db"
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cves")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows], "sqlite"
    return MOCK_CVES, "mock"

@app.get("/")
def root():
    return {"message": "CVE Explorer API is running!", "docs": "/docs", "version": "1.0.0"}

@app.get("/health")
def health():
    _, source = get_cves_from_source()
    return {
        "status": "healthy",
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "data_source": source,
    }

@app.get("/cves")
def get_cves(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    search: Optional[str] = Query(None, description="Search in CVE ID or description"),
    limit: int = Query(50, description="Max results to return"),
    offset: int = Query(0, description="Pagination offset")
):
    cves, source = get_cves_from_source()

    if severity:
        cves = [c for c in cves if c["severity"].upper() == severity.upper()]

    if search:
        cves = [c for c in cves if
                search.lower() in c["cve_id"].lower() or
                search.lower() in c["description"].lower()]

    total = len(cves)
    cves = cves[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "data_source": source,
        "data": cves
    }

@app.get("/cves/{cve_id}")
def get_cve(cve_id: str):
    cves, _ = get_cves_from_source()
    for cve in cves:
        if cve["cve_id"].upper() == cve_id.upper():
            return cve
    raise HTTPException(status_code=404, detail=f"{cve_id} not found")

@app.get("/stats")
def get_stats():
    cves, source = get_cves_from_source()
    stats = {
        "total": len(cves),
        "data_source": source,
        "by_severity": {}
    }
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        stats["by_severity"][severity] = len([c for c in cves if c["severity"] == severity])
    return stats