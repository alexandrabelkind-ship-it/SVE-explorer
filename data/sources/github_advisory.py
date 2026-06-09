"""
GitHub Advisory Database source (GHSA).

GitHub curates security advisories and maps them to *affected packages* across
ecosystems (npm, PyPI, Maven, Go, ...) — information NVD doesn't carry. We pull
the public /advisories feed unauthenticated (60 requests/hour) and key each
advisory to its CVE ID where one exists.

If a GH_TOKEN / GITHUB_TOKEN env var is present we'll use it for the higher rate
limit, but it is not required.
"""

import os
import time
import urllib.parse

from ._http import get_json

NAME = "ghsa"
API_URL = "https://api.github.com/advisories"
PAGE_SIZE = 100  # GitHub's max per_page for this endpoint.

# GHSA severities are lower-case; normalise to our scale.
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "low": "LOW",
}


def _auth_headers():
    token = os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28"}
    return {"X-GitHub-Api-Version": "2022-11-28"}


def _parse(adv):
    """Map one GitHub advisory to our common shape. Returns None if it has no CVE."""
    cve_id = adv.get("cve_id")
    if not cve_id:
        return None  # GHSA-only advisories don't fit our CVE-keyed table.

    cvss = adv.get("cvss") or {}
    sev = (adv.get("severity") or "").lower()

    packages = []
    for v in adv.get("vulnerabilities", []) or []:
        pkg = (v.get("package") or {})
        eco, name = pkg.get("ecosystem"), pkg.get("name")
        if eco and name:
            packages.append(f"{eco}:{name}")

    refs = [r for r in (adv.get("references") or []) if r]
    if adv.get("html_url"):
        refs.insert(0, adv["html_url"])

    return {
        "cve_id": cve_id,
        "title": adv.get("summary", "")[:120],
        "description": adv.get("description") or adv.get("summary", ""),
        "severity": _SEVERITY_MAP.get(sev),
        "cvss_score": cvss.get("score"),
        "published_date": adv.get("published_at", ""),
        "last_modified": adv.get("updated_at", ""),
        "vendors": "",
        "products": "",
        "affected_packages": ", ".join(sorted(set(packages))),
        "ghsa_id": adv.get("ghsa_id"),
        "references": ", ".join(refs[:10]),
        "source": NAME,
    }


def fetch(count=200, **_):
    """Fetch recent GitHub advisories that carry a CVE ID. Common-shape dicts.

    Pages through the public feed (most recent first) until `count` CVE-bearing
    advisories are collected or the feed is exhausted.
    """
    rows = []
    page = 1
    headers = _auth_headers()
    authed = "Authorization" in headers
    print(f"  [ghsa] fetching advisories ({'authenticated' if authed else 'unauthenticated, 60/hr'})...")

    while len(rows) < count:
        query = urllib.parse.urlencode({
            "per_page": PAGE_SIZE,
            "page": page,
            "sort": "published",
            "direction": "desc",
            "type": "reviewed",
        })
        batch = get_json(f"{API_URL}?{query}", headers=headers, retries=1)
        if not batch:
            print("  [ghsa] no more results.")
            break

        for adv in batch:
            parsed = _parse(adv)
            if parsed:
                rows.append(parsed)
        print(f"  [ghsa] page {page}: {len(rows)} CVE-bearing advisories so far.")
        page += 1
        if len(batch) < PAGE_SIZE:
            break
        time.sleep(2)  # spread out unauthenticated calls.

    return rows[:count]
