"""
NVD source — the National Vulnerability Database public API.

This is the baseline feed: broad coverage, CVSS scores, and CPE-derived
vendor/product lists. No API key required.
"""

import time
import urllib.parse
from datetime import datetime, timezone

from ._http import get_json

NAME = "nvd"
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 200  # NVD caps each request at 2000; we page in smaller chunks.


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _fetch_page(start_index, page_size, since=None, until=None):
    query = {"resultsPerPage": page_size, "startIndex": start_index}
    if since:
        # NVD needs both ends of the modified-date window (max 120 days apart).
        query["lastModStartDate"] = since
        query["lastModEndDate"] = until or _now_iso()
    url = f"{API_URL}?{urllib.parse.urlencode(query)}"
    return get_json(url, retries=1)


def _parse(item):
    """Turn one raw NVD record into our common flat shape."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    title = description.split(". ")[0][:120] if description else cve_id

    # CVSS lives under metrics; try v3.1, then v3.0, then v2.
    severity = None
    cvss_score = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            cvss_score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break

    # Affected software from CPE strings: cpe:2.3:a:VENDOR:PRODUCT:VERSION:...
    vendors, products = set(), set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    if vendor and vendor != "*":
                        vendors.add(vendor.replace("_", " "))
                    if product and product != "*":
                        products.add(product.replace("_", " "))

    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

    return {
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "severity": severity.upper() if severity else None,
        "cvss_score": cvss_score,
        "published_date": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vendors": ", ".join(sorted(vendors)),
        "products": ", ".join(sorted(products)),
        "affected_packages": "",
        "ghsa_id": None,
        "references": ", ".join(refs[:10]),
        "source": NAME,
    }


def fetch(count=200, since=None, **_):
    """Fetch up to `count` CVEs from NVD. Yields dicts in the common shape.

    If `since` (ISO date) is given, only CVEs modified since then are returned.
    """
    rows = []
    fetched = 0
    start_index = 0
    while fetched < count:
        page_size = min(PAGE_SIZE, count - fetched)
        where = f" modified since {since[:10]}" if since else ""
        print(f"  [nvd] fetching {page_size} at index {start_index}{where}...")
        data = _fetch_page(start_index, page_size, since=since)

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print("  [nvd] no more results.")
            break

        page = [_parse(v) for v in vulns]
        rows.extend(page)
        fetched += len(page)
        start_index += len(page)
        print(f"  [nvd] got {len(page)} (total {fetched}).")

        if fetched < count:
            time.sleep(6)  # be polite: NVD allows ~5 req / 30s without a key.
    return rows
