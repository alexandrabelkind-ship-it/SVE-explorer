"""
CVE.org source — MITRE's authoritative CVE Services (CVE JSON 5.0).

This is the *authoritative* record straight from the CVE Numbering Authority.
It often has a description before NVD finishes enriching a CVE, so we use it to
fill in or freshen descriptions and references. No API key required.

Because CVE Services has no "list recent" feed that's friendly to scrape, this
source works in *enrich* mode: given a list of CVE IDs (typically the ones NVD or
GHSA already produced), it looks each one up and returns the authoritative fields.
"""

import time

from ._http import get_json

NAME = "cveorg"
API_URL = "https://cveawg.mitre.org/api/cve"  # /{CVE-ID}


def _parse(record):
    """Extract our common fields from one CVE JSON 5.0 record."""
    meta = record.get("cveMetadata", {})
    cve_id = meta.get("cveId", "")
    containers = record.get("containers", {})
    cna = containers.get("cna", {})

    description = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            description = d.get("value", "")
            break

    title = cna.get("title") or (description.split(". ")[0][:120] if description else cve_id)

    # CVSS can live in the CNA metrics or in ADP (enrichment) containers.
    severity, cvss_score = None, None

    def _read_metrics(metrics):
        for m in metrics or []:
            for ver in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
                if ver in m:
                    return m[ver].get("baseScore"), m[ver].get("baseSeverity")
        return None, None

    cvss_score, severity = _read_metrics(cna.get("metrics"))
    if cvss_score is None:
        for adp in containers.get("adp", []):
            cvss_score, severity = _read_metrics(adp.get("metrics"))
            if cvss_score is not None:
                break

    vendors, products = set(), set()
    for aff in cna.get("affected", []):
        if aff.get("vendor") and aff["vendor"] not in ("n/a", "*"):
            vendors.add(aff["vendor"])
        if aff.get("product") and aff["product"] not in ("n/a", "*"):
            products.add(aff["product"])

    refs = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]

    return {
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "severity": severity.upper() if severity else None,
        "cvss_score": cvss_score,
        "published_date": meta.get("datePublished", ""),
        "last_modified": meta.get("dateUpdated", ""),
        "vendors": ", ".join(sorted(vendors)),
        "products": ", ".join(sorted(products)),
        "affected_packages": "",
        "ghsa_id": None,
        "references": ", ".join(refs[:10]),
        "source": NAME,
    }


def fetch(cve_ids=None, **_):
    """Look up each CVE ID against CVE Services. Returns dicts in the common shape.

    `cve_ids` is an iterable of IDs to enrich (usually from NVD/GHSA). Records that
    404 or fail are skipped — CVE.org won't have every reserved ID.
    """
    rows = []
    ids = list(cve_ids or [])
    if not ids:
        print("  [cveorg] no CVE IDs to enrich; skipping.")
        return rows

    print(f"  [cveorg] enriching {len(ids)} CVE(s) from the authoritative record...")
    for i, cve_id in enumerate(ids, 1):
        try:
            record = get_json(f"{API_URL}/{cve_id}", retries=1)
            rows.append(_parse(record))
        except Exception as e:  # 404s and transient errors are expected; skip.
            print(f"  [cveorg] skip {cve_id}: {e}")
        if i % 25 == 0:
            print(f"  [cveorg] {i}/{len(ids)}...")
        time.sleep(0.3)  # gentle pacing against the public service.
    print(f"  [cveorg] enriched {len(rows)}.")
    return rows
