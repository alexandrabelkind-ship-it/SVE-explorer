"""
CVE data sources.

Each source module exposes a single `fetch(...)` function that returns a list of
CVE dicts in our common flat shape (see SHAPE below). The orchestrator in
scrape.py calls each one and merges the results by cve_id.

Common shape (every source fills what it can; missing fields are None/""):

    {
        "cve_id":            "CVE-2024-1234",   # required, the merge key
        "title":             str,
        "description":       str,
        "severity":          "LOW|MEDIUM|HIGH|CRITICAL" | None,
        "cvss_score":        float | None,
        "published_date":    str (ISO),
        "last_modified":     str (ISO),
        "vendors":           "comma, separated",
        "products":          "comma, separated",
        "affected_packages": "ecosystem:name, ...",   # mainly from GHSA
        "ghsa_id":           "GHSA-xxxx-xxxx-xxxx" | None,
        "references":        "url, url, ...",
        "source":            "nvd" | "cveorg" | "ghsa",  # who produced this row
    }
"""

from . import nvd, cveorg, github_advisory  # noqa: F401

# Maps the --source CLI value to the module that implements it.
SOURCES = {
    "nvd": nvd,
    "cveorg": cveorg,
    "ghsa": github_advisory,
}
