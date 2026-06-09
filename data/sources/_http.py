"""
Tiny shared HTTP helper for all sources.

Stdlib only (urllib), so the scraper keeps its zero-dependency promise. Centralises
the User-Agent header and a simple rate-limit backoff so each source doesn't
re-implement it.
"""

import json
import time
import urllib.error
import urllib.request

USER_AGENT = "cve-explorer/2.0"


def get_json(url, headers=None, timeout=30, retries=1):
    """GET a URL and parse JSON. On HTTP 403/429 (rate limited), wait and retry.

    Returns the parsed JSON, or raises on a non-retryable error.
    """
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    attempt = 0
    while True:
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # 403/429 from public APIs almost always means "slow down".
            if e.code in (403, 429) and attempt < retries:
                wait = 30
                print(f"    Rate limited ({e.code}); waiting {wait}s then retrying...")
                time.sleep(wait)
                attempt += 1
                continue
            raise
