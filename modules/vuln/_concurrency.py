"""Shared concurrency helper for the vuln scanners (xss/sqli/ssrf/lfi/open_redirect).

Each scanner's request volume comes from an outer loop over independent units
(a query param, a form field) that used to run strictly sequentially even
though the units share nothing and can safely run at once — this is what made
those scanners slow relative to modules/recon/port_scanner.py, which already
parallelizes its own independent per-port probes.
"""

from concurrent.futures import ThreadPoolExecutor

from config import VULN_SCAN_CONCURRENCY


def run_concurrent_scan(items, worker, max_workers: int = VULN_SCAN_CONCURRENCY) -> list:
    """Run `worker(item)` across `items` concurrently and flatten the results.

    Each `worker` call returns a list (possibly empty) of finding dicts for
    that one item; order across items is not preserved (callers already
    dedupe/sort findings downstream, same as before this existed).
    """
    items = list(items)
    if not items:
        return []
    results = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(items))) as ex:
        for out in ex.map(worker, items):
            if out:
                results.extend(out)
    return results
