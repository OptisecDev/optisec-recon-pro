"""IOC Detection Engine — Phase 1 architecture (design + interface only).

Wraps the existing threat-intel clients (modules.threat_intel.ioc_detector,
modules.threat_intel.otx_feed) behind one check/enrich/extract API. This is
a *different* concern from modules/ioc_correlation.py behind the existing
/correlations page: that module correlates global threat-feed IOCs against
each other, while this engine checks/stores IOCs tied to this installation
(manual lookups + IOCs mined from its own scan findings).

IOCEngine does not talk to a real database yet. It works against an
injectable repository (default: IOCRepository, an in-memory dict) so it can
be re-pointed at web.models.Ioc (see web/models.py) once that table exists
in production — see migrations/README_ioc_migration.md for how that table
gets created. Swapping in a DB-backed repository later should not require
changing IOCEngine's public methods, only the repository implementation.

External API calls (VirusTotal, AbuseIPDB, OTX) are also injectable via
`source_clients`, defaulting to thin wrappers around the real clients in
modules.threat_intel.ioc_detector / otx_feed. IntelligenceX and LeakCheck
are async in this codebase (modules.osint.darkweb_intelligence,
modules.osint.unified_engine) and are better suited to breach/leak lookups
than IP/domain/hash reputation — rather than making this engine async too,
callers fetch those results ahead of time and pass them into enrich_ioc()
via `additional_sources`.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional
from urllib.parse import urlparse

IOC_TYPES = frozenset({"hash_md5", "hash_sha256", "ip", "domain", "url", "email"})

# Relative trust weight per source, used to blend multiple lookups into one
# confidence_score in enrich_ioc(). Mirrors the per-type weighting already
# used in modules/ioc_correlation.py::_TYPE_WEIGHT for the same reason: not
# every source is equally reliable, so a naive average would be misleading.
_SOURCE_WEIGHT = {
    "virustotal": 1.0,
    "abuseipdb": 0.9,
    "otx": 0.85,
    "intelligencex": 0.6,
    "leakcheck": 0.6,
    "manual": 0.5,
    "scan_finding": 0.4,
}

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_HASH_LENGTHS = {"hash_md5": 32, "hash_sha256": 64}


@dataclass
class IOCCheckResult:
    """Normalized result of a single-source IOC lookup."""

    ioc_type: str
    value: str
    source: str
    verdict: str  # CLEAN | SUSPICIOUS | MALICIOUS | CRITICAL | UNKNOWN | NOT_FOUND
    score: float  # 0-100, as reported by the source
    raw: dict = field(default_factory=dict)


class IOCRepository:
    """In-memory stand-in for the future repository over web.models.Ioc.

    Same method shapes (get/upsert/list_active) the real DB-backed
    implementation will need, so swapping this out once the `iocs` table
    exists (see migrations/README_ioc_migration.md) is a constructor-arg
    change to IOCEngine, not a rewrite of its logic.
    """

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], dict] = {}

    def get(self, ioc_type: str, ioc_value: str) -> Optional[dict]:
        return self._store.get((ioc_type, ioc_value))

    def upsert(self, ioc_type: str, ioc_value: str, **fields: Any) -> dict:
        key = (ioc_type, ioc_value)
        now = datetime.utcnow()
        existing = self._store.get(key)
        if existing is not None:
            existing.update(fields)
            existing["last_seen"] = now
            return existing

        record = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "source": fields.get("source", "manual"),
            "confidence_score": 0.0,
            "first_seen": now,
            "last_seen": now,
            "related_finding_id": None,
            "tags": [],
            "is_active": True,
        }
        record.update(fields)
        self._store[key] = record
        return record

    def list_active(self, ioc_type: Optional[str] = None) -> list[dict]:
        return [
            r for r in self._store.values()
            if r["is_active"] and (ioc_type is None or r["ioc_type"] == ioc_type)
        ]


def _default_source_clients() -> dict[str, Callable]:
    from modules.threat_intel import ioc_detector

    return {
        "virustotal_domain": ioc_detector.check_domain,
        "virustotal_hash": ioc_detector.check_hash,
        "abuseipdb_ip": ioc_detector.check_ip,
    }


class IOCEngine:
    def __init__(
        self,
        repository: Optional[IOCRepository] = None,
        source_clients: Optional[dict[str, Callable]] = None,
    ) -> None:
        self.repository = repository or IOCRepository()
        self.source_clients = {**_default_source_clients(), **(source_clients or {})}

    def _safe_call(self, client_name: str, value: str) -> dict:
        client = self.source_clients.get(client_name)
        if client is None:
            return {}
        try:
            return client(value) or {}
        except Exception:
            # Source clients (modules.threat_intel.ioc_detector) already
            # catch their own network errors internally and never raise —
            # this is a last-resort guard for injected test/mocked clients.
            return {}

    def check_ioc(self, value: str, ioc_type: str) -> IOCCheckResult:
        """Check a single IOC against the one source most relevant to its
        type (AbuseIPDB for ip, VirusTotal for domain/hash/url). For
        multi-source enrichment use enrich_ioc() instead."""
        if ioc_type not in IOC_TYPES:
            raise ValueError(f"Unsupported ioc_type: {ioc_type!r}, expected one of {sorted(IOC_TYPES)}")
        value = (value or "").strip()
        if not value:
            raise ValueError("ioc value must not be empty")

        if ioc_type == "ip":
            raw = self._safe_call("abuseipdb_ip", value)
            source = "abuseipdb"
        elif ioc_type == "domain":
            raw = self._safe_call("virustotal_domain", value)
            source = "virustotal"
        elif ioc_type in _HASH_LENGTHS:
            raw = self._safe_call("virustotal_hash", value)
            source = "virustotal"
        elif ioc_type == "url":
            domain = urlparse(value).netloc.split(":")[0] or value
            raw = self._safe_call("virustotal_domain", domain)
            source = "virustotal"
        else:  # email — no reputation feed checks this directly; see enrich_ioc()
            raw = {}
            source = "manual"

        return IOCCheckResult(
            ioc_type=ioc_type,
            value=value,
            source=source,
            verdict=raw.get("verdict", "UNKNOWN"),
            score=float(raw.get("score", 0) or 0),
            raw=raw,
        )

    def enrich_ioc(
        self,
        value: str,
        ioc_type: str,
        *,
        additional_sources: Optional[dict[str, dict]] = None,
    ) -> dict:
        """Combine check_ioc() with pre-fetched results from other sources
        into one unified confidence_score (0-100, weighted by _SOURCE_WEIGHT)
        and upsert the merged record into self.repository.

        additional_sources: raw result dicts keyed by source name (e.g.
        "otx" from modules.threat_intel.otx_feed.fetch_otx_pulses,
        "intelligencex"/"leakcheck" from modules.osint.darkweb_intelligence /
        unified_engine). Those clients are async and rate/cache-sensitive
        (see otx_feed._CACHE) — this engine stays synchronous, so callers
        fetch once and pass the relevant matched result in here rather than
        this method awaiting them itself.
        """
        primary = self.check_ioc(value, ioc_type)
        weighted = [(primary.score, _SOURCE_WEIGHT.get(primary.source, 0.5))]
        sources_consulted = [primary.source]
        raw_by_source = {primary.source: primary.raw}
        tags: list[str] = []

        for source_name, raw in (additional_sources or {}).items():
            if not raw:
                continue
            weight = _SOURCE_WEIGHT.get(source_name, 0.5)
            score = float(raw.get("score", raw.get("threat_score", 0)) or 0)
            weighted.append((score, weight))
            sources_consulted.append(source_name)
            raw_by_source[source_name] = raw
            if raw.get("malware"):
                tags.append(f"malware_family:{raw['malware']}")
            if raw.get("adversary"):
                tags.append(f"campaign:{raw['adversary']}")

        weight_total = sum(w for _, w in weighted) or 1.0
        confidence_score = round(sum(s * w for s, w in weighted) / weight_total, 2)

        record = {
            "ioc_type": ioc_type,
            "ioc_value": value,
            "source": primary.source,
            "confidence_score": confidence_score,
            "sources_consulted": sources_consulted,
            "tags": tags,
            "verdict": primary.verdict,
            "raw": raw_by_source,
        }
        self.repository.upsert(
            ioc_type, value,
            source=primary.source,
            confidence_score=confidence_score,
            tags=tags,
        )
        return record

    def extract_iocs_from_finding(self, finding: dict) -> list[dict]:
        """Mine a scanner finding dict (same shape as web.models.Finding /
        the vuln dicts produced by modules/vuln/*.py: vuln_type, url,
        parameter, payload, evidence) for candidate external-infrastructure
        IOCs — e.g. an Open Redirect's external Location header captured in
        `evidence`.

        Deliberately does NOT mine:
        - finding['url']: always the *scanned target's own* domain plus our
          injected payload (see modules/vuln/ssrf.py, open_redirect.py) —
          never attacker infrastructure.
        - finding['payload']: for SSRF this is one of the fixed internal/
          metadata probe strings we send (127.0.0.1, 169.254.169.254, ...)
          — our own test data, not an observed indicator.
        Only `evidence` (what the target actually did/returned) is scanned.

        Returns a list of candidate dicts shaped like web.models.Ioc columns
        (ioc_type, ioc_value, source="scan_finding", related_finding_id,
        tags), not yet persisted — pass each to enrich_ioc()/repository
        yourself to store it.
        """
        evidence = finding.get("evidence") or ""
        finding_id = finding.get("id")
        vuln_type = finding.get("vuln_type")
        own_host = urlparse(finding.get("url") or "").netloc.split(":")[0]

        candidates: dict[tuple[str, str], dict] = {}

        for url in _URL_RE.findall(evidence):
            host = urlparse(url).netloc.split(":")[0]
            if not host or host == own_host or _is_local_host(host):
                continue
            candidates[("url", url)] = _candidate("url", url, finding_id, vuln_type)
            if _IPV4_RE.fullmatch(host):
                candidates[("ip", host)] = _candidate("ip", host, finding_id, vuln_type)
            else:
                candidates[("domain", host)] = _candidate("domain", host, finding_id, vuln_type)

        for ip in _IPV4_RE.findall(evidence):
            if ip != own_host and not _is_local_host(ip):
                candidates[("ip", ip)] = _candidate("ip", ip, finding_id, vuln_type)

        return list(candidates.values())


def _candidate(ioc_type: str, value: str, finding_id: Any, vuln_type: Optional[str]) -> dict:
    return {
        "ioc_type": ioc_type,
        "ioc_value": value,
        "source": "scan_finding",
        "related_finding_id": finding_id,
        "tags": [f"vuln_type:{vuln_type}"] if vuln_type else [],
    }


def _is_local_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return host in {"localhost"} or host.endswith(".local")
