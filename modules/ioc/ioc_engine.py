"""IOC Detection Engine — Phase 2: real database-backed repository.

Wraps the existing threat-intel clients (modules.threat_intel.ioc_detector,
modules.threat_intel.otx_feed) behind one check/enrich/extract API. This is
a *different* concern from modules/ioc_correlation.py behind the existing
/correlations page: that module correlates global threat-feed IOCs against
each other, while this engine checks/stores IOCs tied to this installation
(manual lookups + IOCs mined from its own scan findings).

IOCRepository is now backed by web.models.Ioc via an injected AsyncSession
(same session/transaction ownership convention as every other router in
this codebase, e.g. web/routers/honeypot.py, web/routers/darkweb_monitor.py
— the repository adds/flushes, the caller commits). The whole app's DB
layer is async-only (web/database.py's SessionLocal is an
async_sessionmaker), so enrich_ioc() — the only method that persists — is
async too; check_ioc() and extract_iocs_from_finding() touch no DB and stay
synchronous, unchanged from Phase 1.

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

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from sqlalchemy import select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from web.models import Ioc

logger = logging.getLogger(__name__)

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
    """Repository over web.models.Ioc, backed by an injected AsyncSession.

    One row per unique (ioc_type, ioc_value) — see the UniqueConstraint on
    web.models.Ioc. Like every other router's DB access in this codebase
    (web/routers/honeypot.py::query_events, darkweb_monitor.py, etc.), this
    repository only db.add()/flush()es; committing the transaction is the
    caller's responsibility so multiple upserts (e.g. one scan's worth of
    mined IOCs) can share a single commit.
    """

    def __init__(self, db: "AsyncSession") -> None:
        self.db = db

    async def get_by_value(self, ioc_type: str, ioc_value: str) -> Optional["Ioc"]:
        from web.models import Ioc

        stmt = select(Ioc).where(Ioc.ioc_type == ioc_type, Ioc.ioc_value == ioc_value)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, ioc_type: str, ioc_value: str, **fields: Any) -> "Ioc":
        from web.models import Ioc

        now = datetime.utcnow()
        row = Ioc(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            source=fields.get("source", "manual"),
            confidence_score=fields.get("confidence_score", 0.0),
            first_seen=now,
            last_seen=now,
            related_finding_id=fields.get("related_finding_id"),
            tags=fields.get("tags") or [],
            is_active=fields.get("is_active", True),
        )
        self.db.add(row)
        await self.db.flush()
        return row

    async def update_last_seen(self, row: "Ioc", **fields: Any) -> "Ioc":
        for key, value in fields.items():
            if key in ("ioc_type", "ioc_value", "id", "first_seen"):
                continue  # identity/immutable columns — never overwritten by an upsert
            if hasattr(row, key):
                setattr(row, key, value)
        row.last_seen = datetime.utcnow()
        await self.db.flush()
        return row

    async def list_active(
        self,
        ioc_type: Optional[str] = None,
        is_active: Optional[bool] = True,
        limit: int = 50,
        offset: int = 0,
    ) -> list["Ioc"]:
        from web.models import Ioc

        stmt = select(Ioc)
        if ioc_type is not None:
            stmt = stmt.where(Ioc.ioc_type == ioc_type)
        if is_active is not None:
            stmt = stmt.where(Ioc.is_active == is_active)
        stmt = stmt.order_by(Ioc.last_seen.desc()).limit(max(1, min(limit, 200))).offset(max(0, offset))
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def upsert(self, ioc_type: str, ioc_value: str, **fields: Any) -> "Ioc":
        existing = await self.get_by_value(ioc_type, ioc_value)
        if existing is not None:
            return await self.update_last_seen(existing, **fields)
        return await self.create(ioc_type, ioc_value, **fields)

    async def search(
        self,
        query: str,
        ioc_type: Optional[str] = None,
        is_active: Optional[bool] = True,
        limit: int = 50,
    ) -> list["Ioc"]:
        """Substring match on ioc_value (case-insensitive), unlike
        list_active()'s exact ioc_type/is_active filtering — for looking up
        "does anything like this domain/ip exist" rather than an exact key
        lookup (that's get_by_value)."""
        from web.models import Ioc

        stmt = select(Ioc).where(Ioc.ioc_value.ilike(f"%{query}%"))
        if ioc_type is not None:
            stmt = stmt.where(Ioc.ioc_type == ioc_type)
        if is_active is not None:
            stmt = stmt.where(Ioc.is_active == is_active)
        stmt = stmt.order_by(Ioc.last_seen.desc()).limit(max(1, min(limit, 200)))
        result = await self.db.execute(stmt)
        return list(result.scalars().all())


def _default_source_clients() -> dict[str, Callable]:
    from modules.threat_intel import ioc_detector

    return {
        "virustotal_domain": ioc_detector.check_domain,
        "virustotal_hash": ioc_detector.check_hash,
        "abuseipdb_ip": ioc_detector.check_ip,
        "otx_pulses": _default_otx_pulses_client,
    }


def _default_otx_pulses_client(limit: int) -> list[dict]:
    """Default `otx_pulses` source client for sync_from_otx(). Mirrors the
    `if OTX_API_KEY: ...` gate already used by web/routers/threat_feed.py
    and web/routers/threat_sharing.py — returns [] (not an error) when no
    key is configured, so sync_from_otx() degrades to a no-op sweep rather
    than failing."""
    import config
    from modules.threat_intel.otx_feed import fetch_otx_pulses

    if not config.OTX_API_KEY:
        return []
    return fetch_otx_pulses(config.OTX_API_KEY, limit=limit)


class IOCEngine:
    def __init__(
        self,
        repository: Optional[IOCRepository] = None,
        source_clients: Optional[dict[str, Callable]] = None,
    ) -> None:
        # No default in-memory repository anymore (Phase 1) — a real
        # repository needs a live AsyncSession, which only the caller has.
        # None is valid: check_ioc()/extract_iocs_from_finding() need no DB
        # at all, and enrich_ioc() simply skips persistence when unset.
        self.repository = repository
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

    async def enrich_ioc(
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

        This method is async (unlike check_ioc/extract_iocs_from_finding)
        purely because persisting into self.repository now means a real
        AsyncSession query/flush — the scoring/blending logic above stays
        plain sync code.
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
        if self.repository is not None:
            await self.repository.upsert(
                ioc_type, value,
                source=primary.source,
                confidence_score=confidence_score,
                tags=tags,
            )
        return record

    async def sync_from_otx(self, limit: int = 100) -> dict:
        """Fetch the latest AlienVault OTX pulse indicators (via the
        injectable `otx_pulses` source client, defaulting to
        modules.threat_intel.otx_feed.fetch_otx_pulses) and upsert each into
        self.repository as a local Ioc row (source="otx").

        OTX indicator types this engine's local store doesn't model (CVE,
        CIDR, Mutex, filepath, YARA, FileHash-SHA1/SHA512 — see
        otx_feed._TYPE_MAP) are counted in `skipped` and dropped rather than
        raising, since IOC_TYPES intentionally covers only the six types
        this table/engine understands.

        fetch_otx_pulses is a blocking `requests` call, so it's run via
        asyncio.to_thread — same pattern web/routers/threat_feed.py and
        threat_sharing.py already use to keep it off the event loop. Never
        raises: a network failure is logged and returned as an all-zero
        summary with an "error" key, so a bad OTX response can't take down
        a caller (a router request or the periodic scheduler sweep).
        """
        client = self.source_clients.get("otx_pulses")
        if client is None:
            return {"fetched": 0, "stored": 0, "skipped": 0, "error": "otx_pulses client not configured"}

        try:
            pulses = await asyncio.to_thread(client, limit)
        except Exception as exc:
            logger.warning("OTX sync: fetch failed: %s", exc)
            return {"fetched": 0, "stored": 0, "skipped": 0, "error": "fetch_failed"}

        pulses = pulses or []
        stored = 0
        skipped = 0
        for item in pulses:
            ioc_type = item.get("type")
            value = item.get("value")
            if ioc_type not in IOC_TYPES or not value:
                skipped += 1
                continue

            tags = []
            if item.get("pulse_name"):
                tags.append(f"pulse:{item['pulse_name']}")
            if item.get("adversary"):
                tags.append(f"campaign:{item['adversary']}")

            if self.repository is not None:
                await self.repository.upsert(
                    ioc_type, value,
                    source="otx",
                    confidence_score=float(item.get("threat_score", 0) or 0),
                    tags=tags,
                )
                stored += 1

        return {"fetched": len(pulses), "stored": stored, "skipped": skipped}

    async def match_scan_results(self, findings: list[dict]) -> list[dict]:
        """Correlate a scan's findings against the local IOC store: mine
        candidate infrastructure IOCs from each finding (same extraction as
        extract_iocs_from_finding) and check whether any of them are
        already known to self.repository — e.g. synced from OTX via
        sync_from_otx(), or mined from an earlier scan's finding.

        Returns one dict per (finding, matched Ioc row) pair actually found
        in the repository. A finding whose candidates are all new/unknown
        infrastructure simply produces no matches — that's the common case,
        not an error. Returns [] outright if no repository is configured,
        same convention as enrich_ioc() skipping persistence when unset.
        """
        if self.repository is None:
            return []

        matches: list[dict] = []
        for finding in findings:
            for candidate in self.extract_iocs_from_finding(finding):
                existing = await self.repository.get_by_value(candidate["ioc_type"], candidate["ioc_value"])
                if existing is not None and existing.is_active:
                    matches.append({
                        "finding_id": finding.get("id"),
                        "vuln_type": finding.get("vuln_type"),
                        "ioc_type": existing.ioc_type,
                        "ioc_value": existing.ioc_value,
                        "ioc_source": existing.source,
                        "confidence_score": existing.confidence_score,
                        "tags": existing.tags or [],
                    })
        return matches

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
