"""
Correlation & Deduplication Engine
Merges findings reported by multiple OSINT sources that describe the same
real-world entity (subdomain, email, IP, account, ...) into one unified
record per entity, and indexes everything into a per-entity "intelligence
file" — the way Maltego's graph view collapses duplicate nodes pulled in by
different transforms into a single entity.

Input shape expected by both functions here is unified_engine.py's
`sources` list: a list of per-source dicts, each
`{"source": str, "available": bool, "results": [finding, ...], "error"?: str}`.
"""

from __future__ import annotations

_MERGE_SKIP_FIELDS = ("sources", "occurrences")


def _entity_key(finding: dict) -> tuple[str, str] | None:
    """Normalize a finding to the (type, value) identity used for merging."""
    value = finding.get("value")
    if value is None:
        return None
    ftype = (finding.get("type") or "unknown").lower()
    return ftype, str(value).strip().lower()


def deduplicate_and_merge(results: list[dict]) -> list[dict]:
    """
    Collapse findings reported by multiple sources for the same entity into
    one merged record per (type, value) pair.

    Algorithm:
      1. Walk every source block's `results` list.
      2. Key each finding by `(type, lowercased value)`.
      3. First sighting of a key: keep all its fields as-is, and attach
         `sources: [source_name]` and `occurrences: 1`.
      4. Every later sighting of the same key: append the new source name
         to `sources` (if not already present) and increment `occurrences`.
         Any field the merged record doesn't already hold a non-empty value
         for is backfilled from the new sighting — the first non-empty
         value for a field wins, so a richer source's detail (e.g. crt.sh's
         `issuer`) is never clobbered by a sparser source reporting the
         same entity later.

    Returns a flat list of merged entity dicts. Each carries a `sources`
    list that confidence_engine.calculate_confidence() reads to score
    cross-source corroboration — the more independent sources agree on an
    entity, the higher its confidence score.
    """
    merged: dict[tuple[str, str], dict] = {}

    for source_block in results or []:
        source_name = source_block.get("source", "unknown")
        for finding in source_block.get("results") or []:
            key = _entity_key(finding)
            if key is None:
                continue

            entry = merged.get(key)
            if entry is None:
                entry = dict(finding)
                entry["sources"] = [source_name]
                entry["occurrences"] = 1
                merged[key] = entry
                continue

            if source_name not in entry["sources"]:
                entry["sources"].append(source_name)
            entry["occurrences"] += 1
            for field, value in finding.items():
                if field in _MERGE_SKIP_FIELDS:
                    continue
                if entry.get(field) in (None, "", []):
                    entry[field] = value

    return list(merged.values())


def build_entity_graph(results: list[dict]) -> dict[str, dict]:
    """
    Build a per-entity intelligence dossier: a dict keyed by entity value,
    each mapping to its merged finding plus a best-effort `related_to` link
    to the parent entity it belongs to.

    This is the flat-dict equivalent of what Maltego/SpiderFoot represent as
    graph nodes + edges; there's no graph-DB backing here, so relationships
    are inferred structurally instead of being explicit edges:
      - an email's `related_to` is the domain after its `@`
      - a subdomain's `related_to` is the apex domain it ends with, if that
        apex domain also appears in this result set (as a `whois_record`
        entity, since WHOIS is always queried for the apex domain itself)

    Use this when you need "everything we know about X" rather than a flat
    findings list — e.g. to render one card per entity in a report UI.
    """
    merged_entities = deduplicate_and_merge(results)
    apex_domains = {
        str(e["value"]).strip().lower()
        for e in merged_entities
        if e.get("type") == "whois_record" and e.get("value")
    }

    graph: dict[str, dict] = {}
    for entity in merged_entities:
        value = str(entity.get("value", "")).strip().lower()
        if not value:
            continue

        related_to = None
        etype = entity.get("type")
        if etype == "email" and "@" in value:
            related_to = value.split("@", 1)[1]
        elif etype == "subdomain":
            for apex in apex_domains:
                if value != apex and value.endswith("." + apex):
                    related_to = apex
                    break

        graph[value] = {**entity, "related_to": related_to}

    return graph
