"""Phase-1 GraphQL scanner: introspection-only, read-only.

Sends only the standard `__schema`/`__type` introspection queries against a
small, fixed list of common GraphQL paths (GRAPHQL_CANDIDATE_PATHS) — no
path brute-forcing/wordlists, no mutations, no batching/aliasing/query-depth
abuse. Those are later phases, not this one; see scan_graphql()'s docstring.

Two requests per candidate path, worst case:
  1. A cheap existence probe (`{ __schema { queryType { name } } }`) over
     POST, the standard GraphQL transport. If that doesn't already give a
     decisive verdict, the same query is retried over GET (`?query=...`) —
     some GraphQL servers only accept GET.
  2. Only once step 1 confirms introspection is enabled does the full
     standard introspection query (_FULL_INTROSPECTION_QUERY) get sent, to
     capture the actual schema dump as evidence.
"""

import requests
from urllib.parse import urlparse

from config import DEFAULT_TIMEOUT
from modules.vuln.waf_aware_classifier import classify_graphql_introspection

GRAPHQL_CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql"]

_EXISTENCE_QUERY = {"query": "{ __schema { queryType { name } } }"}

# The canonical GraphQL.js introspection query (graphql/graphql-js), used
# as-is — no custom fields, no aliasing tricks, nothing beyond what any
# GraphQL client's dev tools would send.
_FULL_INTROSPECTION_QUERY = {"query": """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""}

# Ranks a verdict by how decisive/informative it is, so that when both a
# POST and a GET attempt were tried for the same path, the more informative
# one is kept as the retained record instead of always preferring POST.
_VERDICT_RANK = {
    "ENDPOINT_INVALID": 0,
    "INCONCLUSIVE": 1,
    "WAF_BLOCKED": 2,
    "INTROSPECTION_DISABLED": 3,
    "CONFIRMED": 4,
}

# A POST attempt landing on any of these verdicts already answers the
# question definitively for this path — no need to also burn a GET request.
_DECISIVE_VERDICTS = {"CONFIRMED", "INTROSPECTION_DISABLED", "WAF_BLOCKED"}


def _probe(session: requests.Session, method: str, url: str, query: dict):
    """One HTTP attempt + classification, or None if the request itself
    failed (connection error, timeout, etc.) — indistinguishable from
    "no endpoint here" for this probe's purposes."""
    try:
        if method == "POST":
            response = session.post(url, json=query, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        else:
            response = session.get(
                url, params={"query": query["query"]}, timeout=DEFAULT_TIMEOUT, allow_redirects=False,
            )
    except Exception:
        return None
    result = classify_graphql_introspection(response.status_code, response.headers, response.text)
    return method, response, result


def scan_graphql(base_url: str) -> list:
    """Probe `base_url`'s origin (scheme + host) for a live GraphQL endpoint
    across GRAPHQL_CANDIDATE_PATHS, using only standard introspection
    queries. Returns one retained finding per candidate path tried — same
    "always keep a record, not just confirmed ones" convention as
    modules/vuln/{xss,ssrf,lfi}.py — except the whole scan stops early the
    moment one path CONFIRMS introspection is enabled (Chime's
    one-primary-finding-per-class rule already enforces this one level up
    in scripts/bounty_scan_chime.py, but stopping here too avoids sending
    the remaining candidate paths' requests at all)."""
    findings = []
    parsed_base = urlparse(base_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    session = requests.Session()
    session.headers["User-Agent"] = "OPTISEC-ReconPro/1.0 (Security Testing)"

    for path in GRAPHQL_CANDIDATE_PATHS:
        url = f"{origin}{path}"

        post_attempt = _probe(session, "POST", url, _EXISTENCE_QUERY)
        if post_attempt and post_attempt[2].verdict in _DECISIVE_VERDICTS:
            method, response, result = post_attempt
        else:
            get_attempt = _probe(session, "GET", url, _EXISTENCE_QUERY)
            candidates = [a for a in (post_attempt, get_attempt) if a is not None]
            if not candidates:
                continue
            method, response, result = max(candidates, key=lambda a: _VERDICT_RANK.get(a[2].verdict, -1))

        if result.verdict == "CONFIRMED":
            # Existence query already proved __schema is queryable; now pull
            # the full standard introspection dump as evidence. If this
            # second call somehow doesn't also confirm (flaky WAF, rate
            # limit), keep the existence-query result rather than downgrade.
            full_attempt = _probe(session, method, url, _FULL_INTROSPECTION_QUERY)
            if full_attempt and full_attempt[2].verdict == "CONFIRMED":
                method, response, result = full_attempt

        findings.append({
            "type": "GraphQL Introspection",
            "severity": result.severity,
            "url": url,
            "path": path,
            "method": method,
            "evidence": result.reason,
            "waf_detected": result.waf_detected,
            "verdict": result.verdict,
            "status_code": response.status_code,
            "response_body": response.text[:3000],
        })

        if result.verdict == "CONFIRMED":
            break

    return findings
