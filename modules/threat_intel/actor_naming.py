"""
Shared threat-actor-name heuristic.

AlienVault OTX's pulse `adversary` field (and any similarly free-text
"attribution" field from a community threat-intel source) is authored by
whoever submitted the pulse — it is frequently a generic descriptive phrase
(e.g. "Artificial Intelligence", a topic tag bleeding into the wrong field)
rather than an actual named threat actor. A confirmed incident traced a
false "Compromised" classification for an unrelated target back to exactly
this: the raw adversary string was trusted outright and fed into scoring.

Every consumer of OTX's `adversary` field (modules/osint/darkweb_intelligence.py,
modules/threat_intel/otx_feed.py, and anything downstream of otx_feed.py such
as modules/ioc_correlation.py and modules/ioc/ioc_engine.py) must run the
value through looks_like_threat_actor_name() before treating it as a
confirmed threat actor for scoring, clustering, or classification. Anything
that fails the check should be kept separately (e.g. as an
"unverified_adversary"/"unverified_adversary_mentions" field) rather than
silently discarded or silently trusted.
"""

import re

_RE_ACTOR_CODE = re.compile(r"^(APT|UNC|TA|FIN|UAC|G)[\s-]?\d{1,4}$", re.I)
_RE_ACTOR_ACRONYM = re.compile(r"^[A-Z]{2,6}\d{0,3}$")
_RE_ACTOR_SUFFIX = re.compile(
    r".*\b(Group|Team|Panda|Bear|Kitten|Spider|Tiger|Chollima|Wolf|Ocelot)$", re.I
)
_MAX_ACTOR_NAME_LEN = 40


def looks_like_threat_actor_name(name: str) -> bool:
    """Heuristic check for whether a free-text "adversary"/attribution
    string resembles a real threat-actor codename rather than generic
    free text.

    Accepts: APT/UNC/TA/FIN-style numeric codes (APT28, UNC1151), short
    all-caps acronyms (FIN7, TA505), names ending in a common threat-actor
    suffix (Lazarus Group, Fancy Bear, Charming Kitten), or a single
    capitalized word (Turla, Sandworm, Kimsuky). Rejects long strings and
    multi-word generic phrases, which is what a free-text excerpt from an
    unrelated pulse tag looks like.
    """
    if not name:
        return False
    name = name.strip()
    if not name or len(name) > _MAX_ACTOR_NAME_LEN:
        return False
    if _RE_ACTOR_CODE.match(name) or _RE_ACTOR_ACRONYM.match(name) or _RE_ACTOR_SUFFIX.match(name):
        return True
    words = name.split()
    if len(words) == 1 and name.isalpha() and name[0].isupper():
        return True
    return False
