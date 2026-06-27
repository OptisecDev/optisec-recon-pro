import whois as pythonwhois
from datetime import datetime


def whois_lookup(domain: str) -> dict:
    try:
        w = pythonwhois.whois(domain)
        result = {
            "domain_name": str(w.domain_name or ""),
            "registrar": str(w.registrar or ""),
            "creation_date": _fmt_date(w.creation_date),
            "expiration_date": _fmt_date(w.expiration_date),
            "updated_date": _fmt_date(w.updated_date),
            "name_servers": _as_list(w.name_servers),
            "status": _as_list(w.status),
            "emails": _as_list(w.emails),
            "org": str(w.org or ""),
            "country": str(w.country or ""),
        }
        return result
    except Exception as e:
        return {"error": str(e)}


def _fmt_date(d) -> str:
    if d is None:
        return ""
    if isinstance(d, list):
        d = d[0]
    if isinstance(d, datetime):
        return d.strftime("%Y-%m-%d")
    return str(d)


def _as_list(v) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]
