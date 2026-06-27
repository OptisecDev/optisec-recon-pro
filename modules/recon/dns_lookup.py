import dns.resolver
import dns.reversename


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]


def dns_lookup(domain: str) -> dict:
    results = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []

    return results


def reverse_lookup(ip: str) -> str:
    try:
        rev = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev, "PTR")
        return str(answer[0])
    except Exception:
        return ""
