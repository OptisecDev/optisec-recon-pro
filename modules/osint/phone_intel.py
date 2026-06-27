"""Phone Number Intelligence — phonenumbers library + pattern analysis."""

import phonenumbers
from phonenumbers import geocoder, carrier, timezone as pn_timezone
from phonenumbers import PhoneNumberType, number_type


LINE_TYPE_NAMES = {
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE: "Landline",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed/Mobile",
    PhoneNumberType.TOLL_FREE: "Toll-Free",
    PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "Universal Access Number",
    PhoneNumberType.UNKNOWN: "Unknown",
}

RISK_WEIGHTS = {
    "Mobile": 40,
    "VoIP": 70,
    "Landline": 20,
    "Toll-Free": 30,
}


def analyze_phone(raw: str) -> dict:
    raw = raw.strip()
    if not raw.startswith("+"):
        raw = "+" + raw

    try:
        parsed = phonenumbers.parse(raw)
    except Exception as e:
        return {"error": f"Cannot parse number: {e}", "input": raw}

    valid = phonenumbers.is_valid_number(parsed)
    possible = phonenumbers.is_possible_number(parsed)
    ltype = number_type(parsed)
    ltype_name = LINE_TYPE_NAMES.get(ltype, "Unknown")

    country_code = parsed.country_code
    national = parsed.national_number
    region = phonenumbers.region_code_for_number(parsed)
    country_name = geocoder.description_for_number(parsed, "en")
    carrier_name = carrier.name_for_number(parsed, "en")
    timezones = list(pn_timezone.time_zones_for_number(parsed))

    formats = {
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "rfc3966": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.RFC3966),
    }

    variations = _generate_variations(formats["e164"], country_code, str(national))

    risk_score = _calc_risk(ltype_name, valid, carrier_name)

    return {
        "input": raw,
        "valid": valid,
        "possible": possible,
        "country_code": f"+{country_code}",
        "region": region,
        "country": country_name,
        "carrier": carrier_name or "Unknown",
        "line_type": ltype_name,
        "timezones": timezones,
        "formats": formats,
        "variations": variations,
        "risk_score": risk_score,
        "risk_label": _risk_label(risk_score),
        "intelligence_notes": _build_notes(ltype_name, carrier_name, region, valid),
    }


def _generate_variations(e164: str, country_code: int, national: str) -> list:
    variations = []
    stripped = national.lstrip("0")
    prefix = f"+{country_code}"
    seen = set()
    candidates = [
        e164,
        f"{prefix} {national}",
        f"{prefix}-{national}",
        f"00{country_code}{national}",
        f"0{stripped}",
        national,
    ]
    for c in candidates:
        c = c.strip()
        if c and c not in seen:
            seen.add(c)
            variations.append(c)
    return variations


def _calc_risk(ltype: str, valid: bool, carrier_name: str) -> int:
    base = RISK_WEIGHTS.get(ltype, 30)
    if not valid:
        base += 20
    if not carrier_name:
        base += 15
    return min(base, 100)


def _risk_label(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _build_notes(ltype: str, carrier: str, region: str, valid: bool) -> list:
    notes = []
    if not valid:
        notes.append("Number failed validity check — may be spoofed or invalid")
    if ltype == "VoIP":
        notes.append("VoIP numbers can be spoofed easily; treat with high suspicion")
    if ltype == "Mobile" and not carrier:
        notes.append("Mobile number with unknown carrier — possible MVNO or ported number")
    if region == "IQ":
        notes.append("Iraqi number — carriers: Zain IQ (+9647), Asiacell (+9647), Korek (+9647)")
    return notes
