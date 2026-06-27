"""Iraqi National ID Intelligence — format validation and metadata extraction."""

import re

# Iraqi National ID: 12 digits
# Format: PP YY SSSSSS C
#   PP = province code (2 digits)
#   YY = year of registration (2 digits)
#   SSSSSS = sequence number (6 digits)
#   C = check/extra digit (2 digits) — varies by source

PROVINCE_CODES = {
    "10": {"name": "Baghdad",       "arabic": "بغداد",        "region": "Central"},
    "11": {"name": "Baghdad Rusafa", "arabic": "بغداد الرصافة", "region": "Central"},
    "12": {"name": "Baghdad Karkh", "arabic": "بغداد الكرخ",   "region": "Central"},
    "20": {"name": "Basra",         "arabic": "البصرة",        "region": "South"},
    "30": {"name": "Nineveh",       "arabic": "نينوى",         "region": "North"},
    "35": {"name": "Erbil",         "arabic": "أربيل",         "region": "Kurdistan"},
    "36": {"name": "Sulaymaniyah",  "arabic": "السليمانية",    "region": "Kurdistan"},
    "37": {"name": "Duhok",         "arabic": "دهوك",          "region": "Kurdistan"},
    "40": {"name": "Kirkuk",        "arabic": "كركوك",         "region": "North"},
    "50": {"name": "Diyala",        "arabic": "ديالى",         "region": "Central"},
    "55": {"name": "Wasit",         "arabic": "واسط",          "region": "Central"},
    "60": {"name": "Babil",         "arabic": "بابل",          "region": "Central"},
    "65": {"name": "Karbala",       "arabic": "كربلاء",        "region": "Central"},
    "70": {"name": "Najaf",         "arabic": "النجف",         "region": "Central"},
    "75": {"name": "Qadisiyyah",    "arabic": "القادسية",      "region": "Central"},
    "80": {"name": "Muthanna",      "arabic": "المثنى",        "region": "South"},
    "85": {"name": "Dhi Qar",       "arabic": "ذي قار",        "region": "South"},
    "90": {"name": "Maysan",        "arabic": "ميسان",         "region": "South"},
    "95": {"name": "Saladin",       "arabic": "صلاح الدين",    "region": "Central"},
    "97": {"name": "Anbar",         "arabic": "الأنبار",       "region": "West"},
}

ID_RE = re.compile(r"^\d{12}$")


def analyze_national_id(id_raw: str) -> dict:
    id_clean = re.sub(r"[\s\-]", "", id_raw.strip())

    if not ID_RE.match(id_clean):
        return {
            "input": id_raw,
            "valid": False,
            "error": f"Invalid format — expected 12 digits, got: '{id_clean}' ({len(id_clean)} chars)",
        }

    prov_code = id_clean[:2]
    year_digits = id_clean[2:4]
    sequence = id_clean[4:10]
    check = id_clean[10:12]

    province = PROVINCE_CODES.get(prov_code)
    prov_name = province["name"] if province else f"Unknown (code {prov_code})"
    prov_arabic = province["arabic"] if province else ""
    region = province["region"] if province else "Unknown"

    # Year estimation: YY → could be 19YY or 20YY
    year_int = int(year_digits)
    reg_year = f"19{year_digits}" if year_int > 24 else f"20{year_digits}"

    risk_score = _calc_risk(province, year_int)

    return {
        "input": id_raw,
        "id": id_clean,
        "valid": True,
        "province_code": prov_code,
        "province": prov_name,
        "province_arabic": prov_arabic,
        "region": region,
        "registration_year_estimate": reg_year,
        "sequence_number": sequence,
        "check_digits": check,
        "formatted": f"{prov_code}-{year_digits}-{sequence}-{check}",
        "notes": _build_notes(province, prov_code, reg_year, sequence),
        "risk_score": risk_score,
        "risk_label": _risk_label(risk_score),
        "disclaimer": "Metadata extracted from format only — no real database lookup performed",
    }


def _calc_risk(province: dict, year_int: int) -> int:
    score = 10
    if not province:
        score += 30
    return min(score, 100)


def _risk_label(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def _build_notes(province: dict, code: str, year: str, seq: str) -> list:
    notes = []
    if province:
        notes.append(
            f"Issued in {province['name']} ({province['arabic']}) — {province['region']} Iraq"
        )
    else:
        notes.append(f"Province code {code} not recognized — possibly invalid or outdated")
    notes.append(f"Registration year estimate: {year}")
    notes.append(f"Sequence {seq} — higher numbers indicate later registration within that year/province")
    notes.append("Iraqi National ID is managed by the Ministry of Interior NCCID system")
    return notes


def validate_format(id_str: str) -> bool:
    return bool(ID_RE.match(re.sub(r"[\s\-]", "", id_str.strip())))
