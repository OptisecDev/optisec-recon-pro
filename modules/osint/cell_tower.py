"""Cell Tower Fingerprinting — MCC/MNC database for Iraq + Middle East."""

# MCC/MNC database: { "MCC-MNC": { carrier info } }
MCC_MNC_DB: dict[str, dict] = {
    # Iraq (MCC 418)
    "418-05": {"country": "Iraq", "carrier": "Asia Cell", "brand": "Asiacell",  "tech": ["2G", "3G", "4G"]},
    "418-08": {"country": "Iraq", "carrier": "Mobitel",   "brand": "Mobitel IQ", "tech": ["2G"]},
    "418-20": {"country": "Iraq", "carrier": "Zain Iraq", "brand": "Zain",       "tech": ["2G", "3G", "4G"]},
    "418-30": {"country": "Iraq", "carrier": "ITISALUNA", "brand": "Itisaluna",  "tech": ["2G"]},
    "418-40": {"country": "Iraq", "carrier": "Korek Telecom", "brand": "Korek",  "tech": ["2G", "3G", "4G"]},
    "418-45": {"country": "Iraq", "carrier": "Sanatel",   "brand": "Sanatel",    "tech": ["2G"]},
    "418-62": {"country": "Iraq", "carrier": "TERRA",     "brand": "Terra",      "tech": ["3G", "4G"]},
    "418-92": {"country": "Iraq", "carrier": "Fastlink",  "brand": "Fastlink",   "tech": ["2G", "3G"]},

    # Saudi Arabia (MCC 420)
    "420-01": {"country": "Saudi Arabia", "carrier": "STC",    "brand": "STC",    "tech": ["2G","3G","4G","5G"]},
    "420-03": {"country": "Saudi Arabia", "carrier": "Mobily",  "brand": "Mobily", "tech": ["2G","3G","4G","5G"]},
    "420-04": {"country": "Saudi Arabia", "carrier": "Zain SA", "brand": "Zain",   "tech": ["2G","3G","4G","5G"]},

    # Iran (MCC 432)
    "432-11": {"country": "Iran", "carrier": "IR-MCI",    "brand": "Hamrahe Aval", "tech": ["2G","3G","4G"]},
    "432-14": {"country": "Iran", "carrier": "KFZO",      "brand": "Kish Free Zone", "tech": ["2G","3G"]},
    "432-19": {"country": "Iran", "carrier": "MTCE",      "brand": "Irancell",     "tech": ["2G","3G","4G"]},
    "432-32": {"country": "Iran", "carrier": "RighTel",   "brand": "RighTel",      "tech": ["3G","4G"]},

    # Turkey (MCC 286)
    "286-01": {"country": "Turkey", "carrier": "Turkcell", "brand": "Turkcell", "tech": ["2G","3G","4G","5G"]},
    "286-02": {"country": "Turkey", "carrier": "Vodafone TR", "brand": "Vodafone", "tech": ["2G","3G","4G","5G"]},
    "286-03": {"country": "Turkey", "carrier": "Turk Telekom", "brand": "TT Mobile", "tech": ["2G","3G","4G"]},

    # Jordan (MCC 416)
    "416-01": {"country": "Jordan", "carrier": "Zain JO",     "brand": "Zain",    "tech": ["2G","3G","4G"]},
    "416-03": {"country": "Jordan", "carrier": "Umniah",       "brand": "Umniah",  "tech": ["2G","3G","4G"]},
    "416-77": {"country": "Jordan", "carrier": "Orange JO",    "brand": "Orange",  "tech": ["2G","3G","4G"]},

    # UAE (MCC 424)
    "424-02": {"country": "UAE", "carrier": "Etisalat", "brand": "Etisalat", "tech": ["2G","3G","4G","5G"]},
    "424-03": {"country": "UAE", "carrier": "du",       "brand": "du",       "tech": ["2G","3G","4G","5G"]},

    # Kuwait (MCC 419)
    "419-02": {"country": "Kuwait", "carrier": "Zain KW",  "brand": "Zain",  "tech": ["2G","3G","4G"]},
    "419-03": {"country": "Kuwait", "carrier": "Wataniya", "brand": "Ooredoo", "tech": ["2G","3G","4G"]},
    "419-04": {"country": "Kuwait", "carrier": "Viva",     "brand": "Viva",  "tech": ["2G","3G","4G","5G"]},
}

SIGNAL_QUALITY = {
    range(-60, 0):     {"label": "Excellent", "color": "success"},
    range(-70, -60):   {"label": "Good",      "color": "low"},
    range(-85, -70):   {"label": "Fair",      "color": "medium"},
    range(-100, -85):  {"label": "Poor",      "color": "high"},
    range(-130, -100): {"label": "Very Poor", "color": "critical"},
}


def lookup_cell_tower(mcc: int, mnc: int, lac: int = None, cell_id: int = None,
                      signal_dbm: int = None) -> dict:
    key = f"{mcc}-{str(mnc).zfill(2)}"
    carrier_info = MCC_MNC_DB.get(key)

    signal_info = None
    if signal_dbm is not None:
        signal_info = _analyze_signal(signal_dbm)

    if not carrier_info:
        # Try to identify country from MCC alone
        country = _mcc_to_country(mcc)
        return {
            "mcc": mcc,
            "mnc": mnc,
            "lac": lac,
            "cell_id": cell_id,
            "found": False,
            "country": country,
            "carrier": "Unknown carrier",
            "note": f"MCC {mcc}-MNC {mnc} not in database",
            "signal": signal_info,
            "risk_score": 30,
            "risk_label": "LOW",
        }

    result = {
        "mcc": mcc,
        "mnc": mnc,
        "lac": lac,
        "cell_id": cell_id,
        "found": True,
        **carrier_info,
        "signal": signal_info,
        "coverage_pattern": _build_coverage_notes(carrier_info, lac, cell_id),
        "risk_score": 15,
        "risk_label": "LOW",
    }
    return result


def _analyze_signal(dbm: int) -> dict:
    for rng, info in SIGNAL_QUALITY.items():
        if dbm in rng:
            return {"dbm": dbm, **info}
    return {"dbm": dbm, "label": "No Signal", "color": "critical"}


def _mcc_to_country(mcc: int) -> str:
    MCC_COUNTRIES = {
        418: "Iraq", 420: "Saudi Arabia", 432: "Iran",
        286: "Turkey", 416: "Jordan", 424: "UAE",
        419: "Kuwait", 417: "Syria", 415: "Lebanon",
        421: "Yemen", 426: "Bahrain", 427: "Qatar",
        422: "Oman", 425: "Palestine", 429: "Palestine (Gaza)",
    }
    return MCC_COUNTRIES.get(mcc, f"Unknown (MCC {mcc})")


def _build_coverage_notes(info: dict, lac: int, cell_id: int) -> list:
    notes = []
    carrier = info.get("carrier", "")
    country = info.get("country", "")
    tech = info.get("tech", [])

    notes.append(f"Carrier: {carrier} ({country})")
    notes.append(f"Technologies supported: {', '.join(tech)}")

    if lac:
        notes.append(f"LAC {lac} → Local Area Code (identifies cell region)")
    if cell_id:
        notes.append(f"Cell ID {cell_id} → individual tower within LAC")
    if country == "Iraq":
        notes.append("Iraqi cell tower — coverage denser in Baghdad, Basra, Erbil metro areas")

    return notes


def list_iraq_carriers() -> list:
    return [
        {"mcc_mnc": k, **v}
        for k, v in MCC_MNC_DB.items()
        if v.get("country") == "Iraq"
    ]
