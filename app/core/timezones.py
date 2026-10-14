"""Timezone inference for selected geocoded locations.

Geocoders return coordinates and address components, but do not consistently
return an IANA timezone.  Keep the inference conservative and always return a
ZoneInfo-valid fallback so location forms never have to accept an arbitrary
timezone string from a user.
"""

from zoneinfo import ZoneInfo


_CANADA = {
    "bc": "America/Vancouver",
    "british columbia": "America/Vancouver",
    "ab": "America/Edmonton",
    "alberta": "America/Edmonton",
    "sk": "America/Regina",
    "saskatchewan": "America/Regina",
    "mb": "America/Winnipeg",
    "manitoba": "America/Winnipeg",
    "on": "America/Toronto",
    "ontario": "America/Toronto",
    "qc": "America/Toronto",
    "quebec": "America/Toronto",
    "nb": "America/Moncton",
    "new brunswick": "America/Moncton",
    "ns": "America/Halifax",
    "nova scotia": "America/Halifax",
    "pe": "America/Halifax",
    "prince edward island": "America/Halifax",
    "nl": "America/St_Johns",
    "newfoundland and labrador": "America/St_Johns",
    "yt": "America/Whitehorse",
    "yukon": "America/Whitehorse",
    "nt": "America/Yellowknife",
    "northwest territories": "America/Yellowknife",
    "nu": "America/Iqaluit",
    "nunavut": "America/Iqaluit",
}

_US = {
    **dict.fromkeys(("wa", "washington", "or", "oregon", "ca", "california", "nv", "nevada"), "America/Los_Angeles"),
    **dict.fromkeys(("id", "idaho", "mt", "montana", "wy", "wyoming", "ut", "utah", "az", "arizona", "co", "colorado", "nm", "new mexico"), "America/Denver"),
    **dict.fromkeys(("nd", "north dakota", "sd", "south dakota", "ne", "nebraska", "ks", "kansas", "ok", "oklahoma", "tx", "texas", "mn", "minnesota", "ia", "iowa", "mo", "missouri", "ar", "arkansas", "la", "louisiana", "wi", "wisconsin", "il", "illinois", "al", "alabama", "ms", "mississippi", "tn", "tennessee"), "America/Chicago"),
    **dict.fromkeys(("me", "maine", "nh", "new hampshire", "vt", "vermont", "ma", "massachusetts", "ri", "rhode island", "ct", "connecticut", "ny", "new york", "nj", "new jersey", "pa", "pennsylvania", "oh", "ohio", "mi", "michigan", "in", "indiana", "ky", "kentucky", "wv", "west virginia", "va", "virginia", "md", "maryland", "de", "delaware", "dc", "district of columbia", "nc", "north carolina", "sc", "south carolina", "ga", "georgia", "fl", "florida"), "America/New_York"),
}

_COUNTRY_DEFAULTS = {
    "ca": "America/Toronto",
    "us": "America/New_York",
    "mx": "America/Mexico_City",
    "gb": "Europe/London",
    "au": "Australia/Sydney",
    "nz": "Pacific/Auckland",
}


def infer_timezone(region: str, address: dict | None = None) -> str:
    """Return a valid IANA timezone from a geocoder region/address."""

    address = address or {}
    country = str(region or address.get("country_code") or "").strip().lower()
    subdivision = str(
        address.get("state_code")
        or address.get("province_code")
        or address.get("state")
        or address.get("province")
        or ""
    ).strip().lower()
    if "-" in subdivision:
        subdivision = subdivision.rsplit("-", 1)[-1]
    if country == "ca":
        candidate = _CANADA.get(subdivision, _COUNTRY_DEFAULTS[country])
    elif country == "us":
        candidate = _US.get(subdivision, _COUNTRY_DEFAULTS[country])
    else:
        candidate = _COUNTRY_DEFAULTS.get(country, "UTC")
    ZoneInfo(candidate)
    return candidate


def annotate_geocode_results(results: list[dict], region: str) -> list[dict]:
    """Attach an inferred timezone to every address result returned to a form."""

    return [
        {
            **result,
            "timezone": result.get("timezone") or infer_timezone(region, result.get("address")),
        }
        for result in results
    ]
