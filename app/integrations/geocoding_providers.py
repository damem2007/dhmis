"""Geocoding provider adapters used by platform onboarding.

The platform calls the provider contract rather than a vendor API directly.
TomTom supplies production address coordinates, while the OSM adapters remain
available as configurable alternatives and fallbacks. Storefront map rendering
is a separate frontend concern and uses OpenStreetMap coordinates.
"""

import re
from types import SimpleNamespace
from urllib.parse import quote

import httpx

from app.integrations.contracts import GeocodingProvider, IntegrationFailure


class NominatimGeocodingProvider:
    """OpenStreetMap Nominatim adapter behind the geocoding contract."""

    def __init__(self, context):
        self.options = context.options
        self.endpoint = str(
            self.options.get("endpoint", "https://nominatim.openstreetmap.org/search")
        ).rstrip("/")
        self.user_agent = str(
            self.options.get("user_agent", "DHMIS platform admin location search/1.0")
        )

    async def search(self, query: str, region: str, limit: int = 5) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(
                    self.endpoint,
                    params={
                        "q": query.strip(),
                        "format": "jsonv2",
                        "addressdetails": 1,
                        "limit": limit,
                        "countrycodes": region.lower(),
                    },
                    headers={
                        "Accept": "application/json",
                        "Accept-Language": "en",
                        "User-Agent": self.user_agent,
                    },
                )
                response.raise_for_status()
        except httpx.HTTPError as error:
            raise IntegrationFailure("Geocoding provider is temporarily unavailable") from error
        results: list[dict] = []
        for item in response.json():
            if item.get("lat") is None or item.get("lon") is None:
                continue
            address = dict(item.get("address") or {})
            item_type = str(item.get("type", ""))
            if not address.get("road") and item.get("name") and item_type in {"residential", "road", "street"}:
                address["road"] = str(item["name"])
            results.append(
                {
                    "place_id": str(item.get("place_id", "")),
                    "display_name": str(item.get("display_name", "")),
                    "latitude": float(item["lat"]),
                    "longitude": float(item["lon"]),
                    "type": "street" if address.get("road") and not address.get("house_number") else item_type,
                    "address": address,
                }
            )
        return results


class TomTomGeocodingProvider:
    """TomTom Search API adapter for production address autocomplete."""

    def __init__(self, context):
        self.options = context.options
        self.endpoint = str(
            self.options.get("endpoint", "https://api.tomtom.com/search/2/search")
        ).rstrip("/")
        self.api_key = str(self.options.get("api_key", self.options.get("key", ""))).strip()
        self.user_agent = str(
            self.options.get("user_agent", "DHMIS platform address search/1.0")
        )

    async def search(self, query: str, region: str, limit: int = 5) -> list[dict]:
        if not self.api_key:
            raise IntegrationFailure("TomTom geocoding provider is missing api_key")
        url = f"{self.endpoint}/{quote(query.strip(), safe='')}.json"
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(
                    url,
                    params={
                        "key": self.api_key,
                        "limit": min(limit, 100),
                        "language": self.options.get("language", "en-US"),
                        "countrySet": region.upper(),
                    },
                    headers={
                        "Accept": "application/json",
                        "User-Agent": self.user_agent,
                    },
                )
                response.raise_for_status()
        except httpx.HTTPError as error:
            raise IntegrationFailure("TomTom geocoding provider is temporarily unavailable") from error

        results: list[dict] = []
        for item in response.json().get("results", []):
            position = item.get("position") or {}
            if position.get("lat") is None or position.get("lon") is None:
                continue
            address_data = item.get("address") or {}
            street = address_data.get("streetName")
            house_number = address_data.get("streetNumber")
            address = {
                key: value
                for key, value in {
                    "road": street,
                    "street": street,
                    "house_number": house_number,
                    "city": address_data.get("municipality") or address_data.get("municipalitySubdivision"),
                    "state": address_data.get("countrySubdivisionName") or address_data.get("countrySubdivision"),
                    "postcode": address_data.get("postalCode"),
                    "country": address_data.get("country"),
                    "country_code": address_data.get("countryCode"),
                }.items()
                if value
            }
            entity_type = str(item.get("type") or item.get("entityType") or "").lower()
            result_type = "address" if street and house_number else ("street" if street else entity_type)
            results.append(
                {
                    "place_id": f"tomtom:{item.get('id', len(results))}",
                    "display_name": str(address_data.get("freeformAddress") or query.strip()),
                    "latitude": float(position["lat"]),
                    "longitude": float(position["lon"]),
                    "type": result_type,
                    "address": address,
                }
            )
            if len(results) >= limit:
                break
        return results


class PhotonGeocodingProvider:
    """Photon adapter used as a provider-configured geocoding fallback."""

    def __init__(self, context):
        self.options = context.options
        self.endpoint = str(
            self.options.get("fallback_endpoint", self.options.get("endpoint", "https://photon.komoot.io/api/"))
        ).rstrip("/")
        self.user_agent = str(
            self.options.get("user_agent", "DHMIS platform admin location search/1.0")
        )

    async def search(self, query: str, region: str, limit: int = 5) -> list[dict]:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                lookup = query.strip()
                if region:
                    country_names = self.options.get("country_names") or {
                        "CA": "Canada",
                        "US": "United States",
                    }
                    lookup = f"{lookup}, {country_names.get(region.upper(), region.upper())}"
                response = await client.get(
                    self.endpoint,
                    params={"q": lookup, "limit": limit, "lang": "en"},
                    headers={
                        "Accept": "application/json",
                        "Accept-Language": "en",
                        "User-Agent": self.user_agent,
                    },
                )
                response.raise_for_status()
        except httpx.HTTPError as error:
            raise IntegrationFailure("Geocoding provider is temporarily unavailable") from error

        results: list[dict] = []
        for item in response.json().get("features", []):
            properties = item.get("properties") or {}
            geometry = item.get("geometry") or {}
            coordinates = geometry.get("coordinates") or []
            if len(coordinates) < 2:
                continue
            feature_type = str(properties.get("osm_value") or properties.get("type") or "")
            street_name = properties.get("street")
            if not street_name and feature_type in {"residential", "road", "street"}:
                street_name = properties.get("name")
            address = {
                key: value
                for key, value in {
                    "street": street_name,
                    "housenumber": properties.get("housenumber"),
                    "district": properties.get("district"),
                    "city": properties.get("city"),
                    "state": properties.get("state"),
                    "postcode": properties.get("postcode"),
                    "country": properties.get("country"),
                    "country_code": properties.get("countrycode"),
                }.items()
                if value
            }
            parts = []
            if properties.get("name"):
                parts.append(str(properties["name"]))
            street = " ".join(
                str(value)
                for value in (properties.get("housenumber"), properties.get("street"))
                if value
            )
            if street:
                parts.append(street)
            parts.extend(
                str(properties[key])
                for key in ("district", "city", "state", "postcode", "country")
                if properties.get(key) and str(properties[key]) not in parts
            )
            results.append(
                {
                    "place_id": f"photon:{properties.get('osm_id', len(results))}",
                    "display_name": ", ".join(parts) or query.strip(),
                    "latitude": float(coordinates[1]),
                    "longitude": float(coordinates[0]),
                    "type": feature_type,
                    "address": address,
                }
            )
        region_code = region.strip().lower()
        if region_code:
            results = [
                result
                for result in results
                if (result.get("address") or {}).get("country_code", "").lower()
                == region_code
            ]
        return results[:limit]


class OverpassAddressProvider:
    """OpenStreetMap address-index adapter for expanding a selected street."""

    def __init__(self, context):
        self.options = context.options
        self.endpoint = str(
            self.options.get(
                "address_endpoint", "https://overpass-api.de/api/interpreter"
            )
        )
        self.user_agent = str(
            self.options.get("user_agent", "DHMIS platform admin location search/1.0")
        )

    async def search(self, query: str, region: str, limit: int = 5) -> list[dict]:
        street = query.strip()
        if not street:
            return []
        # The street value is escaped before being embedded in the Overpass
        # expression. The region remains a provider input, never a fixed tenant.
        escaped_street = street.replace("\\", "\\\\").replace('"', '\\"')
        expression = (
            f'[out:json][timeout:20];area["ISO3166-1"="{region.upper()}"]->.region;'
            f'nwr["addr:street"="{escaped_street}"](area.region);out center;'
        )
        try:
            async with httpx.AsyncClient(timeout=25.0) as client:
                response = await client.post(
                    self.endpoint,
                    data={"data": expression},
                    headers={"Accept": "application/json", "User-Agent": self.user_agent},
                )
                response.raise_for_status()
        except httpx.HTTPError as error:
            raise IntegrationFailure("Address detail provider is temporarily unavailable") from error

        results: list[dict] = []
        for item in response.json().get("elements", []):
            tags = item.get("tags") or {}
            house_number = tags.get("addr:housenumber")
            if not house_number:
                continue
            latitude = item.get("lat")
            longitude = item.get("lon")
            if latitude is None or longitude is None:
                center = item.get("center") or {}
                latitude = center.get("lat")
                longitude = center.get("lon")
            if latitude is None or longitude is None:
                continue
            address = {
                key: value
                for key, value in {
                    "house_number": house_number,
                    "road": tags.get("addr:street", street),
                    "unit": tags.get("addr:unit"),
                    "postcode": tags.get("addr:postcode"),
                    "city": tags.get("addr:city"),
                    "state": tags.get("addr:state"),
                    "country_code": region.lower(),
                }.items()
                if value
            }
            locality = ", ".join(
                str(address[key])
                for key in ("city", "state", "postcode")
                if address.get(key)
            )
            display_name = ", ".join(
                part for part in (f"{house_number} {address['road']}", locality) if part
            )
            results.append(
                {
                    "place_id": f"overpass:{item.get('type', 'element')}:{item.get('id', len(results))}",
                    "display_name": display_name,
                    "latitude": float(latitude),
                    "longitude": float(longitude),
                    "type": "address",
                    "address": address,
                }
            )
            if len(results) >= limit:
                break
        return results


class PostalAwareGeocodingProvider:
    """Primary geocoder with a provider-backed fallback for postal searches."""

    _CANADIAN_POSTAL = re.compile(r"^[A-Z]\d[A-Z]\s?\d[A-Z]\d$", re.IGNORECASE)

    def __init__(self, context):
        # Keep both services behind this registered provider.  Endpoints remain
        # options so deployments can replace either provider without code changes.
        options = context.options
        primary_context = SimpleNamespace(
            options={
                **options,
                "endpoint": options.get(
                    "primary_endpoint", "https://nominatim.openstreetmap.org/search"
                ),
            }
        )
        fallback_context = SimpleNamespace(
            options={
                **options,
                "fallback_endpoint": options.get(
                    "fallback_endpoint", "https://photon.komoot.io/api/"
                ),
            }
        )
        self.primary = NominatimGeocodingProvider(primary_context)
        self.fallback = PhotonGeocodingProvider(fallback_context)
        self.addresses = OverpassAddressProvider(fallback_context)

    async def search_addresses(self, query: str, region: str, limit: int = 5) -> list[dict]:
        try:
            results = await self.addresses.search(query, region, limit)
        except IntegrationFailure:
            return await self.search(query, region, limit)
        if not results:
            return await self.search(query, region, limit)

        # OSM address nodes often contain only the street and house number. Use
        # the primary result as provider-backed locality context so each child
        # option remains useful to a person selecting a complete address.
        try:
            parent_results = await self.search(query, region, limit)
        except IntegrationFailure:
            parent_results = []
        parent_context: dict = {}
        normalized_query = " ".join(query.casefold().split())
        for parent in parent_results:
            address = parent.get("address") or {}
            road = address.get("road") or address.get("street")
            if road and " ".join(str(road).casefold().split()) == normalized_query:
                parent_context = address
                break
        if not parent_context and parent_results:
            parent_context = parent_results[0].get("address") or {}

        enriched: list[dict] = []
        for result in results:
            address = dict(result.get("address") or {})
            for key in ("city", "town", "village", "state", "province", "postcode", "country"):
                if not address.get(key) and parent_context.get(key):
                    address[key] = parent_context[key]
            locality = ", ".join(
                str(address[key])
                for key in ("city", "town", "village", "state", "postcode", "country")
                if address.get(key)
            )
            road = address.get("road") or address.get("street") or query.strip()
            house_number = address.get("house_number") or address.get("housenumber")
            enriched.append(
                {
                    **result,
                    "display_name": ", ".join(
                        part for part in (f"{house_number} {road}" if house_number else road, locality) if part
                    ),
                    "address": address,
                }
            )
        return enriched

    async def search(self, query: str, region: str, limit: int = 5) -> list[dict]:
        try:
            primary_results = await self.primary.search(query, region, limit)
        except IntegrationFailure:
            primary_results = []
        normalized_query = re.sub(
            r"\b([EW])\s+(?:avenue|ave)\b",
            r"Ave \1",
            query,
            flags=re.IGNORECASE,
        )
        if normalized_query.strip().lower() != query.strip().lower():
            try:
                normalized_results = await self.primary.search(normalized_query, region, limit)
            except IntegrationFailure:
                normalized_results = []
            primary_results = self._merge(primary_results, normalized_results, limit)
        primary_results = self._collapse_street_matches(primary_results)
        if len(primary_results) >= limit:
            return primary_results[:limit]
        fallback_query = query
        if primary_results:
            primary_address = primary_results[0].get("address") or {}
            locality = primary_address.get("city") or primary_address.get("town")
            if locality and str(locality).lower() not in query.lower():
                fallback_query = f"{query}, {locality}"
        fallback_results = await self.fallback.search(fallback_query, region, limit)
        if not fallback_results:
            return primary_results[:limit]

        normalized = " ".join(query.upper().split())
        if region.upper() == "CA" and self._CANADIAN_POSTAL.fullmatch(normalized):
            first = fallback_results[0]
            address = dict(first.get("address") or {})
            address["postcode"] = normalized
            locality = ", ".join(
                str(address[key])
                for key in ("district", "city", "state", "country")
                if address.get(key)
            )
            fallback_results.insert(
                0,
                {
                    **first,
                    "place_id": f"postal:{region.lower()}:{normalized.replace(' ', '')}",
                    "display_name": ", ".join(part for part in (normalized, locality) if part),
                    "type": "postalcode",
                    "address": address,
                },
            )
        merged = list(primary_results)
        return self._collapse_street_matches(self._merge(merged, fallback_results, limit))[:limit]

    @staticmethod
    def _collapse_street_matches(results: list[dict]) -> list[dict]:
        """Present one selectable street group per road and locality."""
        collapsed: list[dict] = []
        seen_streets: set[tuple[str, str, str]] = set()
        for result in results:
            address = result.get("address") or {}
            road = address.get("road") or address.get("street")
            house_number = address.get("house_number") or address.get("housenumber")
            result_type = str(result.get("type") or "").lower()
            if road and not house_number and result_type not in {"postalcode", "postcode"}:
                locality = str(
                    address.get("city")
                    or address.get("town")
                    or address.get("village")
                    or address.get("municipality")
                    or ""
                )
                state = str(address.get("state") or address.get("province") or "")
                key = (str(road).casefold(), locality.casefold(), state.casefold())
                if key in seen_streets:
                    continue
                seen_streets.add(key)
                place = ", ".join(
                    str(address[value])
                    for value in ("city", "town", "village", "state", "province", "postcode", "country")
                    if address.get(value)
                )
                result = {
                    **result,
                    "type": "street",
                    "display_name": ", ".join(part for part in (str(road), place) if part),
                }
            collapsed.append(result)
        return collapsed

    @staticmethod
    def _merge(primary: list[dict], secondary: list[dict], limit: int) -> list[dict]:
        merged = list(primary)
        seen = {
            (result.get("display_name", "").strip().lower(), round(result["latitude"], 5), round(result["longitude"], 5))
            for result in merged
        }
        for result in secondary:
            key = (
                result.get("display_name", "").strip().lower(),
                round(result["latitude"], 5),
                round(result["longitude"], 5),
            )
            if key not in seen:
                merged.append(result)
                seen.add(key)
            if len(merged) >= limit:
                break
        return merged[:limit]
