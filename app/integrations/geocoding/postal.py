"""Postal-aware geocoding orchestration and normalization helpers."""

import re
from types import SimpleNamespace

from app.integrations.contracts import IntegrationFailure
from app.integrations.geocoding.providers import (
    NominatimGeocodingProvider,
    OverpassAddressProvider,
    PhotonGeocodingProvider,
)


class PostalAwareGeocodingProvider:
    """Primary geocoder with a provider-backed fallback for postal searches."""

    _CANADIAN_POSTAL = re.compile(r"^[A-Z]\d[A-Z]\s?\d[A-Z]\d$", re.IGNORECASE)

    # Initialize the instance with its required state.
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

    # Retrieve search addresses for the current request or workflow.
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

    # Handle search for this module.
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

    # Internal helper for merge.
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
