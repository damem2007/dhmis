"""Compatibility exports for the geocoding provider adapters.

New code should import implementations from ``app.integrations.geocoding``.
This module remains stable for registry and downstream callers during the
incremental refactor.
"""

from app.integrations.geocoding import (
    NominatimGeocodingProvider,
    OverpassAddressProvider,
    PhotonGeocodingProvider,
    PostalAwareGeocodingProvider,
    TomTomGeocodingProvider,
)

__all__ = [
    "NominatimGeocodingProvider",
    "OverpassAddressProvider",
    "PhotonGeocodingProvider",
    "PostalAwareGeocodingProvider",
    "TomTomGeocodingProvider",
]
