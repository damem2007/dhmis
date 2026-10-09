"""Map rendering and directions providers.

Map providers are intentionally separate from geocoders. A geocoder resolves
an address to coordinates; a map provider turns saved coordinates into the
public map, marker and directions links shown by the storefront.
"""

from urllib.parse import quote, urlencode

from app.integrations.contracts import IntegrationFailure


class OpenStreetMapProvider:
    """Provider for OpenStreetMap embeds and directions links."""

    def __init__(self, context):
        self.options = context.options
        self.base_url = str(
            self.options.get("base_url", "https://www.openstreetmap.org")
        ).rstrip("/")
        self.embed_base_url = str(
            self.options.get("embed_base_url", f"{self.base_url}/export/embed.html")
        ).rstrip("/")

    def location_links(
        self,
        latitude: float,
        longitude: float,
        address: str = "",
    ) -> dict[str, str]:
        delta = float(self.options.get("viewport_delta", 0.01))
        directions_delta = float(self.options.get("directions_viewport_delta", 0.003))
        bbox = (
            f"{longitude - delta}%2C{latitude - delta}%2C"
            f"{longitude + delta}%2C{latitude + delta}"
        )
        marker = f"{latitude}%2C{longitude}"
        directions_bbox = (
            f"{longitude - directions_delta}%2C{latitude - directions_delta}%2C"
            f"{longitude + directions_delta}%2C{latitude + directions_delta}"
        )
        query = quote(address.strip()) if address.strip() else f"{latitude}%2C{longitude}"
        return {
            "provider": "openstreetmap",
            "directions_url": (
                f"{self.base_url}/directions?engine=fossgis_osrm_car"
                f"&route=;{latitude}%2C{longitude}"
            ),
            "embed_url": (
                f"{self.embed_base_url}?bbox={bbox}&layer=mapnik&marker={marker}"
            ),
            "directions_embed_url": (
                f"{self.embed_base_url}?bbox={directions_bbox}&layer=mapnik&marker={marker}"
            ),
            "map_url": (
                f"{self.base_url}/?mlat={latitude}&mlon={longitude}"
                f"#map=17/{latitude}/{longitude}"
            ),
            "search_url": f"{self.base_url}/search?query={query}",
        }


class TomTomMapProvider:
    """TomTom static map and map-site links using the configured API key."""

    def __init__(self, context):
        self.options = context.options
        self.api_key = str(self.options.get("api_key", self.options.get("key", ""))).strip()
        self.static_image_endpoint = str(
            self.options.get(
                "static_image_endpoint", "https://api.tomtom.com/map/1/staticimage"
            )
        ).rstrip("?")
        self.web_base_url = str(
            self.options.get("web_base_url", "https://www.tomtom.com/map/")
        ).rstrip("/")

    def location_links(
        self,
        latitude: float,
        longitude: float,
        address: str = "",
    ) -> dict[str, str]:
        del address
        if not self.api_key:
            raise IntegrationFailure("TomTom map provider is missing api_key")
        zoom = int(self.options.get("zoom", 15))
        center = f"{longitude},{latitude}"
        image_query = urlencode(
            {
                "key": self.api_key,
                "zoom": zoom,
                "center": center,
                "format": self.options.get("format", "png"),
                "layer": self.options.get("layer", "basic"),
                "style": self.options.get("style", "main"),
                "width": int(self.options.get("width", 900)),
                "height": int(self.options.get("height", 450)),
            }
        )
        directions_image_query = urlencode(
            {
                "key": self.api_key,
                "zoom": zoom + 2,
                "center": center,
                "format": self.options.get("format", "png"),
                "layer": self.options.get("layer", "basic"),
                "style": self.options.get("style", "main"),
                "width": int(self.options.get("width", 900)),
                "height": int(self.options.get("height", 450)),
            }
        )
        map_url = f"{self.web_base_url}?{urlencode({'center': center, 'zoom': zoom})}"
        return {
            "provider": "tomtom",
            "image_url": f"{self.static_image_endpoint}?{image_query}",
            "directions_image_url": f"{self.static_image_endpoint}?{directions_image_query}",
            "directions_url": map_url,
            "map_url": map_url,
            "search_url": map_url,
        }
