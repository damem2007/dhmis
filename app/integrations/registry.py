"""Ajo-style registration + organization configuration; optional installed-package plugins.
Domain callers depend on contracts, never vendor names. Unknown providers fail closed.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib.metadata import entry_points

from app.core.config import settings
from app.integrations.contracts import (
    ClaimsNetwork,
    AccountingExporter,
    GeocodingProvider,
    IntegrationFailure,
    MapProvider,
    MessagingProvider,
    PaymentGateway,
    SignatureProvider,
)
from app.integrations.geocoding_providers import (
    NominatimGeocodingProvider,
    OverpassAddressProvider,
    PhotonGeocodingProvider,
    PostalAwareGeocodingProvider,
    TomTomGeocodingProvider,
)
from app.integrations.map_providers import OpenStreetMapProvider, TomTomMapProvider
from app.integrations.sandboxes import (
    SandboxAccounting,
    SandboxClaims,
    SandboxMessaging,
    SandboxPayments,
    SandboxSignatures,
)


@dataclass(frozen=True)
class ProviderContext:
    organization_id: str
    region: str
    options: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Registration:
    factory: Callable
    sandbox: bool


CONTRACTS = {
    "payment_gateway": PaymentGateway,
    "claims_network": ClaimsNetwork,
    "signature_provider": SignatureProvider,
    "messaging_provider": MessagingProvider,
    "email_provider": MessagingProvider,
    "sms_provider": MessagingProvider,
    "accounting_exporter": AccountingExporter,
    "geocoding_provider": GeocodingProvider,
    "map_provider": MapProvider,
}
REGISTRY = {capability: {} for capability in CONTRACTS}


def register_provider(capability, name, factory, *, sandbox=False):
    if capability not in CONTRACTS or not name or name in REGISTRY[capability]:
        raise ValueError("Invalid or duplicate provider registration")
    REGISTRY[capability][name] = Registration(factory, sandbox)


def selected_provider(organization, capability):
    selected = getattr(organization, "_effective_adapters", None)
    if selected is None:
        raise IntegrationFailure("Adapter configuration context was not loaded")
    name = selected.get(capability)
    if name is None:
        raise IntegrationFailure("No platform adapter default is configured for this capability")
    return name


def provider_options(*, include_live: bool | None = None):
    """Return selectable names without exposing provider factories or credentials."""
    allow_live = settings().allow_live_integrations if include_live is None else include_live
    return {
        capability: sorted(
            name
            for name, registration in registrations.items()
            if registration.sandbox or allow_live
        )
        for capability, registrations in REGISTRY.items()
    }


def resolve(organization, capability):
    name = selected_provider(organization, capability)
    return resolve_registered(
        capability,
        name,
        organization_id=organization.id,
        region=organization.region,
    )


def resolve_registered(
    capability: str,
    name: str,
    *,
    organization_id: str = "",
    region: str = "*",
    enforce_live: bool = True,
):
    registration = REGISTRY.get(capability, {}).get(name)
    if registration is None:
        raise IntegrationFailure("Selected provider has no installed adapter")
    if enforce_live and not registration.sandbox and not settings().allow_live_integrations:
        raise IntegrationFailure("Live providers are disabled for the Phase 1 sandbox release")
    context = ProviderContext(
        organization_id,
        region,
        settings().provider_options.get(name, {}),
    )
    instance = registration.factory(context)
    if not isinstance(instance, CONTRACTS[capability]):
        raise IntegrationFailure("Provider does not implement the required contract")
    return instance


for capability, cls in [
    ("payment_gateway", SandboxPayments),
    ("signature_provider", SandboxSignatures),
    ("messaging_provider", SandboxMessaging),
    ("email_provider", SandboxMessaging),
    ("sms_provider", SandboxMessaging),
    ("accounting_exporter", SandboxAccounting),
]:
    register_provider(capability, "sandbox", lambda context, cls=cls: cls(), sandbox=True)
    register_provider(capability, "sandbox-timeout", lambda context, cls=cls: cls("timeout"), sandbox=True)
register_provider(
    "payment_gateway", "sandbox-decline", lambda context: SandboxPayments("decline"), sandbox=True
)
for name, region, mode, latency in [
    ("Sandbox1_CDAnet", "CA", "success", 0),
    ("Sandbox2_USAdapter", "US", "success", 0),
    ("sandbox-denied", "CA", "deny", 0),
    ("sandbox-timeout", "CA", "timeout", 0),
    ("sandbox-latency", "CA", "success", 100),
]:
    register_provider(
        "claims_network",
        name,
        lambda context, region=region, mode=mode, latency=latency: SandboxClaims(region, mode, latency),
        sandbox=True,
    )


def load_installed_plugins():
    # Only explicitly installed Python packages are executable. Tenant settings never accept module paths.
    for plugin in entry_points(group="dhmis.providers"):
        plugin.load()(register_provider)


load_installed_plugins()

# Built-in live providers are registered but remain hidden and unusable until
# ALLOW_LIVE_INTEGRATIONS is enabled. Their credentials are read only when selected.
from app.integrations.email_providers import MailjetEmailProvider, SMTPEmailProvider  # noqa: E402

register_provider("email_provider", "smtp", SMTPEmailProvider)
register_provider("email_provider", "mailjet", MailjetEmailProvider)
register_provider("geocoding_provider", "nominatim", NominatimGeocodingProvider, sandbox=True)
register_provider("geocoding_provider", "tomtom", TomTomGeocodingProvider)
register_provider("geocoding_provider", "photon", PhotonGeocodingProvider, sandbox=True)
register_provider("geocoding_provider", "overpass-addresses", OverpassAddressProvider, sandbox=True)
register_provider("geocoding_provider", "postal-aware", PostalAwareGeocodingProvider, sandbox=True)
register_provider("map_provider", "openstreetmap", OpenStreetMapProvider, sandbox=True)
register_provider("map_provider", "tomtom", TomTomMapProvider)
