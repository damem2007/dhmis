from dataclasses import dataclass
from typing import Protocol


# Defines the jurisdiction provider model, contract, or value object.
class JurisdictionProvider(Protocol):
    region: str
    currency: str
    locale: str
    claims_adapter: str

    # Handle defaults for this module.
    def defaults(self, organization_policy: dict) -> dict: ...


# Defines the canada jurisdiction model, contract, or value object.
@dataclass(frozen=True)
class CanadaJurisdiction:
    region: str = "CA"
    currency: str = "CAD"
    locale: str = "en-CA"
    claims_adapter: str = "Sandbox1_CDAnet"

    # Handle defaults for this module.
    def defaults(self, organization_policy):
        return {
            "currency": self.currency,
            "locale": self.locale,
            "claims_adapter": self.claims_adapter,
            "consent_notice": organization_policy.get(
                "consent_notice", "Sandbox consent — not for clinical use"
            ),
            "retention_days": organization_policy.get("retention_days"),
            "tax_rate_basis_points": organization_policy.get("tax_rate_basis_points", 0),
            "production_approved": False,
        }


# Defines the united states jurisdiction model, contract, or value object.
@dataclass(frozen=True)
class UnitedStatesJurisdiction:
    region: str = "US"
    currency: str = "USD"
    locale: str = "en-US"
    claims_adapter: str = "Sandbox1_ANSI_X12_835"

    # Handle defaults for this module.
    def defaults(self, organization_policy):
        return {
            "currency": self.currency,
            "locale": self.locale,
            "claims_adapter": self.claims_adapter,
            "consent_notice": organization_policy.get(
                "consent_notice", "Sandbox consent — not for clinical use"
            ),
            "retention_days": organization_policy.get("retention_days"),
            "tax_rate_basis_points": organization_policy.get("tax_rate_basis_points", 0),
            "production_approved": False,
        }


PROVIDERS = {"CA": CanadaJurisdiction(), "US": UnitedStatesJurisdiction()}


# Handle jurisdiction for this module.
def jurisdiction(region):
    return PROVIDERS[region]
