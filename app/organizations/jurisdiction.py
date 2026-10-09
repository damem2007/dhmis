from dataclasses import dataclass
from typing import Protocol


class JurisdictionProvider(Protocol):
    region: str
    currency: str
    locale: str
    claims_adapter: str

    def defaults(self, organization_policy: dict) -> dict: ...


@dataclass(frozen=True)
class CanadaJurisdiction:
    region: str = "CA"
    currency: str = "CAD"
    locale: str = "en-CA"
    claims_adapter: str = "Sandbox1_CDAnet"

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


@dataclass(frozen=True)
class UnitedStatesJurisdiction:
    region: str = "US"
    currency: str = "USD"
    locale: str = "en-US"
    claims_adapter: str = "Sandbox1_ANSI_X12_835"

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


def jurisdiction(region):
    return PROVIDERS[region]
