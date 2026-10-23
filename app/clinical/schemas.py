from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

TEETH = {str(i) for i in range(1, 33)} | set("ABCDEFGHIJKLMNOPQRST")


# Defines the chart input model, contract, or value object.
class ChartInput(BaseModel):
    patient_id: str
    encounter_id: str | None = None
    tooth: str
    surface: Literal["whole", "mesial", "distal", "buccal", "lingual", "occlusal"]
    condition: str = Field(min_length=1, max_length=100)
    notes: str = Field(default="", max_length=4000)

    # Handle valid tooth for this module.
    @field_validator("tooth", mode="before")
    @classmethod
    def valid_tooth(cls, value):
        value = str(value).upper()
        if value not in TEETH:
            raise ValueError("Use adult 1–32 or primary A–T tooth identifiers")
        return value


# Defines the perio site model, contract, or value object.
class PerioSite(BaseModel):
    depths: list[int] = Field(min_length=6, max_length=6)
    bleeding: list[bool] = Field(min_length=6, max_length=6)
    recession: list[int] = Field(min_length=6, max_length=6)
    furcation: int = Field(ge=0, le=3)
    mobility: int = Field(ge=0, le=3)

    # Handle valid depths for this module.
    @field_validator("depths")
    @classmethod
    def valid_depths(cls, values):
        if any(x < 0 or x > 20 for x in values):
            raise ValueError("Pocket depths must be 0–20 mm")
        return values

    # Handle valid recession for this module.
    @field_validator("recession")
    @classmethod
    def valid_recession(cls, values):
        if any(x < -10 or x > 20 for x in values):
            raise ValueError("Recession must be -10 to 20 mm")
        return values


# Defines the perio input model, contract, or value object.
class PerioInput(BaseModel):
    patient_id: str
    encounter_id: str | None = None
    dentition: list[str] = Field(min_length=1, max_length=52)
    measurements: dict[str, PerioSite]
    status: Literal["draft", "complete"] = "draft"

    # Handle complete exam for this module.
    @model_validator(mode="after")
    def complete_exam(self):
        if len(set(self.dentition)) != len(self.dentition) or not set(self.dentition) <= TEETH:
            raise ValueError("Dentition must contain unique valid tooth identifiers")
        if not set(self.measurements) <= set(self.dentition):
            raise ValueError("Measurements must match present teeth")
        if self.status == "complete" and set(self.measurements) != set(self.dentition):
            raise ValueError("A complete exam requires six-site findings for every present tooth")
        return self


# Defines the procedure input model, contract, or value object.
class ProcedureInput(BaseModel):
    service_id: str | None = Field(default=None, max_length=36)
    catalogue_item_id: str | None = Field(default=None, max_length=36)
    tooth: str | None = None
    tooth_scope: Literal["all"] | None = None
    surface: str | None = Field(default=None, max_length=30)
    area: str | None = Field(default=None, max_length=160)
    quantity: int = Field(default=1, ge=1, le=32)

    # Handle valid tooth for this module.
    @field_validator("tooth", mode="before")
    @classmethod
    def valid_tooth(cls, value):
        if value is None:
            return None
        value = str(value).strip().upper()
        if not value:
            return None
        if value not in TEETH:
            raise ValueError("Use adult 1–32 or primary A–T tooth identifiers")
        return value


# Defines the encounter input model, contract, or value object.
class EncounterInput(BaseModel):
    soap: dict[str, str]
    procedures: list[ProcedureInput] = Field(default_factory=list, max_length=100)
    provider_id: str | None = Field(default=None, min_length=36, max_length=36)

    # Handle valid soap for this module.
    @field_validator("soap")
    @classmethod
    def valid_soap(cls, value):
        if set(value) - {"subjective", "objective", "assessment", "plan"} or any(
            len(v) > 8000 for v in value.values()
        ):
            raise ValueError(
                "SOAP supports subjective, objective, assessment and plan, up to 8000 characters each"
            )
        return value


# Defines the input used when finalizing an encounter.
class EncounterCompletionInput(BaseModel):
    reason: str = Field(default="Encounter finalized from the clinical chart", min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, min_length=1, max_length=80)


class MissingToothReturnInput(BaseModel):
    """Reason and approval reference for reinstating a missing-tooth entry."""

    reason: str = Field(min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, min_length=1, max_length=80)


# Defines the treatment phase model, contract, or value object.
class TreatmentPhase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    procedures: list[ProcedureInput] = Field(min_length=1, max_length=100)


# Defines the treatment option model, contract, or value object.
class TreatmentOption(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    phases: list[TreatmentPhase] = Field(min_length=1, max_length=20)


# Defines the treatment input model, contract, or value object.
class TreatmentInput(BaseModel):
    patient_id: str
    provider_id: str
    title: str = Field(min_length=1, max_length=200)
    options: list[TreatmentOption] = Field(min_length=1, max_length=8)


class CatalogueItemInput(BaseModel):
    """Validate a tenant treatment, condition, or tooth-status catalogue item."""

    item_type: Literal["treatment", "condition", "tooth_status"]
    code: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=180)
    description: str = Field(default="", max_length=1000)
    category: str = Field(default="", max_length=80)
    service_id: str | None = Field(default=None, max_length=36)
    fee_cents: int = Field(default=0, ge=0, le=10000000)
    procedure_code_id: str | None = Field(default=None, max_length=36)
    fee_source: str = Field(default="services", max_length=40)
    quick_chart: bool = False
    appearance_key: str = Field(default="healthy", max_length=60)
    draw_on: str = Field(default="", max_length=40)
    resolved_by: str = Field(default="", max_length=40)
    tooth_status_effect: str = Field(default="", max_length=40)
    applies_to: Literal["none", "tooth", "tooth_surface", "quadrant", "arch", "whole_mouth"] = "whole_mouth"
    allowed_surfaces: list[str] = Field(default_factory=lambda: ["whole"], max_length=8)

    @model_validator(mode="after")
    def chart_only_items_have_no_fee(self):
        """Only treatment/procedure entries may carry a service or fee."""
        if self.item_type != "treatment":
            if self.service_id is not None:
                raise ValueError("Only treatment/procedure entries can link a Services & fees entry")
            self.fee_source = "none"
            self.fee_cents = 0
        if self.item_type != "condition":
            self.quick_chart = False
        return self


class ConditionTreatmentLinkInput(BaseModel):
    condition_ids: list[str] = Field(default_factory=list, max_length=100)
    relationship_type: Literal["may_resolve", "may_treat"] = "may_resolve"


class ResolutionProcedureLinksInput(BaseModel):
    """Select the reusable procedures that may resolve one condition definition."""

    treatment_ids: list[str] = Field(default_factory=list, max_length=100)


class CatalogueOptionInput(BaseModel):
    """Validate a tenant-owned catalogue category option."""

    option_type: Literal["category"] = "category"
    item_type: Literal["treatment", "condition", "tooth_status"]
    value: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=120)
    sort_order: int = Field(default=0, ge=0, le=100000)


class QuickChartSetInput(BaseModel):
    """Validate an ordered Quick chart shortcut set."""

    name: str = Field(min_length=1, max_length=160)
    description: str = Field(default="", max_length=1000)
    items: list[str] = Field(default_factory=list, max_length=200)


class QuoteInput(BaseModel):
    """Select one treatment-plan option for an immutable quote snapshot."""

    option_index: int = Field(ge=0)


# Defines the acceptance model, contract, or value object.
class Acceptance(BaseModel):
    option: int = Field(ge=0)


# Defines the addendum input model, contract, or value object.
class AddendumInput(BaseModel):
    record_type: Literal[
        "encounter",
        "perio_exam",
        "treatment_plan",
        "day_surgery",
        "form_submission",
    ]
    record_id: str = Field(min_length=1, max_length=36)
    reason: str = Field(min_length=10, max_length=1000)
    content: dict = Field(min_length=1)
    approval_request_id: str | None = Field(default=None, max_length=36)


class ClinicalChartSettingsInput(BaseModel):
    """Validate persisted, tenant-wide clinical chart display preferences."""

    save_mode: Literal["manual", "auto"] = "manual"
    enabled_numbering_systems: list[Literal["universal", "fdi", "palmer"]] = Field(
        default_factory=lambda: ["universal"], min_length=1, max_length=3
    )
    default_numbering_system: Literal["universal", "fdi", "palmer"] = "universal"
    procedure_code_set: str = Field(default="", max_length=120)
    dentition_age_ranges: dict[str, int | None] = Field(
        default_factory=lambda: {"primary_max_years": 11, "mixed_max_years": 21}
    )

    @model_validator(mode="after")
    def validate_preferences(self):
        """Ensure the default system is enabled and configured age ranges are ordered."""
        if len(set(self.enabled_numbering_systems)) != len(self.enabled_numbering_systems):
            raise ValueError("Numbering systems cannot be duplicated")
        if self.default_numbering_system not in self.enabled_numbering_systems:
            raise ValueError("The default numbering system must be enabled")
        if set(self.dentition_age_ranges) - {"primary_max_years", "mixed_max_years"}:
            raise ValueError("Unknown dentition age range")
        primary = self.dentition_age_ranges.get("primary_max_years")
        mixed = self.dentition_age_ranges.get("mixed_max_years")
        if primary is not None and primary < 0:
            raise ValueError("Primary dentition age must be non-negative")
        if mixed is not None and mixed < 0:
            raise ValueError("Mixed dentition age must be non-negative")
        if primary is not None and mixed is not None and primary >= mixed:
            raise ValueError("Primary dentition age must be below mixed dentition age")
        return self
