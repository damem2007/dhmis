from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

TEETH = {str(i) for i in range(1, 33)} | set("ABCDEFGHIJKLMNOPQRST")


class ChartInput(BaseModel):
    patient_id: str
    encounter_id: str | None = None
    tooth: str
    surface: Literal["whole", "mesial", "distal", "buccal", "lingual", "occlusal"]
    condition: str = Field(min_length=1, max_length=100)
    notes: str = Field(default="", max_length=4000)

    @field_validator("tooth", mode="before")
    @classmethod
    def valid_tooth(cls, value):
        value = str(value).upper()
        if value not in TEETH:
            raise ValueError("Use adult 1–32 or primary A–T tooth identifiers")
        return value


class PerioSite(BaseModel):
    depths: list[int] = Field(min_length=6, max_length=6)
    bleeding: list[bool] = Field(min_length=6, max_length=6)
    recession: list[int] = Field(min_length=6, max_length=6)
    furcation: int = Field(ge=0, le=3)
    mobility: int = Field(ge=0, le=3)

    @field_validator("depths")
    @classmethod
    def valid_depths(cls, values):
        if any(x < 0 or x > 20 for x in values):
            raise ValueError("Pocket depths must be 0–20 mm")
        return values

    @field_validator("recession")
    @classmethod
    def valid_recession(cls, values):
        if any(x < -10 or x > 20 for x in values):
            raise ValueError("Recession must be -10 to 20 mm")
        return values


class PerioInput(BaseModel):
    patient_id: str
    encounter_id: str | None = None
    dentition: list[str] = Field(min_length=1, max_length=52)
    measurements: dict[str, PerioSite]
    status: Literal["draft", "complete"] = "draft"

    @model_validator(mode="after")
    def complete_exam(self):
        if len(set(self.dentition)) != len(self.dentition) or not set(self.dentition) <= TEETH:
            raise ValueError("Dentition must contain unique valid tooth identifiers")
        if not set(self.measurements) <= set(self.dentition):
            raise ValueError("Measurements must match present teeth")
        if self.status == "complete" and set(self.measurements) != set(self.dentition):
            raise ValueError("A complete exam requires six-site findings for every present tooth")
        return self


class ProcedureInput(BaseModel):
    service_id: str
    tooth: str | None = None
    quantity: int = Field(default=1, ge=1, le=32)

    @field_validator("tooth")
    @classmethod
    def valid_tooth(cls, value):
        if value is not None and value not in TEETH:
            raise ValueError("Invalid tooth")
        return value


class EncounterInput(BaseModel):
    soap: dict[str, str]
    procedures: list[ProcedureInput] = Field(default_factory=list, max_length=100)

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


class TreatmentPhase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    procedures: list[ProcedureInput] = Field(min_length=1, max_length=100)


class TreatmentOption(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    phases: list[TreatmentPhase] = Field(min_length=1, max_length=20)


class TreatmentInput(BaseModel):
    patient_id: str
    provider_id: str
    title: str = Field(min_length=1, max_length=200)
    options: list[TreatmentOption] = Field(min_length=1, max_length=8)


class Acceptance(BaseModel):
    option: int = Field(ge=0)


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
