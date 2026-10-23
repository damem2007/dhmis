"""Request and response validation for tenant code-library operations."""

from datetime import date

from pydantic import BaseModel, Field


class ActivationInput(BaseModel):
    """Validate the licence attestation required before code import."""

    licence_holder: str = Field(min_length=1, max_length=180)
    licence_reference: str = Field(min_length=1, max_length=180)
    valid_until: date | None = None
    source_file_name: str = Field(default="", max_length=255)
    source_file_size: int = Field(default=0, ge=0, le=50_000_000)
    source_mime_type: str = Field(default="", max_length=120)
    source_content_base64: str = Field(default="", max_length=70_000_000)
    attested: bool


class CodeInput(BaseModel):
    """Validate one normalized procedure-code record."""

    code: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=4000)
    category: str = Field(default="", max_length=120)
    status: str = Field(default="active", pattern="^(active|retired)$")


class VersionImportInput(BaseModel):
    """Validate a version import and its normalized code rows."""

    version: str = Field(min_length=1, max_length=80)
    checksum: str = Field(min_length=8, max_length=128)
    source_file_name: str = Field(default="", max_length=255)
    source_file_size: int = Field(default=0, ge=0, le=50_000_000)
    source_mime_type: str = Field(default="", max_length=120)
    source_content_base64: str = Field(default="", max_length=70_000_000)
    codes: list[CodeInput] = Field(min_length=1, max_length=100_000)


class MappingInput(BaseModel):
    """Validate a service-to-code mapping request."""

    service_id: str = Field(min_length=1, max_length=36)
    procedure_code_id: str = Field(min_length=1, max_length=36)
