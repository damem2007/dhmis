from pydantic import BaseModel, Field, model_validator


class ConsentEvidence(BaseModel):
    confirmed: bool = False
    confirmed_by: str = Field(default="", max_length=160)
    confirmed_at: str = Field(default="", max_length=80)
    source: str = Field(default="", max_length=120)
    document_reference: str = Field(default="", max_length=240)


class MediaInput(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    kind: str = Field(pattern="^(hero|provider|gallery|testimonial)$")
    file_name: str = Field(default="", max_length=220)
    file_url: str = Field(default="", max_length=500)
    mime_type: str = Field(default="", max_length=120)
    alt_text: str = Field(default="", max_length=300)
    consent: ConsentEvidence = Field(default_factory=ConsentEvidence)
    visible: bool = True


class ServiceInput(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=180)
    icon: str = Field(default="tooth", max_length=80)
    description: str = Field(default="", max_length=90)
    fee_mode: str = Field(default="from", pattern="^(from|free|contact)$")
    fee_cents: int | None = Field(default=None, ge=0)
    visible: bool = True
    order: int = Field(default=0, ge=0, le=10000)

    @model_validator(mode="after")
    def fee(self):
        if self.fee_mode == "from" and self.fee_cents is None:
            raise ValueError("A starting fee is required when fee display is From")
        return self


class DentistInput(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=160)
    role: str = Field(default="Dentist", max_length=120)
    biography: str = Field(default="", max_length=160)
    languages: list[str] = Field(default_factory=list, max_length=20)
    accepting_new_patients: bool = False
    bookable_online: bool = False
    photo_key: str = Field(default="", max_length=100)
    visible: bool = True
    order: int = Field(default=0, ge=0, le=10000)


class LocationContentInput(BaseModel):
    location_id: str = Field(min_length=36, max_length=36)
    name: str = Field(default="", max_length=180)
    address: str = Field(default="", max_length=500)
    phone: str = Field(default="", max_length=40)
    email: str = Field(default="", max_length=254)
    timezone: str = Field(default="", max_length=80)
    hours: dict[str, str] = Field(default_factory=dict)
    closure_note: str = Field(default="", max_length=500)
    visible: bool = True


class TestimonialInput(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    quote: str = Field(min_length=2, max_length=1000)
    attribution: str = Field(default="", max_length=160)
    consent: ConsentEvidence = Field(default_factory=ConsentEvidence)
    visible: bool = True


class CmsContentInput(BaseModel):
    headline: str = Field(min_length=2, max_length=180)
    introduction: str = Field(default="", max_length=2000)
    contact_email: str = Field(default="", max_length=254)
    contact_phone: str = Field(default="", max_length=40)
    address: str = Field(default="", max_length=500)
    brand: dict[str, str] = Field(default_factory=dict)
    services: list[ServiceInput] = Field(default_factory=list, max_length=200)
    dentists: list[DentistInput] = Field(default_factory=list, max_length=200)
    locations: list[LocationContentInput] = Field(default_factory=list, max_length=100)
    media: list[MediaInput] = Field(default_factory=list, max_length=500)
    testimonials_enabled: bool = False
    regulator_declaration: bool = False
    testimonials: list[TestimonialInput] = Field(default_factory=list, max_length=200)


class ApplicabilityInput(BaseModel):
    scope: str = Field(default="organization", pattern="^(organization|location)$")
    location_ids: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def scope_locations(self):
        unique = list(dict.fromkeys(self.location_ids))
        if len(unique) != len(self.location_ids):
            raise ValueError("Location scope cannot contain duplicates")
        if self.scope == "organization" and self.location_ids:
            raise ValueError("Organization scope does not list locations")
        if self.scope == "location" and not self.location_ids:
            raise ValueError("Location scope requires at least one location")
        return self


class DraftInput(BaseModel):
    content: CmsContentInput
    applicability: ApplicabilityInput
    expected_updated_at: str | None = None


class MediaUploadInput(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    kind: str = Field(pattern="^(hero|provider|gallery|testimonial)$")
    file_name: str = Field(min_length=1, max_length=220)
    mime_type: str = Field(pattern="^image/(jpeg|png|webp)$")
    content_base64: str = Field(min_length=4)
    alt_text: str = Field(default="", max_length=300)
    consent: ConsentEvidence = Field(default_factory=ConsentEvidence)
    visible: bool = True
    expected_updated_at: str | None = None


class PublishInput(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=100)
    expected_updated_at: str
    confirmed_scope: str = Field(pattern="^(organization|location)$")
    confirmed_location_ids: list[str] = Field(default_factory=list, max_length=100)
    reason: str = Field(default="Publish CMS revision", min_length=8, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)
