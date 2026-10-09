from datetime import date

from pydantic import BaseModel, Field, field_validator, model_validator


class PatientCreate(BaseModel):
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)
    birth_date: date
    email: str = Field(default="", max_length=254)
    phone: str = Field(default="", max_length=40)
    allergies: list[str] = Field(default_factory=list, max_length=50)
    location_id: str

    @field_validator("first_name", "last_name")
    @classmethod
    def name_not_blank(cls, value):
        if not value.strip():
            raise ValueError("Name must not be blank")
        return value.strip()

    @field_validator("birth_date")
    @classmethod
    def not_future(cls, value):
        if value > date.today():
            raise ValueError("Birth date cannot be in the future")
        return value

    medical_history: str = Field(default="", max_length=5000)
    dental_history: str = Field(default="", max_length=5000)
    alerts: list[str] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def contact_required(self):
        if not self.email.strip() and not self.phone.strip():
            raise ValueError("At least one email or phone contact is required")
        if self.email and ("@" not in self.email or " " in self.email):
            raise ValueError("Invalid email address")
        return self
