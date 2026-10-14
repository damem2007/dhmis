from pydantic import AwareDatetime, BaseModel, Field, model_validator


# Defines the booking model, contract, or value object.
class Booking(BaseModel):
    patient_id: str
    location_id: str
    provider_id: str
    chair: str = Field(min_length=1, max_length=40)
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    procedure: str = Field(min_length=1, max_length=180)

    # Handle valid duration for this module.
    @model_validator(mode="after")
    def valid_duration(self):
        seconds = (self.ends_at - self.starts_at).total_seconds()
        if seconds <= 0 or seconds > 8 * 3600:
            raise ValueError("Appointment duration must be between 1 second and 8 hours")
        return self


# Defines the cancellation model, contract, or value object.
class Cancellation(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


# Defines the series booking model, contract, or value object.
class SeriesBooking(Booking):
    occurrences: int = Field(ge=2, le=52)
    interval_days: int = Field(ge=1, le=365, default=7)


# Defines the no show model, contract, or value object.
class NoShow(BaseModel):
    reason: str = Field(min_length=3, max_length=500, default="Patient did not attend")
