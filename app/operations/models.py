from datetime import date

from sqlalchemy import Boolean, Date, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class ProviderCredential(Record, Base):
    __tablename__ = "provider_credentials"
    __table_args__ = {"schema": "tenant"}
    provider_id: Mapped[str] = mapped_column(ForeignKey("tenant.staff_users.id"))
    location_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.locations.id"), nullable=True
    )
    credential_type: Mapped[str] = mapped_column(String(120))
    credential_number: Mapped[str] = mapped_column(String(160))
    jurisdiction: Mapped[str] = mapped_column(String(80))
    issued_on: Mapped[date] = mapped_column(Date)
    expires_on: Mapped[date] = mapped_column(Date)
    alert_lead_days: Mapped[int] = mapped_column(Integer, default=60)
    required: Mapped[bool] = mapped_column(Boolean, default=True)

