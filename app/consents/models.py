from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class Consent(Record, Base):
    __tablename__ = "consents"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    title: Mapped[str] = mapped_column(String(180))
    template_version: Mapped[str] = mapped_column(String(30), default="1")
    status: Mapped[str] = mapped_column(String(30), default="requested")
    certificate: Mapped[dict] = mapped_column(JSON, default=dict)
