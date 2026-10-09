from sqlalchemy import JSON, Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class FormTemplate(Record, Base):
    __tablename__ = "form_templates"
    __table_args__ = {"schema": "tenant"}
    title: Mapped[str] = mapped_column(String(180))
    version: Mapped[str] = mapped_column(String(30))
    fields: Mapped[list] = mapped_column(JSON)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class FormSubmission(Record, Base):
    __tablename__ = "form_submissions"
    __table_args__ = {"schema": "tenant"}
    template_id: Mapped[str] = mapped_column(ForeignKey("tenant.form_templates.id"))
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    template_version: Mapped[str] = mapped_column(String(30))
    responses: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(30), default="completed")
    certificate: Mapped[dict] = mapped_column(JSON, default=dict)
