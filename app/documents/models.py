from sqlalchemy import ForeignKey, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class Document(Record, Base):
    __tablename__ = "documents"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    category: Mapped[str] = mapped_column(String(30))
    filename: Mapped[str] = mapped_column(String(220))
    mime_type: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(500), default="")
    comparison_group: Mapped[str] = mapped_column(String(80), default="")
    content: Mapped[bytes] = mapped_column(LargeBinary)
