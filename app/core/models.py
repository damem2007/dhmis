from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


# Defines the base model, contract, or value object.
class Base(DeclarativeBase):
    pass


# Handle utcnow for this module.
def utcnow():
    return datetime.now(UTC)


# Defines the record model, contract, or value object.
class Record:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    created_by: Mapped[str] = mapped_column(String(100), default="system")
    updated_by: Mapped[str] = mapped_column(String(100), default="system")
