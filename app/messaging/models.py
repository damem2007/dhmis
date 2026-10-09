from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class MessageThread(Record, Base):
    __tablename__ = "message_threads"
    __table_args__ = {"schema": "tenant"}
    patient_id: Mapped[str] = mapped_column(ForeignKey("tenant.patients.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    subject: Mapped[str] = mapped_column(String(180))
    status: Mapped[str] = mapped_column(String(30), default="open")


class Message(Record, Base):
    __tablename__ = "messages"
    __table_args__ = {"schema": "tenant"}
    thread_id: Mapped[str] = mapped_column(ForeignKey("tenant.message_threads.id"))
    location_id: Mapped[str] = mapped_column(ForeignKey("tenant.locations.id"))
    sender_type: Mapped[str] = mapped_column(String(20))
    sender_id: Mapped[str] = mapped_column(String(36))
    body_cipher: Mapped[str] = mapped_column(Text)
