from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class AnalyticsActionItem(Record, Base):
    __tablename__ = "analytics_action_items"
    __table_args__ = {"schema": "tenant"}
    dedupe_key: Mapped[str] = mapped_column(String(180), unique=True)
    category: Mapped[str] = mapped_column(String(60))
    title: Mapped[str] = mapped_column(String(240))
    detail: Mapped[str] = mapped_column(String(1000), default="")
    severity: Mapped[str] = mapped_column(String(20), default="info")
    status: Mapped[str] = mapped_column(String(30), default="open")
    role_scopes: Mapped[list] = mapped_column(JSON, default=list)
    location_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    provider_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    patient_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target: Mapped[dict] = mapped_column(JSON, default=dict)
    source_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
