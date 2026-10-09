from sqlalchemy import Boolean, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class PlatformRegion(Record, Base):
    """Platform-owned source of truth for supported onboarding regions."""

    __tablename__ = "platform_regions"
    __table_args__ = {"schema": "dhmis_control"}
    code: Mapped[str] = mapped_column(String(2), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    jurisdiction_provider: Mapped[str] = mapped_column(String(80))
    claims_route: Mapped[str] = mapped_column(String(120))
    locale: Mapped[str] = mapped_column(String(30))
    currency: Mapped[str] = mapped_column(String(3))
    tax_defaults: Mapped[dict] = mapped_column(JSON, default=dict)
    residency_defaults: Mapped[dict] = mapped_column(JSON, default=dict)
