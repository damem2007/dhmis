from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record


class CmsRevision(Record, Base):
    __tablename__ = "cms_revisions"
    __table_args__ = {"schema": "tenant"}
    revision_number: Mapped[int] = mapped_column(Integer, unique=True)
    status: Mapped[str] = mapped_column(String(24), default="draft")
    base_revision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    applicability: Mapped[dict] = mapped_column(JSON, default=dict)
    validation: Mapped[dict] = mapped_column(JSON, default=dict)
    policy_versions: Mapped[dict] = mapped_column(JSON, default=dict)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published_by: Mapped[str] = mapped_column(String(100), default="")
    publication_key: Mapped[str | None] = mapped_column(String(100), nullable=True, unique=True)


class CmsPublicationPointer(Record, Base):
    __tablename__ = "cms_publication_pointers"
    __table_args__ = {"schema": "tenant"}
    scope_key: Mapped[str] = mapped_column(String(100), unique=True)
    location_id: Mapped[str | None] = mapped_column(
        ForeignKey("tenant.locations.id"), nullable=True
    )
    revision_id: Mapped[str] = mapped_column(ForeignKey("tenant.cms_revisions.id"))
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CmsMediaAsset(Record, Base):
    __tablename__ = "cms_media_assets"
    __table_args__ = (UniqueConstraint("revision_id", "asset_key"), {"schema": "tenant"})
    revision_id: Mapped[str] = mapped_column(ForeignKey("tenant.cms_revisions.id"))
    asset_key: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(30))
    file_name: Mapped[str] = mapped_column(String(220), default="")
    file_url: Mapped[str] = mapped_column(String(500), default="")
    mime_type: Mapped[str] = mapped_column(String(120), default="")
    alt_text: Mapped[str] = mapped_column(String(300), default="")
    consent: Mapped[dict] = mapped_column(JSON, default=dict)
    visible: Mapped[bool] = mapped_column(Boolean, default=True)
    content: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    content_sha256: Mapped[str] = mapped_column(String(64), default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
