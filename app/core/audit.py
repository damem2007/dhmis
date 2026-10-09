from contextvars import ContextVar

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.models import Base, Record

request_context = ContextVar("request_context", default={})


class AuditEvent(Record, Base):
    __tablename__ = "audit_events"
    __table_args__ = {"schema": "tenant"}
    action: Mapped[str] = mapped_column(String(80))
    resource: Mapped[str] = mapped_column(String(100))
    resource_id: Mapped[str] = mapped_column(String(100), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


def audit(db, actor, action, resource, resource_id="", **details):
    details = {**request_context.get(), **details}
    actor_context = db.info.get("actor")
    if actor_context:
        details.setdefault("organization_id", actor_context.organization.id)
    if resource in ("patients", "clinical", "ledger", "consents") and resource_id:
        details.setdefault("patient_id", resource_id)
    db.add(
        AuditEvent(
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=details,
            created_by=actor,
            updated_by=actor,
        )
    )
