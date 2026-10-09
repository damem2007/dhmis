"""Central location visibility for tenant-owned clinical/financial records."""

from fastapi import HTTPException
from sqlalchemy import event
from sqlalchemy.orm import Session, with_loader_criteria

from app.core.models import Base


@event.listens_for(Session, "do_orm_execute")
def restrict_reads(state):
    actor = state.session.info.get("actor")
    if (
        not actor
        or actor.assignment_scope == "organization"
        or actor.settings is None
        or actor.settings.visibility != "location"
        or not state.is_select
    ):
        return
    allowed = tuple(actor.location_ids)
    for mapper in Base.registry.mappers:
        model = mapper.class_
        if hasattr(model, "location_id"):
            state.statement = state.statement.options(
                with_loader_criteria(model, model.location_id.in_(allowed), include_aliases=True)
            )


@event.listens_for(Session, "before_flush")
def restrict_writes(session, context, instances):
    actor = session.info.get("actor")
    if not actor or actor.assignment_scope == "organization" or actor.settings is None or actor.settings.visibility != "location":
        return
    for record in session.new.union(session.dirty):
        location = getattr(record, "location_id", None)
        if location is not None and location not in actor.location_ids:
            raise HTTPException(403, "Record is outside assigned locations")
