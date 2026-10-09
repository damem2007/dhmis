import csv
import io
from datetime import date, datetime, time, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from app.core.audit import AuditEvent, audit
from app.core.repository import serialize
from app.identity.models import StaffUser
from app.identity.service import current_actor, db_session, permit, role_names_with_module
from app.organizations.models import Location

router = APIRouter(prefix="/organization", tags=["Organization"])


@router.get("/reference")
async def reference(db=Depends(db_session), actor=Depends(current_actor)):
    locations = (await db.scalars(select(Location))).all()
    providers = (
        await db.scalars(
            select(StaffUser).where(
                StaffUser.active, StaffUser.role.in_(await role_names_with_module(db, "clinical"))
            )
        )
    ).all()
    return {
        "locations": [serialize(x) for x in locations],
        "providers": [{"id": x.id, "name": x.name} for x in providers],
        "currency": "CAD",
    }


def audit_query(
    patient_id: str | None,
    actor_id: str | None,
    *,
    start: date | None = None,
    end: date | None = None,
    action: str | None = None,
    resource: str | None = None,
    location_id: str | None = None,
    outcome: str | None = None,
):
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    if patient_id:
        query = query.where(AuditEvent.details["patient_id"].as_string() == patient_id)
    if actor_id:
        query = query.where(AuditEvent.created_by == actor_id)
    if start:
        query = query.where(
            AuditEvent.created_at >= datetime.combine(start, time.min, tzinfo=timezone.utc)
        )
    if end:
        query = query.where(
            AuditEvent.created_at
            < datetime.combine(end + timedelta(days=1), time.min, tzinfo=timezone.utc)
        )
    if action:
        query = query.where(AuditEvent.action == action)
    if resource:
        query = query.where(AuditEvent.resource == resource)
    if location_id:
        query = query.where(AuditEvent.details["location_id"].as_string() == location_id)
    if outcome == "denied":
        query = query.where(AuditEvent.action.ilike("%denied%"))
    elif outcome == "success":
        query = query.where(~AuditEvent.action.ilike("%denied%"))
    return query


@router.get("/audit")
async def events(
    patient_id: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    rows = (await db.scalars(audit_query(patient_id, actor_id).limit(500))).all()
    audit(db, actor.user_id, "read", "audit_events")
    return [serialize(x) for x in rows]


@router.get("/audit/query")
async def query_events(
    patient_id: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    start: date | None = Query(default=None),
    end: date | None = Query(default=None),
    action: str | None = Query(default=None, max_length=80),
    resource: str | None = Query(default=None, max_length=100),
    location_id: str | None = Query(default=None),
    outcome: str | None = Query(default=None, pattern="^(success|denied)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
    db=Depends(db_session),
    actor=Depends(permit("settings")),
):
    if start and end and (end < start or (end - start).days > 366):
        raise HTTPException(422, "Audit range must be 0 to 366 days")
    query = audit_query(
        patient_id,
        actor_id,
        start=start,
        end=end,
        action=action,
        resource=resource,
        location_id=location_id,
        outcome=outcome,
    )
    total = await db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    rows = (
        await db.scalars(query.offset((page - 1) * page_size).limit(page_size))
    ).all()
    audit(db, actor.user_id, "read", "audit_events", page=page, page_size=page_size)
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [serialize(row) for row in rows],
    }


@router.get("/audit/export")
async def export_events(
    patient_id: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    start: date | None = Query(default=None),
    end: date | None = Query(default=None),
    action: str | None = Query(default=None, max_length=80),
    resource: str | None = Query(default=None, max_length=100),
    location_id: str | None = Query(default=None),
    outcome: str | None = Query(default=None, pattern="^(success|denied)$"),
    db=Depends(db_session),
    actor=Depends(permit("audit_export")),
):
    if start and end and (end < start or (end - start).days > 366):
        raise HTTPException(422, "Audit range must be 0 to 366 days")
    rows = (
        await db.scalars(
            audit_query(
                patient_id,
                actor_id,
                start=start,
                end=end,
                action=action,
                resource=resource,
                location_id=location_id,
                outcome=outcome,
            )
        )
    ).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "actor", "action", "resource", "resource_id", "details"])
    for row in rows:
        writer.writerow(
            [row.created_at.isoformat(), row.created_by, row.action, row.resource, row.resource_id, row.details]
        )
    audit(
        db,
        actor.user_id,
        "export",
        "audit_events",
        patient_id=patient_id or "",
        filters={
            "actor_id": actor_id or "",
            "start": start.isoformat() if start else "",
            "end": end.isoformat() if end else "",
            "action": action or "",
            "resource": resource or "",
            "location_id": location_id or "",
            "outcome": outcome or "",
        },
        count=len(rows),
    )
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="dhmis-audit.csv"'},
    )
