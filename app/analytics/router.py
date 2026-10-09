import csv
import io
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.analytics.catalogue import public_catalogue
from app.analytics.models import AnalyticsActionItem
from app.analytics.scope import resolve_scope
from app.analytics.service import (
    ROLE_METRICS,
    calculate_metrics,
    organization_breakdown,
    project_actions,
    visible_actions,
    worklist,
)
from app.core.audit import audit
from app.core.repository import required, serialize
from app.identity.service import db_session, permit

router = APIRouter(prefix="/analytics", tags=["Role dashboards and analytics"])
PERIODS = {"today", "yesterday", "week", "month", "quarter", "ytd", "custom"}


def date_window(period: str, start: date | None, end: date | None):
    if period not in PERIODS:
        raise HTTPException(422, "Unknown analytics date range")
    today = datetime.now(UTC).date()
    if period == "today":
        beginning = ending = today
    elif period == "yesterday":
        beginning = ending = today - timedelta(days=1)
    elif period == "week":
        beginning, ending = today - timedelta(days=today.weekday()), today
    elif period == "month":
        beginning, ending = today.replace(day=1), today
    elif period == "quarter":
        month = ((today.month - 1) // 3) * 3 + 1
        beginning, ending = today.replace(month=month, day=1), today
    elif period == "ytd":
        beginning, ending = today.replace(month=1, day=1), today
    else:
        if start is None or end is None:
            raise HTTPException(422, "Custom analytics range requires start and end")
        beginning, ending = start, end
    if ending < beginning or (ending - beginning).days > 366:
        raise HTTPException(422, "Analytics range must be 0 to 366 days")
    return beginning, ending


class ActionUpdate(BaseModel):
    status: str = Field(pattern="^(open|in_progress|resolved|dismissed|not_applicable)$")
    note: str = Field(default="", max_length=1000)


@router.get("/catalogue")
async def catalogue(actor=Depends(permit("analytics"))):
    return {"catalogue_version": "1.0", "metrics": public_catalogue()}


@router.get("/dashboard")
async def role_dashboard(
    period: str = Query(default="today"),
    start: date | None = Query(default=None),
    end: date | None = Query(default=None),
    location_id: str | None = Query(default=None),
    provider_id: str | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("analytics")),
):
    beginning, ending = date_window(period, start, end)
    scope = resolve_scope(actor, location_id, provider_id)
    await project_actions(db, actor, scope)
    metrics = await calculate_metrics(db, scope, beginning, ending)
    actions = await visible_actions(db, scope, status="open", limit=10)
    generated = datetime.now(UTC)
    audit(
        db,
        actor.user_id,
        "analytics.read",
        "dashboard",
        role_profile=scope.profile,
        start=beginning.isoformat(),
        end=ending.isoformat(),
        location_ids=list(scope.location_ids),
        provider_id=scope.provider_id,
    )
    return {
        "role_profile": scope.profile,
        "period": period,
        "start": beginning,
        "end": ending,
        "scope": {
            "location_ids": scope.location_ids,
            "provider_id": scope.provider_id,
            "can_export": scope.can_export,
        },
        "freshness": {
            "last_updated": generated,
            "mode": "near-real-time",
            "catalogue_version": "1.0",
        },
        "metrics": metrics,
        "actions": actions,
    }


@router.get("/actions")
async def actions(
    status: str | None = Query(default=None, pattern="^(open|in_progress|resolved|dismissed|not_applicable)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
    location_id: str | None = Query(default=None),
    provider_id: str | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("analytics")),
):
    scope = resolve_scope(actor, location_id, provider_id)
    rows = await visible_actions(db, scope, status=status, limit=page * page_size + 1)
    start_index = (page - 1) * page_size
    return {
        "page": page,
        "page_size": page_size,
        "items": rows[start_index : start_index + page_size],
        "has_more": len(rows) > start_index + page_size,
    }


@router.get("/organization-summary")
async def organization_summary(
    period: str = Query(default="month"),
    start: date | None = Query(default=None),
    end: date | None = Query(default=None),
    location_id: str | None = Query(default=None),
    db=Depends(db_session),
    actor=Depends(permit("analytics")),
):
    beginning, ending = date_window(period, start, end)
    scope = resolve_scope(actor, location_id)
    if scope.profile not in {"organization-executive", "clinic-admin"}:
        raise HTTPException(403, "Organization summary is outside the authorized role scope")
    result = await organization_breakdown(db, scope, beginning, ending)
    audit(
        db,
        actor.user_id,
        "analytics.read",
        "organization-summary",
        start=beginning.isoformat(),
        end=ending.isoformat(),
        location_ids=list(scope.location_ids),
    )
    return result


@router.put("/actions/{identifier}")
async def update_action(
    identifier: str,
    body: ActionUpdate,
    db=Depends(db_session),
    actor=Depends(permit("analytics")),
):
    scope = resolve_scope(actor)
    row = await required(db, AnalyticsActionItem, identifier, lock=True)
    if row.role_scopes and scope.profile not in row.role_scopes:
        raise HTTPException(403, "Action is outside the authorized role scope")
    if scope.location_ids and row.location_id and row.location_id not in scope.location_ids:
        raise HTTPException(403, "Action is outside the authorized location scope")
    if scope.provider_id and row.provider_id and row.provider_id != scope.provider_id:
        raise HTTPException(403, "Action is outside the authorized provider scope")
    previous = row.status
    row.status = body.status
    row.updated_by = actor.user_id
    audit(
        db,
        actor.user_id,
        "analytics.action-status",
        "analytics_action_items",
        row.id,
        previous_status=previous,
        status=body.status,
        note=body.note,
    )
    return serialize(row)


@router.get("/worklists/{key}")
async def metric_worklist(
    key: str,
    period: str = Query(default="today"),
    start: date | None = Query(default=None),
    end: date | None = Query(default=None),
    location_id: str | None = Query(default=None),
    provider_id: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
    search: str = Query(default="", max_length=120),
    db=Depends(db_session),
    actor=Depends(permit("analytics")),
):
    beginning, ending = date_window(period, start, end)
    scope = resolve_scope(actor, location_id, provider_id)
    if key not in ROLE_METRICS.get(scope.profile, []):
        raise HTTPException(403, "Metric is outside the authorized role scope")
    effective_key = "collections" if key == "collection_rate" else key
    try:
        result = await worklist(
            db,
            effective_key,
            scope,
            beginning,
            ending,
            page=page,
            page_size=page_size,
            search=search,
        )
    except KeyError:
        raise HTTPException(404, "Metric worklist is not available") from None
    audit(db, actor.user_id, "analytics.drilldown", key, page=page, page_size=page_size)
    result["metric_key"] = key
    return result


@router.get("/worklists/{key}/export")
async def export_metric_worklist(
    key: str,
    period: str = Query(default="today"),
    start: date | None = Query(default=None),
    end: date | None = Query(default=None),
    location_id: str | None = Query(default=None),
    provider_id: str | None = Query(default=None),
    search: str = Query(default="", max_length=120),
    db=Depends(db_session),
    actor=Depends(permit("analytics_export")),
):
    beginning, ending = date_window(period, start, end)
    scope = resolve_scope(actor, location_id, provider_id)
    if key not in ROLE_METRICS.get(scope.profile, []):
        raise HTTPException(403, "Metric is outside the authorized role scope")
    effective_key = "collections" if key == "collection_rate" else key
    try:
        result = await worklist(
            db,
            effective_key,
            scope,
            beginning,
            ending,
            page=1,
            page_size=10000,
            search=search,
        )
    except KeyError:
        raise HTTPException(404, "Metric worklist is not available") from None
    output = io.StringIO()
    items = result["items"]
    if items:
        writer = csv.DictWriter(output, fieldnames=list(items[0]))
        writer.writeheader()
        writer.writerows(items)
    audit(
        db,
        actor.user_id,
        "analytics.export",
        key,
        row_count=len(items),
        start=beginning.isoformat(),
        end=ending.isoformat(),
    )
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="dhmis-{key}.csv"'},
    )
