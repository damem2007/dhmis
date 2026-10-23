from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.database import control_session
from app.core.repository import serialize
from app.platform_identity.service import PlatformActor, platform_audit, platform_or_bootstrap
from app.organizations.models import Organization
from app.rbac.dependencies import permit_platform_or_bootstrap
from app.rbac.models import PlatformApprovalPolicy, PlatformChangeDecision, PlatformChangeRequest
from app.rbac.runtime import decide_platform, platform_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)
from app.regions.models import PlatformRegion, TenantCodeSetActivation
from app.regions.service import ensure_region_registry

router = APIRouter(prefix="/platform/regions", tags=["Platform regions"])


# Defines the region status input model, contract, or value object.
class RegionStatusInput(BaseModel):
    enabled: bool
    reason: str = Field(min_length=10, max_length=1000)
    approval_request_id: str | None = Field(default=None, max_length=36)


# Handle region status actor for this module.
async def region_status_actor(
    request: Request,
    body: RegionStatusInput,
    actor: PlatformActor = Depends(platform_or_bootstrap),
):
    permission_key = (
        "regions.supported_region_registry.enable"
        if body.enabled
        else "regions.supported_region_registry.disable"
    )
    return await permit_platform_or_bootstrap(
        permission_key, workflow_handles_approval=True
    )(request, actor)


# Handle regions for this module.
@router.get("")
async def regions(
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("regions.supported_region_registry.read")
    ),
):
    async with control_session() as db:
        await ensure_region_registry(db)
        rows = (await db.scalars(select(PlatformRegion).order_by(PlatformRegion.code))).all()
        return [serialize(row) for row in rows]


@router.get("/activation-summary")
async def activation_summary(
    actor: PlatformActor = Depends(
        permit_platform_or_bootstrap("regions.supported_region_registry.read")
    ),
):
    """Return aggregate activation status without exposing tenant code content."""
    async with control_session() as db:
        await ensure_region_registry(db)
        regions = (await db.scalars(select(PlatformRegion).order_by(PlatformRegion.code))).all()
        code_set_by_region = {region.code: region.code_set_type for region in regions if region.code_set_type}
        organizations = (await db.scalars(select(Organization))).all()
        total_by_set: dict[str, int] = {}
        for organization in organizations:
            code_set = code_set_by_region.get(str(organization.region).upper())
            if code_set:
                total_by_set[code_set] = total_by_set.get(code_set, 0) + 1
        active_rows = (await db.scalars(select(TenantCodeSetActivation).where(TenantCodeSetActivation.active.is_(True)))).all()
        activated_by_set: dict[str, int] = {}
        for activation in active_rows:
            activated_by_set[activation.code_set_type] = activated_by_set.get(activation.code_set_type, 0) + 1
        code_sets = set(total_by_set) | set(activated_by_set)
        labels = {"CDA": "Canadian Dental Association", "CDT": "American Dental Association"}
        return [
            {
                "code_set_type": code_set,
                "label": labels.get(code_set, "Tenant procedure code set"),
                "activated": activated_by_set.get(code_set, 0),
                "pending": None,
                "not_activated": total_by_set.get(code_set, 0) - activated_by_set.get(code_set, 0),
            }
            for code_set in sorted(code_sets)
        ]


# Handle region status for this module.
@router.put("/{code}/status")
async def region_status(
    code: str,
    body: RegionStatusInput,
    actor: PlatformActor = Depends(region_status_actor),
):
    code = code.upper()
    async with control_session() as db:
        await ensure_region_registry(db)
        row = await db.scalar(select(PlatformRegion).where(PlatformRegion.code == code).with_for_update())
        if row is None:
            raise HTTPException(404, "Region not found")
        permission_key = (
            "regions.supported_region_registry.enable"
            if body.enabled
            else "regions.supported_region_registry.disable"
        )
        payload = {"region": code, "enabled": body.enabled}
        decision = None if actor.user_id == "bootstrap" else await decide_platform(
            db, actor.user_id, permission_key
        )
        if decision is not None and (not decision.allowed or decision.needs_step_up):
            raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission_key]})
        approval = None
        if decision is not None and decision.needs_approval:
            if body.approval_request_id:
                approval = await authorize_runtime_action(
                    db,
                    request_id=body.approval_request_id,
                    permission_key=permission_key,
                    payload=payload,
                    maker_id=actor.user_id,
                    request_model=PlatformChangeRequest,
                )
            else:
                approval, created = await create_runtime_action_request(
                    db,
                    permission_key=permission_key,
                    payload=payload,
                    reason=body.reason,
                    maker_id=actor.user_id,
                    context=await platform_policy_context(db),
                    request_model=PlatformChangeRequest,
                    policy_model=PlatformApprovalPolicy,
                )
                return JSONResponse(
                    status_code=202,
                    content=jsonable_encoder({
                        "status": "approval_required",
                        "request": await request_payload(db, approval, PlatformChangeDecision),
                        "created": created,
                    }),
                )
        row.enabled = body.enabled
        row.updated_by = actor.user_id
        platform_audit(
            db,
            actor.user_id,
            "region.status",
            details={"region": code, "enabled": body.enabled, "reason": body.reason},
        )
        if approval:
            await complete_runtime_action(approval, {"resource": "platform_region", "resource_id": row.id})
        await db.flush()
        return serialize(row)
