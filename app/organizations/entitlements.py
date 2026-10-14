"""Resolve platform subscription entitlements for tenant-side enforcement."""

from fastapi import HTTPException
from sqlalchemy import select

from app.core.database import control_session
from app.organizations.models import PlatformFeature, PlatformPlan, PlatformPlanFeature, PlatformSubscription


# Retrieve resolve entitlements for the current request or workflow.
async def resolve_entitlements(organization_id: str) -> dict[str, dict]:
    async with control_session() as db:
        rows = (
            await db.execute(
                select(PlatformFeature, PlatformPlanFeature)
                .join(PlatformPlanFeature, PlatformPlanFeature.feature_id == PlatformFeature.id)
                .join(PlatformPlan, PlatformPlan.id == PlatformPlanFeature.plan_id)
                .join(PlatformSubscription, PlatformSubscription.plan_id == PlatformPlanFeature.plan_id)
                .where(
                    PlatformSubscription.organization_id == organization_id,
                    PlatformSubscription.status.in_(("trialing", "active", "past_due")),
                    PlatformPlan.active,
                    PlatformFeature.active,
                )
            )
        ).all()
    return {
        feature.key: {
            "key": feature.key,
            "name": feature.name,
            "description": feature.description,
            "category": feature.category,
            "feature_type": feature.feature_type,
            "unit": feature.unit,
            "enabled": assignment.enabled,
            "value": assignment.value,
            "unlimited": assignment.unlimited,
            "included_quantity": assignment.included_quantity,
            "public_label": assignment.public_label,
        }
        for feature, assignment in rows
    }


# Validate or enforce require location capacity before the operation continues.
async def require_location_capacity(organization_id: str, current_count: int) -> None:
    entitlements = await resolve_entitlements(organization_id)
    limit = entitlements.get("limit.locations")
    if limit is None or not limit.get("enabled", False):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "LOCATION_PLAN_REQUIRED",
                "message": "An active subscription with a location allowance is required to add a location.",
                "feature": "limit.locations",
            },
        )
    if not limit["unlimited"] and limit["value"] is not None and current_count >= limit["value"]:
        raise HTTPException(
            status_code=402,
            detail={
                "code": "LOCATION_LIMIT_REACHED",
                "message": f"This subscription allows {limit['value']} location(s). Upgrade the plan to add another location.",
                "feature": "limit.locations",
                "limit": limit["value"],
            },
        )
