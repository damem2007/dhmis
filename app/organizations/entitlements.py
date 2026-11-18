"""Resolve platform subscription entitlements for tenant-side enforcement."""

from fastapi import HTTPException
from sqlalchemy import select

from app.core.database import control_session
from app.organizations.models import (
    PlatformFeature,
    PlatformPlan,
    PlatformPlanFeature,
    PlatformSubscription,
    PlatformTenantAddon,
)


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
        addon_rows = (
            await db.execute(
                select(PlatformFeature, PlatformTenantAddon)
                .join(PlatformTenantAddon, PlatformTenantAddon.feature_id == PlatformFeature.id)
                .where(
                    PlatformTenantAddon.organization_id == organization_id,
                    PlatformTenantAddon.status == "active",
                    PlatformFeature.active,
                )
            )
        ).all()
    entitlements = {
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
    for feature, addon in addon_rows:
        entitlements[feature.key] = {
            "key": feature.key,
            "name": feature.name,
            "description": feature.description,
            "category": feature.category,
            "feature_type": feature.feature_type,
            "unit": feature.unit,
            "enabled": True,
            "value": addon.quantity if feature.feature_type == "limit" else None,
            "unlimited": False,
            "included_quantity": addon.quantity if feature.feature_type == "metered" else None,
            "public_label": feature.name,
            "source": "tenant_addon",
        }
        if feature.key == "module.appointment_widget":
            current_limit = entitlements.get("limit.appointment_widget_origins")
            plan_quantity = int(current_limit.get("value") or 0) if current_limit and current_limit.get("enabled") else 0
            entitlements["limit.appointment_widget_origins"] = {
                "key": "limit.appointment_widget_origins",
                "name": "Appointment widget origins",
                "description": "Maximum approved website origins for the Appointment Widget.",
                "category": "limits",
                "feature_type": "limit",
                "unit": "origins",
                "enabled": True,
                # A Widget product buys *additional* approved external origins.
                # The tenant's portal/public hostname is an application route,
                # not a Widget origin, and is therefore absent from this count.
                "value": plan_quantity + addon.quantity,
                "unlimited": False,
                "included_quantity": None,
                "public_label": f"{plan_quantity + addon.quantity} widget origin(s)",
                "source": "tenant_addon",
            }
    return entitlements


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
