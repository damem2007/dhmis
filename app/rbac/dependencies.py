import time

from fastapi import Depends, HTTPException, Request

from app.core.audit import audit
from app.core.database import control_session, organization_session
from app.identity.service import Actor, current_actor
from app.platform_identity.models import PlatformUser
from app.platform_identity.service import (
    PlatformActor,
    current_platform,
    is_bootstrap_platform_user,
    platform_audit,
    platform_or_bootstrap,
)
from app.rbac.runtime import decide_platform, decide_tenant


def _permission_denial_detail(message: str, permission_keys: tuple[str, ...] | list[str]) -> dict:
    """Return a structured denial so clients can tell the user what to request."""
    return {
        "message": message,
        "required_permissions": list(dict.fromkeys(permission_keys)),
    }


# Internal helper for mfa age minutes.
def _mfa_age_minutes(authenticated_at: int) -> int | None:
    if not authenticated_at:
        return None
    return max(0, int((time.time() - authenticated_at) // 60))


# Handle permit tenant for this module.
def permit_tenant(permission_key: str, *, workflow_handles_approval: bool = False):
    # Handle guard for this module.
    async def guard(
        request: Request,
        actor: Actor = Depends(current_actor),
    ):
        denial: str | None = None
        async with organization_session(actor.organization) as db:
            db.info["actor"] = actor
            decision = await decide_tenant(
                db,
                actor.user_id,
                permission_key,
                selected_location_id=actor.selected_location_id,
                mfa_age_minutes=_mfa_age_minutes(actor.mfa_authenticated_at),
                current_ip=request.client.host if request.client else None,
            )
            if (
                not decision.allowed
                or decision.needs_step_up
                or (decision.needs_approval and not workflow_handles_approval)
            ):
                audit(
                    db,
                    actor.user_id,
                    "access.denied",
                    permission_key,
                    organization_id=actor.organization.id,
                    trace=list(decision.trace),
                    needs_step_up=decision.needs_step_up,
                    needs_approval=decision.needs_approval,
                )
                if decision.needs_step_up:
                    denial = "Recent step-up MFA is required"
                elif decision.needs_approval:
                    denial = "Maker-checker approval is required"
                else:
                    denial = "Permission denied"
        if denial:
            raise HTTPException(403, _permission_denial_detail(denial, (permission_key,)))
        return actor

    return guard


def permit_any_tenant(*permission_keys: str):
    """Allow a route when the actor has any one of the supplied grants.

    This is for composite pages whose tabs are independently governed. The
    dependency records the exact grants that passed on the request so the
    handler can filter each response collection without broadening access.
    """
    if not permission_keys:
        raise ValueError("permit_any_tenant requires at least one permission")

    async def guard(
        request: Request,
        actor: Actor = Depends(current_actor),
    ):
        async with organization_session(actor.organization) as db:
            db.info["actor"] = actor
            decisions = {
                key: await decide_tenant(
                    db,
                    actor.user_id,
                    key,
                    selected_location_id=actor.selected_location_id,
                    mfa_age_minutes=_mfa_age_minutes(actor.mfa_authenticated_at),
                    current_ip=request.client.host if request.client else None,
                )
                for key in permission_keys
            }
            allowed = {
                key
                for key, decision in decisions.items()
                if decision.allowed and not decision.needs_step_up and not decision.needs_approval
            }
            request.state.rbac_allowed_permissions = allowed
            if allowed:
                return actor

            audit(
                db,
                actor.user_id,
                "access.denied",
                " or ".join(permission_keys),
                organization_id=actor.organization.id,
                trace=[line for decision in decisions.values() for line in decision.trace],
                needs_step_up=any(decision.needs_step_up for decision in decisions.values()),
                needs_approval=any(decision.needs_approval for decision in decisions.values()),
            )
            if any(decision.needs_step_up for decision in decisions.values()):
                denial = "Recent step-up MFA is required"
            elif any(decision.needs_approval for decision in decisions.values()):
                denial = "Maker-checker approval is required"
            else:
                denial = "Permission denied"
        raise HTTPException(403, _permission_denial_detail(denial, permission_keys))

    return guard


# Handle permit platform for this module.
def permit_platform(permission_key: str, *, workflow_handles_approval: bool = False):
    # Handle guard for this module.
    async def guard(
        request: Request,
        actor: PlatformActor = Depends(current_platform),
    ):
        denial: str | None = None
        async with control_session() as db:
            decision = await decide_platform(
                db,
                actor.user_id,
                permission_key,
                mfa_age_minutes=_mfa_age_minutes(actor.mfa_authenticated_at),
                current_ip=request.client.host if request.client else None,
            )
            if (
                not decision.allowed
                or decision.needs_step_up
                or (decision.needs_approval and not workflow_handles_approval)
            ):
                platform_audit(
                    db,
                    actor.user_id,
                    "platform-access.denied",
                    details={
                        "permission_key": permission_key,
                        "trace": list(decision.trace),
                        "needs_step_up": decision.needs_step_up,
                        "needs_approval": decision.needs_approval,
                    },
                )
                if decision.needs_step_up:
                    denial = "Recent step-up MFA is required"
                elif decision.needs_approval:
                    denial = "Maker-checker approval is required"
                else:
                    denial = "Permission denied"
        if denial:
            raise HTTPException(403, _permission_denial_detail(denial, (permission_key,)))
        return actor

    return guard


# Handle permit platform or bootstrap for this module.
def permit_platform_or_bootstrap(permission_key: str, *, workflow_handles_approval: bool = False):
    # Handle guard for this module.
    async def guard(
        request: Request,
        actor: PlatformActor = Depends(platform_or_bootstrap),
    ):
        if actor.user_id == "bootstrap" or actor.is_bootstrap_operator:
            return actor
        # Re-read persisted provenance for sessions created before the
        # bootstrap marker was normalized on the actor object.
        async with control_session() as db:
            user = await db.get(PlatformUser, actor.user_id)
            if user is not None and is_bootstrap_platform_user(user):
                actor.is_bootstrap_operator = True
                return actor
        return await permit_platform(
            permission_key,
            workflow_handles_approval=workflow_handles_approval,
        )(request, actor)

    return guard
