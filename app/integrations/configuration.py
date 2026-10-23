from sqlalchemy import select

from app.core.database import control_session
from app.integrations.models import PlatformAdapterDefault, TenantAdapterOverride


async def _effective_adapter_configuration(organization) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve provider names and operator-selected modes for one organization."""

    async with control_session() as db:
        defaults = (
            await db.scalars(
                select(PlatformAdapterDefault).where(
                    PlatformAdapterDefault.active,
                    PlatformAdapterDefault.region.in_(["*", organization.region]),
                )
            )
        ).all()
        overrides = (
            await db.scalars(
                select(TenantAdapterOverride).where(
                    TenantAdapterOverride.organization_id == organization.id,
                    TenantAdapterOverride.active,
                )
            )
        ).all()
    selected = {
        row.capability: row.provider_name
        for row in defaults
        if row.region == "*"
    }
    modes = {
        row.capability: row.mode or "auto"
        for row in defaults
        if row.region == "*"
    }
    selected.update(
        {
            row.capability: row.provider_name
            for row in defaults
            if row.region == organization.region
        }
    )
    modes.update(
        {
            row.capability: row.mode or "auto"
            for row in defaults
            if row.region == organization.region
        }
    )
    selected.update({row.capability: row.provider_name for row in overrides})
    modes.update({row.capability: row.mode or "auto" for row in overrides})
    return selected, modes


async def effective_adapter_names(organization) -> dict[str, str]:
    """Resolve approved tenant override over region/global platform defaults."""

    selected, _modes = await _effective_adapter_configuration(organization)
    return selected


# Handle attach effective adapters for this module.
async def attach_effective_adapters(organization) -> dict[str, str]:
    selected, modes = await _effective_adapter_configuration(organization)
    organization._effective_adapters = selected
    organization._effective_adapter_modes = modes
    return selected


async def platform_adapter_names(db) -> dict[str, str]:
    """Resolve control-plane providers from active global defaults only."""

    rows = (
        await db.scalars(
            select(PlatformAdapterDefault).where(
                PlatformAdapterDefault.active,
                PlatformAdapterDefault.region == "*",
            )
        )
    ).all()
    return {row.capability: row.provider_name for row in rows}
