from arq import cron
from arq.connections import RedisSettings
from sqlalchemy import select

from app.core.config import settings
from app.core.database import control_session, organization_session
from app.identity.service import Actor
from app.integrations.configuration import attach_effective_adapters
from app.notifications.service import dispatch
from app.organizations.configuration import tenant_settings
from app.organizations.models import Organization
from app.platform_identity.delivery import platform_tick
from app.rbac.models import PlatformChangeRequest, TenantChangeRequest
from app.rbac.workflow import expire_requests


async def tick(context):
    async with control_session() as db:
        await expire_requests(db, PlatformChangeRequest)
        organizations = (await db.scalars(select(Organization).where(Organization.status == "active"))).all()
    results = []
    for org in organizations:
        try:
            adapter_names = await attach_effective_adapters(org)
            async with organization_session(org) as db:
                expired_approvals = await expire_requests(db, TenantChangeRequest)
                runtime_settings = await tenant_settings(db)
                dispatch_result = await dispatch(
                    db,
                    Actor(
                        "worker",
                        org,
                        "Worker",
                        "admin",
                        settings=runtime_settings,
                        adapter_names=adapter_names,
                    ),
                )
                dispatch_result["expired_approvals"] = expired_approvals
                results.append(dispatch_result)
        except Exception as error:
            results.append({"organization_id": org.id, "error_type": type(error).__name__})
    return results


class WorkerSettings:
    redis_settings = RedisSettings.from_dsn(settings().redis_url)
    functions = [tick, platform_tick]
    cron_jobs = [
        cron(tick, second={0, 30}, run_at_startup=True),
        cron(platform_tick, second={0, 30}, run_at_startup=True),
    ]
    max_jobs = 2
