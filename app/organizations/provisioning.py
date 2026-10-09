from pathlib import Path
from uuid import uuid4

from alembic import command
from alembic.config import Config
from sqlalchemy import select, text

from app.core.config import settings
from app.core.database import checked_schema, control_session, engine, engine_for, tenant_session
from app.organizations.configuration import backfill_legacy_configuration
from app.organizations.models import Organization, PlatformCommercialAccount
from app.organizations.tenant_resolution import normalize_slug

ROOT = Path(__file__).resolve().parents[2]


def apply_migrations(connection, schema):
    config = Config(str(ROOT / "alembic.ini"))
    config.attributes.update(connection=connection, schema=schema)
    command.upgrade(config, "head")


async def migrate_schema(schema, database_alias="primary"):
    if schema != "dhmis_control":
        checked_schema(schema)
    async with engine_for(database_alias).begin() as connection:
        await connection.execute(text("SELECT pg_advisory_xact_lock(726430119)"))
        await connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
        await connection.run_sync(lambda sync: apply_migrations(sync, schema))
    if schema == "dhmis_control":
        from app.rbac.bootstrap import seed_platform_super_admin
        from app.rbac.registry import synchronize_permission_registry
        from app.regions.service import ensure_region_registry

        async with control_session() as db:
            await synchronize_permission_registry(db)
            await seed_platform_super_admin(db)
            await ensure_region_registry(db)
    else:
        from app.rbac.bootstrap import seed_tenant_super_admin

        async with tenant_session(schema, database_alias) as db:
            await seed_tenant_super_admin(db)


async def provision(name, organization_id=None, slug=None, region="CA", database_alias="primary"):
    identifier = organization_id or str(uuid4())
    schema = "dhmis_t_" + identifier.replace("-", "")
    checked_schema(schema)
    # Lock provisioning for this identifier independently of migration-run serialization.
    async with engine.connect() as lock:
        await lock.execute(
            text("SELECT pg_advisory_lock(hashtextextended(:key,0))"), {"key": "provision:" + identifier}
        )
        try:
            async with control_session() as db:
                from app.regions.service import enabled_region

                await enabled_region(db, region)
                org = await db.get(Organization, identifier)
                if org is None:
                    base_slug = normalize_slug(slug or name)
                    if await db.scalar(
                        select(Organization).where(Organization.slug == base_slug)
                    ):
                        base_slug = f"{base_slug[:71]}-{identifier.replace('-', '')[:8]}"
                    org = Organization(
                        id=identifier,
                        name=name,
                        slug=base_slug,
                        region=region,
                        schema_name=schema,
                        status="pending",
                        database_alias=database_alias,
                    )
                    db.add(org)
                elif org.status == "active":
                    return org
            try:
                async with engine.begin() as db:
                    await db.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
                async with control_session() as db:
                    org = await db.get(Organization, identifier)
                    org.status = "schema_created"
                await migrate_schema(schema, org.database_alias)
                async with control_session() as db:
                    org = await db.get(Organization, identifier)
                    org.status = "migrated"
                    org.last_error = ""
                    account = await db.scalar(
                        select(PlatformCommercialAccount).where(
                            PlatformCommercialAccount.organization_id == org.id
                        )
                    )
                    if account is None:
                        db.add(
                            PlatformCommercialAccount(
                                organization_id=org.id,
                                account_status="active",
                                plan_code=org.plan,
                                created_by="provisioning",
                                updated_by="provisioning",
                            )
                        )
                await backfill_legacy_configuration(org)
                # Activation is separate so onboarding can atomically create the location and invite first.
                return org
            except Exception as error:
                async with control_session() as db:
                    org = await db.get(Organization, identifier)
                    org.status = "failed"
                    org.last_error = type(error).__name__
                raise
        finally:
            await lock.execute(
                text("SELECT pg_advisory_unlock(hashtextextended(:key,0))"),
                {"key": "provision:" + identifier},
            )


async def activate(identifier):
    async with control_session() as db:
        org = await db.get(Organization, identifier)
        if org.status not in ("migrated", "active"):
            raise ValueError("Organization is not fully migrated")
        org.status = "active"
    return org


async def migrate_all():
    await migrate_schema("dhmis_control")
    # A session-level run lock spans all tenant transactions, even a tenant failure.
    async with engine.connect() as lock:
        await lock.execute(text("SELECT pg_advisory_lock(726430118)"))
        try:
            await migrate_schema("dhmis_template")
            async with control_session() as db:
                orgs = (await db.scalars(select(Organization))).all()
            results = []
            for org in orgs:
                try:
                    await migrate_schema(org.schema_name, org.database_alias)
                    await backfill_legacy_configuration(org)
                    results.append({"organization_id": org.id, "migrated": True})
                except Exception as error:
                    results.append(
                        {"organization_id": org.id, "migrated": False, "error_type": type(error).__name__}
                    )
            return results
        finally:
            await lock.execute(text("SELECT pg_advisory_unlock(726430118)"))


async def reset_development_schemas():
    """Discard disposable development schemas before a clean migration/bootstrap."""
    if settings().environment != "development":
        raise RuntimeError("Development schema reset is disabled outside development")
    async with engine.connect() as lock:
        await lock.execute(text("SELECT pg_advisory_lock(726430117)"))
        schemas = (
            await lock.execute(
                text(
                    """
                    SELECT schema_name
                    FROM information_schema.schemata
                    WHERE schema_name IN ('dhmis_control', 'dhmis_template')
                       OR schema_name LIKE 'dhmis_t_%'
                    ORDER BY schema_name
                    """
                )
            )
        ).scalars().all()
        try:
            for schema in schemas:
                if schema not in {"dhmis_control", "dhmis_template"}:
                    checked_schema(schema)
                # One transaction per schema bounds locks below managed-Postgres limits.
                async with engine.begin() as connection:
                    await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        finally:
            await lock.execute(text("SELECT pg_advisory_unlock(726430117)"))
    return list(schemas)
