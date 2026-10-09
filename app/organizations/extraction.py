from sqlalchemy import text

from app.core.database import checked_schema, engine_for


async def database_snapshot(schema: str, alias: str):
    checked_schema(schema)
    async with engine_for(alias).connect() as connection:
        exists = await connection.scalar(
            text(
                "SELECT EXISTS(SELECT 1 FROM information_schema.schemata "
                "WHERE schema_name=:schema)"
            ),
            {"schema": schema},
        )
        if not exists:
            return {"exists": False, "version": None, "tables": []}
        version = await connection.scalar(
            text(f'SELECT version_num FROM "{schema}".alembic_version')
        )
        tables = (
            await connection.execute(
                text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema=:schema ORDER BY table_name"
                ),
                {"schema": schema},
            )
        ).scalars().all()
        return {"exists": True, "version": version, "tables": tables}


async def extraction_preflight(organization, target_alias: str):
    if target_alias == organization.database_alias:
        raise ValueError("Target alias must differ from the current database alias")
    source = await database_snapshot(organization.schema_name, organization.database_alias)
    target = await database_snapshot(organization.schema_name, target_alias)
    return {
        "organization_id": organization.id,
        "schema_name": organization.schema_name,
        "source_alias": organization.database_alias,
        "target_alias": target_alias,
        "source": source,
        "target": target,
        "ready": bool(
            source["exists"]
            and target["exists"]
            and source["version"] == target["version"]
            and source["tables"] == target["tables"]
        ),
    }

