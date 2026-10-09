import re
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.core.config import settings


def build_engine(raw_url):
    return create_async_engine(
        raw_url.replace("postgresql://", "postgresql+asyncpg://", 1),
        pool_size=10,
        max_overflow=5,
        pool_pre_ping=True,
        connect_args={
            "ssl": "require",
            "statement_cache_size": 0,
            "prepared_statement_cache_size": 0,
            "timeout": 15,
        },
    )


engine = build_engine(settings().database_url.get_secret_value())
_engines = {"primary": engine}


def engine_for(alias: str):
    if alias in _engines:
        return _engines[alias]
    configured = settings().database_aliases.get(alias)
    if configured is None:
        raise RuntimeError("Organization database alias is not configured")
    _engines[alias] = build_engine(configured.get_secret_value())
    return _engines[alias]


async def dispose_engines():
    for configured_engine in set(_engines.values()):
        await configured_engine.dispose()


def checked_schema(schema: str) -> str:
    if not re.fullmatch(r"(?:dhmis_t_[a-f0-9]{32}|dhmis_template)", schema):
        raise ValueError("Invalid tenant schema")
    return schema


@asynccontextmanager
async def control_session():
    async with AsyncSession(engine, expire_on_commit=False) as session, session.begin():
        yield session


@asynccontextmanager
async def tenant_session(schema: str, database_alias: str = "primary"):
    checked_schema(schema)
    async with engine_for(database_alias).connect() as connection:
        connection = await connection.execution_options(schema_translate_map={"tenant": schema})
        async with AsyncSession(connection, expire_on_commit=False) as session, session.begin():
            await session.execute(text("SELECT set_config('search_path', :path, true)"), {"path": schema})
            yield session


@asynccontextmanager
async def organization_session(organization):
    async with tenant_session(
        organization.schema_name, getattr(organization, "database_alias", "primary")
    ) as session:
        yield session
