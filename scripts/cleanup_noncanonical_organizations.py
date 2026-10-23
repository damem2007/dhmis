#!/usr/bin/env python
"""Inspect or remove every tenant except the two protected organizations.

The command is intentionally dry-run by default. Use ``--apply`` to drop
non-protected tenant schemas and delete their control-plane records.

Examples::

    python scripts/cleanup_noncanonical_organizations.py
    python scripts/cleanup_noncanonical_organizations.py --apply
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import bindparam, select, text

from app.core.database import checked_schema, control_session, dispose_engines, engine
from app.organizations.models import Organization


KEEP = {
    "d1100000-0000-4000-8000-000000000001": "dhmis_t_d1100000000040008000000000000001",
    "ff975364-88f7-4c22-a166-835695ae7e14": "dhmis_t_ff97536488f74c22a166835695ae7e14",
}
CONTROL_REFERENCE_TABLES = (
    "adapter_customization_requests",
    "platform_audit_events",
    "platform_commercial_accounts",
    "platform_subscriptions",
    "platform_support_tickets",
    "tenant_adapter_overrides",
    "tenant_code_set_activation",
)
LOCK_KEY = 726430117


async def inventory() -> dict:
    async with control_session() as db:
        organizations = (await db.scalars(select(Organization).order_by(Organization.created_at, Organization.id))).all()
        organization_rows = [
            {
                "id": row.id,
                "name": row.name,
                "slug": row.slug,
                "schema_name": row.schema_name,
                "status": row.status,
            }
            for row in organizations
        ]

    async with engine.connect() as connection:
        schema_names = list(
            (
                await connection.execute(
                    text(
                        """
                        SELECT schema_name
                        FROM information_schema.schemata
                        WHERE schema_name LIKE 'dhmis_t\\_%' ESCAPE '\\'
                        ORDER BY schema_name
                        """
                    )
                )
            ).scalars()
        )
        references: dict[str, list[dict[str, int | str]]] = {}
        for table in CONTROL_REFERENCE_TABLES:
            rows = (
                await connection.execute(
                    text(
                        f"""
                        SELECT organization_id, count(*) AS count
                        FROM dhmis_control.\"{table}\"
                        WHERE organization_id IS NOT NULL
                        GROUP BY organization_id
                        ORDER BY organization_id
                        """
                    )
                )
            ).all()
            references[table] = [
                {"organization_id": row[0], "count": row[1]}
                for row in rows
            ]

    organization_schemas = {row["schema_name"] for row in organization_rows}
    return {
        "organizations": organization_rows,
        "tenant_schemas": schema_names,
        "orphan_tenant_schemas": sorted(set(schema_names) - organization_schemas),
        "organization_references": references,
    }


def validate_protected_rows(report: dict) -> None:
    organizations = {row["id"]: row for row in report["organizations"]}
    missing = sorted(set(KEEP) - set(organizations))
    if missing:
        raise RuntimeError(f"Protected organization is missing: {missing}")
    for organization_id, expected_schema in KEEP.items():
        actual_schema = organizations[organization_id]["schema_name"]
        if actual_schema != expected_schema:
            raise RuntimeError(
                f"Protected organization {organization_id} has schema {actual_schema}, expected {expected_schema}"
            )


async def cleanup() -> dict:
    async with engine.connect() as lock:
        await lock.execute(text(f"SELECT pg_advisory_lock({LOCK_KEY})"))
        await lock.commit()
        try:
            report = await inventory()
            validate_protected_rows(report)
            protected_schemas = set(KEEP.values()) | {"dhmis_control", "dhmis_template"}
            schemas_to_drop = sorted(
                set(report["tenant_schemas"]) - protected_schemas
            )

            for schema in schemas_to_drop:
                checked_schema(schema)
                async with engine.begin() as connection:
                    # Drop one schema per transaction. Dropping every tenant
                    # schema in one transaction can exceed PostgreSQL's
                    # max_locks_per_transaction setting.
                    await connection.execute(
                        text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
                    )

            keep_ids = list(KEEP)
            keep_bind = bindparam("keep_ids", expanding=True)
            deleted_references: dict[str, int] = {}
            async with control_session() as db:
                for table in CONTROL_REFERENCE_TABLES:
                    result = await db.execute(
                        text(
                            f"""
                            DELETE FROM dhmis_control.\"{table}\"
                            WHERE organization_id IS NOT NULL
                              AND organization_id NOT IN :keep_ids
                            """
                        ).bindparams(keep_bind),
                        {"keep_ids": keep_ids},
                    )
                    deleted_references[table] = result.rowcount
                deleted_organizations = await db.execute(
                    text(
                        "DELETE FROM dhmis_control.organizations WHERE id NOT IN :keep_ids"
                    ).bindparams(keep_bind),
                    {"keep_ids": keep_ids},
                )

            return {
                "deleted_organizations": deleted_organizations.rowcount,
                "dropped_schemas": len(schemas_to_drop),
                "deleted_control_rows": deleted_references,
                "verification": await inventory(),
            }
        finally:
            await lock.execute(text(f"SELECT pg_advisory_unlock({LOCK_KEY})"))
            await lock.commit()


async def main(apply: bool) -> None:
    try:
        report = await cleanup() if apply else await inventory()
        if not apply:
            validate_protected_rows(report)
            report = {
                "mode": "dry-run",
                "would_delete_organizations": max(0, len(report["organizations"]) - len(KEEP)),
                "would_drop_schemas": len(
                    set(report["tenant_schemas"]) - set(KEEP.values()) - {"dhmis_template"}
                ),
                **report,
            }
        else:
            report = {"mode": "apply", **report}
            final_ids = {row["id"] for row in report["verification"]["organizations"]}
            final_schemas = set(report["verification"]["tenant_schemas"])
            if final_ids != set(KEEP) or final_schemas != set(KEEP.values()):
                raise RuntimeError("Cleanup verification did not leave exactly the protected organizations")
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        await dispose_engines()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="drop non-protected tenant schemas and delete their database records",
    )
    args = parser.parse_args()
    asyncio.run(main(args.apply))
