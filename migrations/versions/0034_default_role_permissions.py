"""Backfill the declarative default-role permissions into existing tenants.

Role definitions are kept in ``app/rbac/default_roles.json``.  The application
bootstrap calls the same reconciler for every tenant, but this migration also
handles deployments that upgrade schemas directly with Alembic.
"""

from uuid import uuid4

import sqlalchemy as sa
from alembic import context, op

from app.rbac.default_roles import _validate_default_permissions, default_role_definitions
from app.rbac.registry import load_approved_registry

revision = "0034_default_role_permissions"
down_revision = "0033_plan_feature_catalogue"
branch_labels = None
depends_on = None


# Internal helper for scope.
def _scope(definition, permission) -> str | None:
    scopes = {scope.value for scope in permission.valid_scopes}
    if definition.get("organization_scope") and "Organization" in scopes:
        return "Organization"
    if not definition.get("organization_scope") and "Location" in scopes:
        return "Location"
    if "Organization" in scopes:
        return "Organization"
    if "Location" in scopes:
        return "Location"
    return None


# Run the upgrade entry point for this module.
def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return

    registry = load_approved_registry()
    definitions = {item["name"]: item for item in default_role_definitions()}
    _validate_default_permissions(registry, definitions)
    connection = op.get_bind()
    grant_rows = []
    for name, definition in definitions.items():
        role_id = connection.execute(
            sa.text(
                f'SELECT id FROM "{schema}".tenant_roles '
                "WHERE name = :name AND status <> 'archived' LIMIT 1"
            ),
            {"name": name},
        ).scalar()
        if role_id is None:
            continue
        explicit = set(definition.get("additional_permissions", ()))
        for permission in registry.permissions.values():
            if permission.domain.value != "tenant":
                continue
            if not permission.reviewed or permission.retired:
                continue
            module = permission.resource_key.split(".", 1)[0]
            if module not in definition.get("modules", ()) and permission.key not in explicit:
                continue
            if permission.key not in explicit and permission.action not in {"read", "create", "update"}:
                continue
            scope = _scope(definition, permission)
            if scope is None:
                continue
            grant_rows.append(
                {
                    "id": str(uuid4()),
                    "role_id": role_id,
                    "permission_key": permission.key,
                    "scope": scope,
                }
            )

    # Submit the complete backfill as one executemany operation.  The previous
    # per-grant round trip made remote Supabase upgrades appear to hang while
    # preserving the same idempotent unique-key behavior.
    if grant_rows:
        connection.execute(
            sa.text(
                f"""
                INSERT INTO "{schema}".tenant_role_grants
                    (id, role_id, permission_key, effect, scope,
                     conditions, created_at, updated_at, created_by, updated_by)
                VALUES
                    (:id, :role_id, :permission_key, 'allow', :scope,
                     '{{}}'::json, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
                     'default-role-permissions-migration',
                     'default-role-permissions-migration')
                ON CONFLICT (role_id, permission_key) DO NOTHING
                """
            ),
            grant_rows,
        )


# Run the downgrade entry point for this module.
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
