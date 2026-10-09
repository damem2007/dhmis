"""Add approved RBAC registry and role persistence foundations."""

import sqlalchemy as sa
from alembic import context, op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def record_columns(default="migration-0014"):
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default=default),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default=default),
    ]


def role_columns(schema, table):
    return [
        *record_columns(),
        sa.Column("domain", sa.String(20), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("parent_id", sa.String(36), sa.ForeignKey(f"{schema}.{table}.id"), nullable=True),
        sa.Column("locked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    ]


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        op.create_table(
            "permission_registry",
            sa.Column("key", sa.String(180), primary_key=True),
            sa.Column("domain", sa.String(20), primary_key=True),
            sa.Column("module_id", sa.String(20), nullable=False),
            sa.Column("module_name", sa.String(180), nullable=False),
            sa.Column("resource_key", sa.String(140), nullable=False),
            sa.Column("resource_name", sa.String(180), nullable=False),
            sa.Column("action", sa.String(80), nullable=False),
            sa.Column("action_group", sa.String(20), nullable=False),
            sa.Column("risk", sa.Integer(), nullable=False),
            sa.Column("restricted", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("reviewed", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("retired", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("requires", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("valid_scopes", sa.JSON(), nullable=False, server_default="[]"),
            sa.Column("registry_version", sa.String(40), nullable=False),
            sa.Column("source_digest", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_by", sa.String(100), nullable=False, server_default="registry-sync"),
            schema=schema,
        )
        op.create_index("ix_permission_registry_domain", "permission_registry", ["domain"], schema=schema)
        op.create_index(
            "ix_permission_registry_resource_key",
            "permission_registry",
            ["resource_key"],
            schema=schema,
        )
        op.create_table(
            "platform_roles",
            *role_columns(schema, "platform_roles"),
            sa.CheckConstraint("domain = 'platform'", name="ck_platform_role_domain"),
            schema=schema,
        )
        op.create_index("ix_platform_roles_status", "platform_roles", ["status"], schema=schema)
        op.execute(
            f'CREATE UNIQUE INDEX uq_platform_role_name ON "{schema}".platform_roles '
            "(lower(name)) WHERE status <> 'archived'"
        )
        op.create_table(
            "platform_role_grants",
            *record_columns(),
            sa.Column(
                "role_id",
                sa.String(36),
                sa.ForeignKey(f"{schema}.platform_roles.id"),
                nullable=False,
            ),
            sa.Column("permission_key", sa.String(180), nullable=False),
            sa.Column("effect", sa.String(10), nullable=False),
            sa.Column("scope", sa.String(20), nullable=False),
            sa.Column("conditions", sa.JSON(), nullable=False, server_default="{}"),
            sa.CheckConstraint("scope = 'Platform'", name="ck_platform_grant_scope"),
            schema=schema,
        )
        op.create_index(
            "uq_platform_role_grant",
            "platform_role_grants",
            ["role_id", "permission_key"],
            unique=True,
            schema=schema,
        )
        op.create_table(
            "platform_role_assignments",
            *record_columns(),
            sa.Column("user_id", sa.String(36), nullable=False),
            sa.Column(
                "role_id",
                sa.String(36),
                sa.ForeignKey(f"{schema}.platform_roles.id"),
                nullable=False,
            ),
            sa.Column("level", sa.String(20), nullable=False, server_default="Platform"),
            sa.Column("location_id", sa.String(36), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.CheckConstraint("level = 'Platform'", name="ck_platform_assignment_level"),
            schema=schema,
        )
        op.create_index(
            "uq_platform_role_assignment",
            "platform_role_assignments",
            ["user_id", "role_id"],
            unique=True,
            schema=schema,
        )
        return

    op.create_table(
        "tenant_roles",
        *role_columns(schema, "tenant_roles"),
        sa.CheckConstraint("domain = 'tenant'", name="ck_tenant_role_domain"),
        schema=schema,
    )
    op.create_index("ix_tenant_roles_status", "tenant_roles", ["status"], schema=schema)
    op.execute(
        f'CREATE UNIQUE INDEX uq_tenant_role_name ON "{schema}".tenant_roles '
        "(lower(name)) WHERE status <> 'archived'"
    )
    op.create_table(
        "tenant_role_grants",
        *record_columns(),
        sa.Column(
            "role_id",
            sa.String(36),
            sa.ForeignKey(f"{schema}.tenant_roles.id"),
            nullable=False,
        ),
        sa.Column("permission_key", sa.String(180), nullable=False),
        sa.Column("effect", sa.String(10), nullable=False),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("conditions", sa.JSON(), nullable=False, server_default="{}"),
        sa.CheckConstraint(
            "scope IN ('Organization','Location','Assigned','Own')",
            name="ck_tenant_grant_scope",
        ),
        schema=schema,
    )
    op.create_index(
        "uq_tenant_role_grant",
        "tenant_role_grants",
        ["role_id", "permission_key"],
        unique=True,
        schema=schema,
    )
    op.create_table(
        "tenant_role_assignments",
        *record_columns(),
        sa.Column(
            "user_id", sa.String(36), sa.ForeignKey(f"{schema}.staff_users.id"), nullable=False
        ),
        sa.Column(
            "role_id",
            sa.String(36),
            sa.ForeignKey(f"{schema}.tenant_roles.id"),
            nullable=False,
        ),
        sa.Column("level", sa.String(20), nullable=False),
        sa.Column(
            "location_id", sa.String(36), sa.ForeignKey(f"{schema}.locations.id"), nullable=True
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(level = 'Organization' AND location_id IS NULL) OR "
            "(level = 'Location' AND location_id IS NOT NULL)",
            name="ck_tenant_role_assignment_reach",
        ),
        schema=schema,
    )
    op.create_index(
        "uq_tenant_role_organization_assignment",
        "tenant_role_assignments",
        ["user_id", "role_id"],
        unique=True,
        schema=schema,
        postgresql_where=sa.text("level = 'Organization'"),
    )
    op.create_index(
        "uq_tenant_role_location_assignment",
        "tenant_role_assignments",
        ["user_id", "role_id", "location_id"],
        unique=True,
        schema=schema,
        postgresql_where=sa.text("level = 'Location'"),
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
