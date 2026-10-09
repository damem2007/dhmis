"""Create authoritative staff roles per organization or location scope."""

import sqlalchemy as sa
from alembic import context, op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def record_columns():
    return [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0009"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0009"),
    ]


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.create_table(
        "staff_location_assignments",
        *record_columns(),
        sa.Column("user_id", sa.String(36), sa.ForeignKey(f"{schema}.staff_users.id"), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(f"{schema}.locations.id"), nullable=True),
        sa.Column("scope", sa.String(20), nullable=False, server_default="location"),
        sa.Column("role", sa.String(30), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("replaced_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(scope = 'organization' AND location_id IS NULL) OR "
            "(scope = 'location' AND location_id IS NOT NULL)",
            name="ck_staff_assignment_scope",
        ),
        schema=schema,
    )
    op.create_index(
        "uq_staff_active_location_assignment",
        "staff_location_assignments",
        ["user_id", "location_id"],
        unique=True,
        schema=schema,
        postgresql_where=sa.text("active AND scope = 'location'"),
    )
    op.create_index(
        "uq_staff_active_organization_assignment",
        "staff_location_assignments",
        ["user_id"],
        unique=True,
        schema=schema,
        postgresql_where=sa.text("active AND scope = 'organization'"),
    )
    op.create_table(
        "staff_invite_assignments",
        *record_columns(),
        sa.Column("invite_id", sa.String(36), sa.ForeignKey(f"{schema}.staff_invites.id"), nullable=False),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("location_id", sa.String(36), sa.ForeignKey(f"{schema}.locations.id"), nullable=True),
        sa.Column("scope", sa.String(20), nullable=False, server_default="location"),
        sa.Column("role", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.CheckConstraint(
            "(scope = 'organization' AND location_id IS NULL) OR "
            "(scope = 'location' AND location_id IS NOT NULL)",
            name="ck_staff_invite_assignment_scope",
        ),
        schema=schema,
    )
    op.create_index(
        "uq_staff_invite_location_assignment",
        "staff_invite_assignments",
        ["invite_id", "location_id"],
        unique=True,
        schema=schema,
        postgresql_where=sa.text("scope = 'location'"),
    )
    op.create_index(
        "uq_staff_invite_organization_assignment",
        "staff_invite_assignments",
        ["invite_id"],
        unique=True,
        schema=schema,
        postgresql_where=sa.text("scope = 'organization'"),
    )
def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
