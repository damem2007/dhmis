"""Add bounded profile archive metadata and append-only clinical addenda."""

import sqlalchemy as sa
from alembic import context, op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.add_column("patients", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True), schema=schema)
    op.add_column("patients", sa.Column("archived_by", sa.String(100), nullable=True), schema=schema)
    op.add_column("patients", sa.Column("archive_reason", sa.String(1000), nullable=False, server_default=""), schema=schema)
    op.create_table(
        "record_addenda",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(100), nullable=False, server_default="migration-0018"),
        sa.Column("updated_by", sa.String(100), nullable=False, server_default="migration-0018"),
        sa.Column("record_type", sa.String(80), nullable=False),
        sa.Column("record_id", sa.String(36), nullable=False),
        sa.Column("patient_id", sa.String(36), sa.ForeignKey(f"{schema}.patients.id"), nullable=False),
        sa.Column("parent_id", sa.String(36), sa.ForeignKey(f"{schema}.record_addenda.id"), nullable=True),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("source_snapshot", sa.JSON(), nullable=False),
        sa.Column("source_hash", sa.String(64), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finalized_by", sa.String(100), nullable=False),
        schema=schema,
    )
    op.create_index("ix_record_addenda_record_id", "record_addenda", ["record_id"], schema=schema)
    op.create_index("ix_record_addenda_patient_id", "record_addenda", ["patient_id"], schema=schema)


def downgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return
    op.drop_table("record_addenda", schema=schema)
    op.drop_column("patients", "archive_reason", schema=schema)
    op.drop_column("patients", "archived_by", schema=schema)
    op.drop_column("patients", "archived_at", schema=schema)
