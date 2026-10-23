"""Encrypt patient profile and portal contact fields with the application vault."""

import json

import sqlalchemy as sa
from alembic import context, op

from app.core.secure_fields import email_lookup
from app.identity.security import vault

revision = "0057"
down_revision = "0056_password_expiry"
branch_labels = None
depends_on = None


def _text(value):
    """Convert a legacy value to the string representation used by the vault."""

    return "" if value is None else str(value)


def _json(value):
    """Convert a legacy JSON value to a stable JSON string before encryption."""

    if value is None:
        return "null"
    if isinstance(value, str):
        try:
            return json.dumps(json.loads(value), separators=(",", ":"), sort_keys=True)
        except json.JSONDecodeError:
            return json.dumps(value, separators=(",", ":"), sort_keys=True)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _migrate_encrypted_columns(table, columns, json_columns=(), email_column=None):
    """Encrypt existing values, then replace their plaintext columns."""

    schema = context.config.attributes["schema"]
    bind = op.get_bind()
    encrypted_names = {column: f"{column}__cipher" for column in columns}
    for column in columns:
        op.add_column(
            table,
            sa.Column(encrypted_names[column], sa.Text(), nullable=True),
            schema=schema,
        )
    if email_column:
        op.add_column(
            table,
            sa.Column("email_lookup", sa.String(64), nullable=True),
            schema=schema,
        )

    table_ref = f'"{schema}"."{table}"'
    select_columns = ", ".join('"' + column + '"' for column in columns)
    rows = list(
        bind.execute(sa.text(f'SELECT "id", {select_columns} FROM {table_ref}')).mappings()
    )
    for row in rows:
        values = {}
        for column in columns:
            raw = _json(row[column]) if column in json_columns else _text(row[column])
            values[encrypted_names[column]] = vault().seal(raw)
        if email_column:
            values["email_lookup"] = email_lookup(row[email_column])
        assignments = ", ".join(f'"{key}" = :{key}' for key in values)
        bind.execute(
            sa.text(f'UPDATE {table_ref} SET {assignments} WHERE "id" = :id'),
            {**values, "id": row["id"]},
        )

    for column in columns:
        op.drop_column(table, column, schema=schema)
    for column in columns:
        op.alter_column(
            table,
            encrypted_names[column],
            new_column_name=column,
            nullable=False,
            schema=schema,
        )
    if email_column:
        op.alter_column(table, "email_lookup", nullable=False, schema=schema)


def upgrade():
    """Encrypt patient PHI while preserving exact email authentication lookups."""

    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return

    _migrate_encrypted_columns(
        "patients",
        (
            "first_name",
            "last_name",
            "birth_date",
            "email",
            "phone",
            "allergies",
            "medical_history",
            "dental_history",
            "alerts",
            "archive_reason",
        ),
        json_columns=("allergies", "alerts"),
        email_column="email",
    )
    _migrate_encrypted_columns("guardian_links", ("relationship",))
    _migrate_encrypted_columns("patient_users", ("email",), email_column="email")
    _migrate_encrypted_columns("patient_invites", ("email",), email_column="email")
    _migrate_encrypted_columns("patient_verification_challenges", ("email",))
    _migrate_encrypted_columns("outbox_messages", ("payload", "result"), json_columns=("payload", "result"))

    table_ref = f'"{schema}"."patient_users"'
    # The old unique constraint was on plaintext email. Uniqueness now belongs
    # to the keyed lookup column because randomized ciphertext is never equal.
    op.execute(f'ALTER TABLE {table_ref} DROP CONSTRAINT IF EXISTS patient_users_email_key')
    op.create_unique_constraint(
        "patient_users_email_lookup_key",
        "patient_users",
        ["email_lookup"],
        schema=schema,
    )
    op.create_index("patients_email_lookup_idx", "patients", ["email_lookup"], schema=schema)
    op.create_index("patient_invites_email_lookup_idx", "patient_invites", ["email_lookup"], schema=schema)


def downgrade():
    """Encryption migrations are forward-only to avoid writing plaintext back."""

    raise RuntimeError("Patient encryption migration is forward-only")
