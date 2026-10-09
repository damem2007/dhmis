"""Phase 1 identity, clinical, financial and administration expansion."""

import json
from pathlib import Path

import sqlalchemy as sa
from alembic import context, op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    schema = context.config.attributes["schema"]
    group = "control" if schema == "dhmis_control" else "tenant"
    snapshot = json.loads((Path(__file__).parent / "0002_schema.json").read_text())
    for statement in snapshot[group]:
        op.execute(statement.replace("tenant.", f'"{schema}".'))

    def add(table, name, type_, default=None, nullable=False):
        op.add_column(table, sa.Column(name, type_, nullable=nullable, server_default=default), schema=schema)

    if group == "control":
        for name in ["branding", "policy", "jurisdiction_policy"]:
            add("organizations", name, sa.JSON(), "{}")
        add("organizations", "plan", sa.String(30), "sandbox")
        add("organizations", "last_error", sa.String(120), "")
        return
    for name, type_, default in [
        ("mfa_secret", sa.Text(), ""),
        ("mfa_enabled", sa.Boolean(), "false"),
        ("mfa_counter", sa.BigInteger(), "-1"),
        ("location_ids", sa.JSON(), "[]"),
    ]:
        add("staff_users", name, type_, default)
    add("staff_users", "external_subject", sa.String(250), nullable=True)
    op.create_unique_constraint(
        "staff_external_subject_key", "staff_users", ["external_subject"], schema=schema
    )
    add("locations", "opening_hour", sa.Integer(), "8")
    add("locations", "closing_hour", sa.Integer(), "18")
    for name in ["medical_history", "dental_history"]:
        add("patients", name, sa.String(8000), "")
    add("patients", "alerts", sa.JSON(), "[]")
    op.alter_column(
        "chart_entries", "tooth", type_=sa.String(3), postgresql_using="tooth::varchar", schema=schema
    )
    for table in ["chart_entries", "perio_exams"]:
        add(table, "encounter_id", sa.String(36), nullable=True)
        op.create_foreign_key(
            table + "_encounter_fk",
            table,
            "encounters",
            ["encounter_id"],
            ["id"],
            source_schema=schema,
            referent_schema=schema,
        )
    add("perio_exams", "dentition", sa.JSON(), "[]")
    add("invoices", "adjustment_cents", sa.Integer(), "0")
    op.execute(f'ALTER TABLE "{schema}".invoices DROP CONSTRAINT invoices_check')
    op.create_check_constraint(
        "invoice_nonnegative_balance",
        "invoices",
        "total_cents >= 0 AND paid_cents >= 0 AND total_cents + adjustment_cents >= paid_cents",
        schema=schema,
    )
    op.drop_constraint("claims_invoice_id_key", "claims", schema=schema, type_="unique")
    add("claims", "plan_id", sa.String(36), nullable=True)
    op.create_foreign_key(
        "claims_plan_fk",
        "claims",
        "insurance_plans",
        ["plan_id"],
        ["id"],
        source_schema=schema,
        referent_schema=schema,
    )
    add("claims", "idempotency_key", sa.String(100), nullable=True)
    op.create_unique_constraint("claims_idempotency_key", "claims", ["idempotency_key"], schema=schema)
    add("claims", "submitted_cents", sa.Integer(), "0")
    add("claims", "payer_order", sa.Integer(), "1")
    add("claims", "due_at", sa.DateTime(timezone=True), nullable=True)
    add("claims", "remittance", sa.JSON(), "{}")
    add("claims", "discrepancy", sa.String(500), "")
    add("outbox_messages", "due_at", sa.DateTime(timezone=True), nullable=True)
    add("outbox_messages", "attempts", sa.Integer(), "0")
    add("outbox_messages", "result", sa.JSON(), "{}")
    for account, sign in [("accounts_receivable", 1), ("contra", -1)]:
        op.execute(f'''INSERT INTO "{schema}".journal_lines(id,posting_id,account,amount_cents,location_id,created_at,updated_at,created_by,updated_by)
            SELECT gen_random_uuid()::text,id,CASE WHEN '{account}'='contra' THEN CASE WHEN kind='charge' THEN 'revenue' ELSE 'cash' END ELSE '{account}' END,amount_cents*{sign},location_id,created_at,updated_at,created_by,updated_by FROM "{schema}".ledger_entries''')
    op.execute(f'''CREATE FUNCTION "{schema}".check_balanced_posting() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE net bigint; lines bigint;
    BEGIN SELECT COALESCE(SUM(amount_cents),0),COUNT(*) INTO net,lines FROM "{schema}".journal_lines WHERE posting_id=NEW.id;
    IF net<>0 OR lines<2 THEN RAISE EXCEPTION 'Unbalanced journal posting'; END IF; RETURN NEW; END; $$''')
    op.execute(
        f'CREATE CONSTRAINT TRIGGER balanced_posting AFTER INSERT ON "{schema}".ledger_entries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "{schema}".check_balanced_posting()'
    )
    for table in ["journal_lines", "fee_versions"]:
        op.execute(
            f'CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON "{schema}".{table} FOR EACH ROW EXECUTE FUNCTION "{schema}".reject_mutation()'
        )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
