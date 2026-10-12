"""Promote tenant defaults into the shared tenant bootstrap state.

The template schema is the source for newly provisioned tenants. Existing
tenant schemas are updated only when they still have the empty migration
default, so tenant-owned customisations are preserved.
"""

from alembic import context, op
import sqlalchemy as sa


revision = "0028_tenant_defaults"
down_revision = "0027_staff_lifecycle"
branch_labels = None
depends_on = None


DEFAULT_COMMUNICATION_TEMPLATES = (
    '{"appointment-reminder":{"name":"Appointment reminder","channel":"email",'
    '"subject":"Appointment reminder from {{clinic_name}}",'
    '"body":"Hi {{patient_first_name}}, your appointment is {{appointment_date}} at {{appointment_time}}. '
    'Call {{clinic_phone}} if you need to make a change.","active":true},'
    '"installment-due-soon":{"name":"Installment due soon","channel":"email",'
    '"subject":"Payment installment due from {{clinic_name}}",'
    '"body":"Hi {{patient_first_name}}, {{installment_amount}} is due on {{due_date}}. '
    'Remaining plan balance: {{plan_balance}}.","active":true},'
    '"installment-overdue":{"name":"Installment overdue","channel":"email",'
    '"subject":"Payment installment overdue at {{clinic_name}}",'
    '"body":"Hi {{patient_first_name}}, {{installment_amount}} was due on {{due_date}}. '
    'Remaining plan balance: {{plan_balance}}. Call {{clinic_phone}} if you need help.","active":true},'
    '"staff-invitation":{"name":"Staff invitation","channel":"email",'
    '"subject":"Your invitation to {{clinic_name}}",'
    '"body":"Hi {{recipient_name}},\\n\\nYou have been invited to join {{clinic_name}} as {{role}}.\\n\\n'
    'Accept your invitation: {{invitation_link}}\\n\\nThis link expires {{invitation_expires_at}} '
    '({{invitation_expires_in}}). If you were not expecting this message, contact {{clinic_name}} support.",'
    '"active":true},'
    '"password-reset":{"name":"Password reset","channel":"email",'
    '"subject":"Reset your {{clinic_name}} password",'
    '"body":"Hi {{recipient_name}}, use this one-time link to reset your password: {{reset_link}}",'
    '"active":true}}'
)


def upgrade():
    schema = context.config.attributes["schema"]
    if schema == "dhmis_control":
        return

    op.execute(
        sa.text(
            f"""
            UPDATE "{schema}".tenant_settings
            SET communication_templates = CAST(:templates AS json),
                updated_by = 'tenant-defaults-migration'
            WHERE id = 'organization-settings'
              AND communication_templates::jsonb = '{{}}'::jsonb
            """
        ).bindparams(templates=DEFAULT_COMMUNICATION_TEMPLATES)
    )
    # Older schemas marked every seeded role as locked. The tenant Super Admin
    # is the only protected role; all operational roles remain editable.
    op.execute(
        sa.text(
            f"""
            UPDATE "{schema}".tenant_roles
            SET locked = false,
                updated_by = 'tenant-defaults-migration'
            WHERE name <> 'Tenant Super Admin'
            """
        )
    )


def downgrade():
    raise RuntimeError("Use a reviewed forward migration")
