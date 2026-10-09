from copy import deepcopy
from datetime import UTC, datetime

from app.core.database import control_session, organization_session
from app.organizations.models import Organization, PlatformConfiguration, TenantSettings

SETTINGS_ID = "organization-settings"
PLATFORM_SETTINGS_ID = "platform-defaults"
DEFAULT_POLICY = {
    "cancellation_notice_hours": 24,
    "cancellation_fee_cents": 0,
    "buffer_minutes": 0,
    "reminder_hours": 24,
}
COMMUNICATION_TEMPLATE_VARIABLES = (
    "clinic_name", "clinic_phone", "patient_first_name", "provider_name",
    "appointment_date", "appointment_time", "installment_amount", "due_date",
    "plan_balance", "recipient_name", "role", "tenant_slug", "platform_name",
    "invitation_expires_at", "invitation_expires_in", "invitation_link", "reset_link",
)
DEFAULT_COMMUNICATION_TEMPLATES = {
    "appointment-reminder": {
        "name": "Appointment reminder",
        "channel": "email",
        "subject": "Appointment reminder from {{clinic_name}}",
        "body": "Hi {{patient_first_name}}, your appointment is {{appointment_date}} at {{appointment_time}}. Call {{clinic_phone}} if you need to make a change.",
        "active": True,
    },
    "installment-due-soon": {
        "name": "Installment due soon",
        "channel": "email",
        "subject": "Payment installment due from {{clinic_name}}",
        "body": "Hi {{patient_first_name}}, {{installment_amount}} is due on {{due_date}}. Remaining plan balance: {{plan_balance}}.",
        "active": True,
    },
    "installment-overdue": {
        "name": "Installment overdue",
        "channel": "email",
        "subject": "Payment installment overdue at {{clinic_name}}",
        "body": "Hi {{patient_first_name}}, {{installment_amount}} was due on {{due_date}}. Remaining plan balance: {{plan_balance}}. Call {{clinic_phone}} if you need help.",
        "active": True,
    },
    "staff-invitation": {
        "name": "Staff invitation",
        "channel": "email",
        "subject": "Your invitation to {{clinic_name}}",
        "body": "Hi {{recipient_name}},\n\nYou have been invited to join {{clinic_name}} as {{role}}.\n\nAccept your invitation: {{invitation_link}}\n\nThis link expires {{invitation_expires_at}} ({{invitation_expires_in}}). If you were not expecting this message, contact {{clinic_name}} support.",
        "active": True,
    },
    "password-reset": {
        "name": "Password reset",
        "channel": "email",
        "subject": "Reset your {{clinic_name}} password",
        "body": "Hi {{recipient_name}}, use this one-time link to reset your password: {{reset_link}}",
        "active": True,
    },
}
LEGACY_STAFF_INVITATION_BODY = "Hi {{recipient_name}}, use this secure link to accept your staff invitation: {{invitation_link}}"


def render_communication_template(template: dict, values: dict[str, str]) -> tuple[str, str]:
    subject = template.get("subject", "")
    body = template.get("body", "")
    for key, value in values.items():
        subject = subject.replace("{{" + key + "}}", value)
        body = body.replace("{{" + key + "}}", value)
    return subject, body


async def platform_configuration(db) -> PlatformConfiguration:
    row = await db.get(PlatformConfiguration, PLATFORM_SETTINGS_ID)
    if row is None:
        row = PlatformConfiguration(
            id=PLATFORM_SETTINGS_ID,
            default_visibility="organization",
            default_policy=deepcopy(DEFAULT_POLICY),
            communication_templates=deepcopy(DEFAULT_COMMUNICATION_TEMPLATES),
            created_by="platform-default",
            updated_by="platform-default",
        )
        db.add(row)
        await db.flush()
    else:
        templates = deepcopy(row.communication_templates)
        changed = False
        for key, value in DEFAULT_COMMUNICATION_TEMPLATES.items():
            if key not in templates or (
                key == "staff-invitation" and templates[key].get("body") == LEGACY_STAFF_INVITATION_BODY
            ):
                templates[key] = deepcopy(value)
                changed = True
        if changed:
            row.communication_templates = templates
            await db.flush()
    return row


async def tenant_settings(db) -> TenantSettings:
    row = await db.get(TenantSettings, SETTINGS_ID)
    if row is None:
        row = TenantSettings(
            id=SETTINGS_ID,
            policy=deepcopy(DEFAULT_POLICY),
            communication_templates=deepcopy(DEFAULT_COMMUNICATION_TEMPLATES),
            migration_state={"legacy_control_backfilled": False},
        )
        db.add(row)
        await db.flush()
    else:
        templates = deepcopy(row.communication_templates)
        changed = False
        for key, value in DEFAULT_COMMUNICATION_TEMPLATES.items():
            if key not in templates or (
                key == "staff-invitation" and templates[key].get("body") == LEGACY_STAFF_INVITATION_BODY
            ):
                templates[key] = deepcopy(value)
                changed = True
        if changed:
            row.communication_templates = templates
            await db.flush()
    return row


async def backfill_legacy_configuration(organization: Organization) -> TenantSettings:
    """Copy legacy control values once, retaining the source columns for verification."""

    async with control_session() as db:
        source = await db.get(Organization, organization.id)
        snapshot = {
            "visibility": source.visibility,
            "branding": deepcopy(source.branding),
            "policy": {**DEFAULT_POLICY, **deepcopy(source.policy)},
            "jurisdiction_policy": deepcopy(source.jurisdiction_policy),
            "public_content": deepcopy(source.public_content),
        }
    async with organization_session(organization) as db:
        target = await tenant_settings(db)
        if target.migration_state.get("legacy_control_backfilled"):
            return target
        for key, value in snapshot.items():
            setattr(target, key, value)
        if not target.communication_templates:
            target.communication_templates = deepcopy(DEFAULT_COMMUNICATION_TEMPLATES)
        target.migration_state = {
            "legacy_control_backfilled": True,
            "source": "dhmis_control.organizations",
            "version": "0006",
            "completed_at": datetime.now(UTC).isoformat(),
            "verified": all(getattr(target, key) == value for key, value in snapshot.items()),
        }
        target.updated_by = "migration"
        await db.flush()
        return target


async def configure_tenant(
    db,
    *,
    visibility: str | None = None,
    branding: dict | None = None,
    policy: dict | None = None,
    jurisdiction_policy: dict | None = None,
    public_content: dict | None = None,
    booking_widget: dict | None = None,
    actor_id: str,
) -> TenantSettings:
    row = await tenant_settings(db)
    values = {
        "visibility": visibility,
        "branding": branding,
        "policy": policy,
        "jurisdiction_policy": jurisdiction_policy,
        "public_content": public_content,
        "booking_widget": booking_widget,
    }
    for key, value in values.items():
        if value is not None:
            setattr(row, key, deepcopy(value))
    row.updated_by = actor_id
    await db.flush()
    return row
