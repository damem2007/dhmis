from copy import deepcopy
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.database import control_session, organization_session
from app.identity.password_policy import DEFAULT_PASSWORD_POLICY
from app.organizations.models import Organization, PlatformConfiguration, TenantSettings

# A singleton keeps an independent UUID primary key. Its human role is an
# immutable business name that is safe to use for idempotent lookup.
SETTINGS_NAME = "organization-settings"
PLATFORM_SETTINGS_NAME = "platform-settings"
DEFAULT_POLICY = {
    "cancellation_notice_hours": 24,
    "cancellation_fee_cents": 0,
    "buffer_minutes": 0,
    "reminder_hours": 24,
    # The lifetime of staff and tenant-administrator invitation links. This is
    # inherited from the platform default at provisioning and tenant-owned
    # afterwards.
    "invitation_expiry_hours": 24,
    # Clinics choose how configured discounts interact with insurance. The
    # four modes cover the standard invoice/line and pre/post-insurance cases.
    "discount_application_mode": "invoice_before_insurance",
    "discounts": [],
    "password_policy": deepcopy(DEFAULT_PASSWORD_POLICY),
}
DEFAULT_BRANDING = {
    "--sage": "#0ea968",
    "--sage-deep": "#076b41",
    "--sage-tint": "#d3f3e4",
    "--amber": "#e8a93b",
    "--paper": "#f3f6f4",
    "--surface": "#ffffff",
    "--ink": "#0f1b17",
    "--font-ui": "IBM Plex Sans, sans-serif",
    "--font-display": "Fraunces, Georgia, serif",
}
DEFAULT_LOGO_URL = "/assets/dhmis-logo-v2/svg/dhmis-lockup-website.svg"
# Auto dentition defaults follow the approved age bands; tenant settings may override them.
DEFAULT_CLINICAL_CHART = {
    "save_mode": "manual",
    "enabled_numbering_systems": ["universal"],
    "default_numbering_system": "universal",
    "procedure_code_set": "",
    "dentition_age_ranges": {"primary_max_years": 11, "mixed_max_years": 21},
}
COMMUNICATION_TEMPLATE_VARIABLES = (
    "clinic_name",
    "clinic_phone",
    "patient_first_name",
    "provider_name",
    "appointment_date",
    "appointment_time",
    "installment_amount",
    "due_date",
    "plan_balance",
    "recipient_name",
    "role",
    "tenant_slug",
    "platform_name",
    "invitation_expires_at",
    "invitation_expires_in",
    "invitation_link",
    "reset_link",
)
COMMUNICATION_CHANNELS = ("email", "sms", "whatsapp")
EMAIL_TEMPLATE_MAX_LENGTH = 12_000
SMS_TEMPLATE_MAX_LENGTH = 480
WHATSAPP_TEMPLATE_MAX_LENGTH = 4_096


def _default_template(name: str, subject: str, body: str) -> dict:
    """Create a channel-aware template while retaining legacy read fields.

    ``channel``, ``subject`` and ``body`` remain in the JSON for older
    callers and existing database rows. New callers must use
    :func:`communication_template_deliveries` so each enabled channel gets
    its own content and delivery record.
    """

    return {
        "name": name,
        "active": True,
        "delivery_mode": "selected",
        "selected_channels": ["email"],
        "channels": {"email": {"subject": subject, "body": body, "signature": ""}},
        "channel": "email",
        "subject": subject,
        "body": body,
    }


DEFAULT_COMMUNICATION_TEMPLATES = {
    "appointment-reminder": {
        **_default_template(
            "Appointment reminder",
            "Appointment reminder from {{clinic_name}}",
            "Hi {{patient_first_name}}, your appointment is {{appointment_date}} at {{appointment_time}}. Call {{clinic_phone}} if you need to make a change.",
        ),
    },
    "installment-due-soon": {
        **_default_template(
            "Installment due soon",
            "Payment installment due from {{clinic_name}}",
            "Hi {{patient_first_name}}, {{installment_amount}} is due on {{due_date}}. Remaining plan balance: {{plan_balance}}.",
        ),
    },
    "installment-overdue": {
        **_default_template(
            "Installment overdue",
            "Payment installment overdue at {{clinic_name}}",
            "Hi {{patient_first_name}}, {{installment_amount}} was due on {{due_date}}. Remaining plan balance: {{plan_balance}}. Call {{clinic_phone}} if you need help.",
        ),
    },
    "staff-invitation": {
        **_default_template(
            "Staff invitation",
            "Your invitation to {{clinic_name}}",
            "Hi {{recipient_name}},\n\nYou have been invited to join {{clinic_name}} as {{role}}.\n\nAccept your invitation: {{invitation_link}}\n\nThis link expires {{invitation_expires_at}} ({{invitation_expires_in}}). If you were not expecting this message, contact {{clinic_name}} support.",
        ),
    },
    "password-reset": {
        **_default_template(
            "Password reset",
            "Reset your {{clinic_name}} password",
            "Hi {{recipient_name}}, use this one-time link to reset your password: {{reset_link}}",
        ),
    },
}
LEGACY_STAFF_INVITATION_BODY = (
    "Hi {{recipient_name}}, use this secure link to accept your staff invitation: {{invitation_link}}"
)


# Handle render communication template for this module.
def normalize_communication_template(template: dict) -> dict:
    """Return the durable channel-aware representation of a template.

    This accepts every deployed flat ``channel`` template so old tenant and
    platform JSON remains usable without a data migration. The legacy fields
    are retained as the first email (or selected) channel for integrations
    that are upgraded independently.
    """

    source = deepcopy(template or {})
    raw_channels = source.get("channels")
    channels: dict[str, dict] = {}
    if isinstance(raw_channels, dict):
        for channel, content in raw_channels.items():
            if channel not in COMMUNICATION_CHANNELS or not isinstance(content, dict):
                continue
            body = str(content.get("body", ""))
            # Signatures used to be stored separately. Fold them into the
            # rich email body during normalization so templates have one
            # source of truth going forward.
            signature = str(content.get("signature", "")) if channel == "email" else ""
            if signature:
                body = f"{body.rstrip()}\n\n{signature.strip()}"
            channels[channel] = {
                "subject": str(content.get("subject", "")) if channel == "email" else "",
                "body": body,
                "signature": "",
            }
    if not channels:
        legacy_channel = source.get("channel", "email")
        if legacy_channel not in COMMUNICATION_CHANNELS:
            legacy_channel = "email"
        channels[legacy_channel] = {
            "subject": str(source.get("subject", "")) if legacy_channel == "email" else "",
            "body": str(source.get("body", "")),
            "signature": "",
        }
    selected = source.get("selected_channels")
    if not isinstance(selected, list):
        selected = [source.get("channel", "email")]
    selected = [channel for channel in selected if channel in channels]
    if not selected:
        selected = [next(iter(channels))]
    mode = source.get("delivery_mode", "selected")
    if mode not in {"selected", "all_available"}:
        mode = "selected"
    primary = channels.get("email") or channels[selected[0]]
    primary_channel = "email" if "email" in channels else selected[0]
    return {
        "name": str(source.get("name", "Communication template")),
        "active": bool(source.get("active", True)),
        "delivery_mode": mode,
        "selected_channels": selected,
        "channels": channels,
        # Compatibility fields are deliberately read-only projections.
        "channel": primary_channel,
        "subject": primary.get("subject", ""),
        "body": primary.get("body", ""),
    }


def normalize_communication_templates(templates: dict | None) -> dict:
    return {
        key: normalize_communication_template(value)
        for key, value in (templates or {}).items()
        if isinstance(value, dict)
    }


def communication_template_deliveries(template: dict) -> list[tuple[str, dict]]:
    """Return configured channel templates in deterministic delivery order."""

    normalized = normalize_communication_template(template)
    if not normalized["active"]:
        return []
    channels = normalized["channels"]
    keys = channels.keys() if normalized["delivery_mode"] == "all_available" else normalized["selected_channels"]
    return [(channel, channels[channel]) for channel in keys if channel in channels]


def render_communication_template(template: dict, values: dict[str, str]) -> tuple[str, str]:
    subject = template.get("subject", "")
    body = template.get("body", "")
    for key, value in values.items():
        subject = subject.replace("{{" + key + "}}", value)
        body = body.replace("{{" + key + "}}", value)
    signature = template.get("signature", "")
    for key, value in values.items():
        signature = signature.replace("{{" + key + "}}", value)
    if signature:
        body = f"{body.rstrip()}\n\n{signature.strip()}"
    return subject, body


# Handle platform configuration for this module.
async def platform_configuration(db) -> PlatformConfiguration:
    row = await db.scalar(
        select(PlatformConfiguration).where(PlatformConfiguration.name == PLATFORM_SETTINGS_NAME)
    )
    if row is None:
        row = PlatformConfiguration(
            name=PLATFORM_SETTINGS_NAME,
            default_visibility="organization",
            default_policy=deepcopy(DEFAULT_POLICY),
            password_policy=deepcopy(DEFAULT_PASSWORD_POLICY),
            communication_templates=deepcopy(DEFAULT_COMMUNICATION_TEMPLATES),
            created_by="platform-default",
            updated_by="platform-default",
        )
        db.add(row)
        await db.flush()
    else:
        templates = normalize_communication_templates(row.communication_templates)
        changed = False
        default_policy = {**DEFAULT_POLICY, **(row.default_policy or {})}
        default_policy["password_policy"] = {
            **DEFAULT_PASSWORD_POLICY,
            **(default_policy.get("password_policy") or {}),
        }
        if default_policy != (row.default_policy or {}):
            row.default_policy = default_policy
            changed = True
        if not row.default_visibility:
            row.default_visibility = "organization"
            changed = True
        if not row.password_policy:
            row.password_policy = deepcopy(DEFAULT_PASSWORD_POLICY)
            changed = True
        for key, value in DEFAULT_COMMUNICATION_TEMPLATES.items():
            if key not in templates or (
                key == "staff-invitation" and templates[key].get("body") == LEGACY_STAFF_INVITATION_BODY
            ):
                templates[key] = deepcopy(value)
                changed = True
        if templates != (row.communication_templates or {}):
            changed = True
        if changed:
            row.communication_templates = templates
            await db.flush()
    return row


# Handle tenant settings for this module.
async def tenant_settings(db) -> TenantSettings:
    row = await db.scalar(select(TenantSettings).where(TenantSettings.name == SETTINGS_NAME))
    if row is None:
        row = TenantSettings(
            name=SETTINGS_NAME,
            branding=deepcopy(DEFAULT_BRANDING),
            logo_url=DEFAULT_LOGO_URL,
            policy=deepcopy(DEFAULT_POLICY),
            clinical_chart=deepcopy(DEFAULT_CLINICAL_CHART),
            communication_templates=deepcopy(DEFAULT_COMMUNICATION_TEMPLATES),
            migration_state={"legacy_control_backfilled": False},
        )
        db.add(row)
        await db.flush()
    else:
        branding = {**DEFAULT_BRANDING, **(row.branding or {})}
        policy = {**DEFAULT_POLICY, **(row.policy or {})}
        policy["password_policy"] = {**DEFAULT_PASSWORD_POLICY, **(policy.get("password_policy") or {})}
        changed = branding != (row.branding or {})
        if policy != (row.policy or {}):
            row.policy = policy
            changed = True
        clinical_chart = {**DEFAULT_CLINICAL_CHART, **(row.clinical_chart or {})}
        stored_ranges = (row.clinical_chart or {}).get("dentition_age_ranges") or {}
        clinical_chart["dentition_age_ranges"] = {
            "primary_max_years": stored_ranges.get("primary_max_years")
            if stored_ranges.get("primary_max_years") is not None
            else 11,
            "mixed_max_years": stored_ranges.get("mixed_max_years")
            if stored_ranges.get("mixed_max_years") is not None
            else 21,
        }
        if clinical_chart != (row.clinical_chart or {}):
            row.clinical_chart = clinical_chart
            changed = True
        migration_state = {
            "legacy_control_backfilled": False,
            **(row.migration_state or {}),
        }
        if migration_state != (row.migration_state or {}):
            row.migration_state = migration_state
            changed = True
        if not row.logo_url:
            row.logo_url = DEFAULT_LOGO_URL
            changed = True
        templates = normalize_communication_templates(row.communication_templates)
        for key, value in DEFAULT_COMMUNICATION_TEMPLATES.items():
            if key not in templates or (
                key == "staff-invitation" and templates[key].get("body") == LEGACY_STAFF_INVITATION_BODY
            ):
                templates[key] = deepcopy(value)
                changed = True
        if templates != (row.communication_templates or {}):
            changed = True
        if branding != (row.branding or {}):
            row.branding = branding
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
            "branding": {**DEFAULT_BRANDING, **deepcopy(source.branding or {})},
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


# Update configure tenant while preserving existing validation and audit behavior.
async def configure_tenant(
    db,
    *,
    visibility: str | None = None,
    branding: dict | None = None,
    logo_url: str | None = None,
    policy: dict | None = None,
    jurisdiction_policy: dict | None = None,
    public_content: dict | None = None,
    booking_widget: dict | None = None,
    actor_id: str,
) -> TenantSettings:
    row = await tenant_settings(db)
    values = {
        "visibility": visibility,
        "branding": {**DEFAULT_BRANDING, **deepcopy(branding)} if branding is not None else None,
        "logo_url": logo_url.strip()
        if isinstance(logo_url, str) and logo_url.strip()
        else DEFAULT_LOGO_URL
        if logo_url is not None
        else None,
        "policy": (
            {
                **DEFAULT_POLICY,
                **deepcopy(policy),
                "password_policy": {
                    **DEFAULT_PASSWORD_POLICY,
                    **(deepcopy(policy).get("password_policy") or {}),
                },
            }
            if policy is not None
            else None
        ),
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
