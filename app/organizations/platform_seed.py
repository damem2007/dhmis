"""Idempotent control-plane defaults applied by the setup seed."""

from sqlalchemy import select

from app.integrations.models import PlatformAdapterDefault
from app.organizations.configuration import platform_configuration
from app.organizations.models import PlatformFeature, PlatformPlan, PlatformPlanFeature
from app.rbac.bootstrap import seed_platform_super_admin
from app.rbac.registry import synchronize_permission_registry
from app.regions.service import ensure_region_registry

# These values are the approved platform adapter baseline. Existing platform
# operator overrides are preserved; setup only fills a missing default row.
PLATFORM_ADAPTER_DEFAULTS = (
    ("*", "payment_gateway", "sandbox"),
    ("*", "signature_provider", "sandbox"),
    ("*", "messaging_provider", "sandbox"),
    ("*", "email_provider", "mailjet"),
    ("*", "sms_provider", "sandbox"),
    ("*", "accounting_exporter", "sandbox"),
    ("CA", "claims_network", "Sandbox1_CDAnet"),
    ("US", "claims_network", "Sandbox2_USAdapter"),
    ("*", "geocoding_provider", "tomtom"),
    ("*", "map_provider", "openstreetmap"),
)

PLATFORM_PLANS = (
    {
        "code": "solo",
        "name": "Solo",
        "description": "One dentist, one location.",
        "price_cents": 9900,
        "currency": "CAD",
        "interval": "month",
        "trial_days": 14,
        "max_locations": 1,
        "features": ["Charting and treatment plans", "Recalls and reminders", "Patient portal"],
    },
    {
        "code": "clinic",
        "name": "Clinic",
        "description": "Up to 8 providers.",
        "price_cents": 29900,
        "currency": "CAD",
        "interval": "month",
        "trial_days": 14,
        "max_locations": 3,
        "features": ["Everything in Solo", "Billing and claims", "Reports and analytics"],
    },
    {
        "code": "group",
        "name": "Group",
        "description": "Multiple locations with enterprise controls.",
        "price_cents": 0,
        "currency": "CAD",
        "interval": "month",
        "trial_days": 14,
        "max_locations": None,
        "features": ["Everything in Clinic", "SSO and audit log", "API, webhooks and sandbox"],
    },
)

PLATFORM_FEATURES = (
    (
        "module.charting",
        "Charting and treatment plans",
        "Clinical workflows and treatment planning.",
        "clinical",
        "boolean",
        "",
    ),
    (
        "module.recalls",
        "Recalls and reminders",
        "Recall schedules and automated patient reminders.",
        "engagement",
        "boolean",
        "",
    ),
    (
        "module.patient_portal",
        "Patient portal",
        "Patient forms, messages, plans and payments.",
        "portal",
        "boolean",
        "",
    ),
    (
        "module.billing",
        "Billing and claims",
        "Invoices, ledger and claims workflows.",
        "financial",
        "boolean",
        "",
    ),
    (
        "module.reports",
        "Reports and analytics",
        "Operational, financial and provider reporting.",
        "analytics",
        "boolean",
        "",
    ),
    (
        "module.sso_audit",
        "SSO and audit log",
        "Single sign-on and advanced audit controls.",
        "security",
        "boolean",
        "",
    ),
    (
        "module.api",
        "API, webhooks and sandbox",
        "Developer API access, webhooks and sandbox tooling.",
        "developer",
        "boolean",
        "",
    ),
    (
        "limit.locations",
        "Locations",
        "Maximum locations available to a tenant.",
        "limits",
        "limit",
        "locations",
    ),
    (
        "module.appointment_widget",
        "Appointment widget",
        "Embeddable appointment booking for tenant-owned websites.",
        "engagement",
        "boolean",
        "",
    ),
    ("experience.tenant_website", "Tenant website", "Public clinic website.", "experience", "boolean", ""),
    (
        "capability.appointment_booking",
        "Online appointment booking",
        "Allow patients to create appointments through enabled patient channels.",
        "engagement",
        "boolean",
        "",
    ),
    (
        "limit.appointment_widget_origins",
        "Appointment widget origins",
        "Maximum approved website origins for the Appointment Widget.",
        "limits",
        "limit",
        "origins",
    ),
)

PLAN_FEATURES = {
    "solo": {
        "module.charting",
        "module.recalls",
        "module.patient_portal",
        "module.appointment_widget",
        "experience.tenant_website",
        "capability.appointment_booking",
        "limit.appointment_widget_origins",
    },
    "clinic": {
        "module.charting",
        "module.recalls",
        "module.patient_portal",
        "module.billing",
        "module.reports",
        "module.appointment_widget",
        "experience.tenant_website",
        "capability.appointment_booking",
        "limit.appointment_widget_origins",
    },
    "group": {
        "module.charting",
        "module.recalls",
        "module.patient_portal",
        "module.billing",
        "module.reports",
        "module.sso_audit",
        "module.api",
        "module.appointment_widget",
        "experience.tenant_website",
        "capability.appointment_booking",
        "limit.appointment_widget_origins",
    },
}


# Ensure approved platform adapter defaults without overwriting operator changes.
async def ensure_platform_adapter_defaults(db, actor_id: str = "platform-setup"):
    existing = {
        (row.region, row.capability) for row in (await db.scalars(select(PlatformAdapterDefault))).all()
    }
    for region, capability, provider_name in PLATFORM_ADAPTER_DEFAULTS:
        if (region, capability) in existing:
            continue
        db.add(
            PlatformAdapterDefault(
                region=region,
                capability=capability,
                provider_name=provider_name,
                mode="auto",
                active=True,
                created_by=actor_id,
                updated_by=actor_id,
            )
        )
        existing.add((region, capability))
    await db.flush()


# Ensure approved platform plans, features and their assignments.
async def ensure_platform_catalogue(db, actor_id: str = "platform-setup"):
    plans = {row.code: row for row in (await db.scalars(select(PlatformPlan))).all()}
    for values in PLATFORM_PLANS:
        if values["code"] not in plans:
            row = PlatformPlan(
                **values,
                active=True,
                created_by=actor_id,
                updated_by=actor_id,
            )
            db.add(row)
            plans[row.code] = row
    await db.flush()

    features = {row.key: row for row in (await db.scalars(select(PlatformFeature))).all()}
    for key, name, description, category, feature_type, unit in PLATFORM_FEATURES:
        if key in features:
            continue
        row = PlatformFeature(
            key=key,
            name=name,
            description=description,
            category=category,
            feature_type=feature_type,
            unit=unit,
            active=True,
            created_by=actor_id,
            updated_by=actor_id,
        )
        db.add(row)
        features[key] = row
    await db.flush()

    existing = {
        (row.plan_id, row.feature_id) for row in (await db.scalars(select(PlatformPlanFeature))).all()
    }
    feature_keys = {key for key, *_ in PLATFORM_FEATURES}
    for plan_code, enabled_keys in PLAN_FEATURES.items():
        plan = plans[plan_code]
        for key in sorted((enabled_keys | {"limit.locations"}) & feature_keys):
            feature = features[key]
            identity = (plan.id, feature.id)
            if identity in existing:
                continue
            is_location_limit = key == "limit.locations"
            is_widget_origin_limit = key == "limit.appointment_widget_origins"
            db.add(
                PlatformPlanFeature(
                    plan_id=plan.id,
                    feature_id=feature.id,
                    enabled=True,
                    value=(None if plan_code == "group" else {"solo": 1, "clinic": 3}[plan_code])
                    if is_location_limit
                    else (1 if is_widget_origin_limit else None),
                    unlimited=plan_code == "group" if is_location_limit else False,
                    included_quantity=None,
                    public_label="",
                    created_by=actor_id,
                    updated_by=actor_id,
                )
            )
            existing.add(identity)
    await db.flush()


# Apply the complete approved control-plane setup seed.
async def seed_platform_configuration(db, actor_id: str = "platform-setup"):
    await platform_configuration(db)
    await synchronize_permission_registry(db, actor_id=actor_id)
    await seed_platform_super_admin(db, actor_id=actor_id)
    await ensure_region_registry(db, actor_id=actor_id)
    await ensure_platform_adapter_defaults(db, actor_id=actor_id)
    await ensure_platform_catalogue(db, actor_id=actor_id)
