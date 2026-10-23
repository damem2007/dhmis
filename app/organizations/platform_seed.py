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
    ("adapter-default-01", "*", "payment_gateway", "sandbox"),
    ("adapter-default-02", "*", "signature_provider", "sandbox"),
    ("adapter-default-03", "*", "messaging_provider", "sandbox"),
    ("adapter-default-04", "*", "email_provider", "mailjet"),
    ("adapter-default-05", "*", "sms_provider", "sandbox"),
    ("adapter-default-06", "*", "accounting_exporter", "sandbox"),
    ("adapter-default-07", "CA", "claims_network", "Sandbox1_CDAnet"),
    ("adapter-default-08", "US", "claims_network", "Sandbox2_USAdapter"),
    ("adapter-default-geocoding", "*", "geocoding_provider", "tomtom"),
    ("adapter-default-map", "*", "map_provider", "openstreetmap"),
)

PLATFORM_PLANS = (
    {
        "id": "platform-plan-solo",
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
        "id": "platform-plan-clinic",
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
        "id": "platform-plan-group",
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
    ("module.charting", "Charting and treatment plans", "Clinical workflows and treatment planning.", "clinical", "boolean", ""),
    ("module.recalls", "Recalls and reminders", "Recall schedules and automated patient reminders.", "engagement", "boolean", ""),
    ("module.patient_portal", "Patient portal", "Patient forms, messages, plans and payments.", "portal", "boolean", ""),
    ("module.billing", "Billing and claims", "Invoices, ledger and claims workflows.", "financial", "boolean", ""),
    ("module.reports", "Reports and analytics", "Operational, financial and provider reporting.", "analytics", "boolean", ""),
    ("module.sso_audit", "SSO and audit log", "Single sign-on and advanced audit controls.", "security", "boolean", ""),
    ("module.api", "API, webhooks and sandbox", "Developer API access, webhooks and sandbox tooling.", "developer", "boolean", ""),
    ("limit.locations", "Locations", "Maximum locations available to a tenant.", "limits", "limit", "locations"),
)

PLAN_FEATURES = {
    "solo": {"module.charting", "module.recalls", "module.patient_portal"},
    "clinic": {"module.charting", "module.recalls", "module.patient_portal", "module.billing", "module.reports"},
    "group": {"module.charting", "module.recalls", "module.patient_portal", "module.billing", "module.reports", "module.sso_audit", "module.api"},
}


# Ensure approved platform adapter defaults without overwriting operator changes.
async def ensure_platform_adapter_defaults(db, actor_id: str = "platform-setup"):
    existing = {
        (row.region, row.capability)
        for row in (await db.scalars(select(PlatformAdapterDefault))).all()
    }
    for row_id, region, capability, provider_name in PLATFORM_ADAPTER_DEFAULTS:
        if (region, capability) in existing:
            continue
        db.add(
            PlatformAdapterDefault(
                id=row_id,
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
    plans = {
        row.code: row for row in (await db.scalars(select(PlatformPlan))).all()
    }
    for values in PLATFORM_PLANS:
        if values["code"] not in plans:
            row = PlatformPlan(**values, active=True, created_by=actor_id, updated_by=actor_id)
            db.add(row)
            plans[row.code] = row
    await db.flush()

    features = {
        row.key: row for row in (await db.scalars(select(PlatformFeature))).all()
    }
    for index, (key, name, description, category, feature_type, unit) in enumerate(PLATFORM_FEATURES, start=1):
        if key in features:
            continue
        row = PlatformFeature(
            id=f"platform-feature-{index:02d}",
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
        (row.plan_id, row.feature_id)
        for row in (await db.scalars(select(PlatformPlanFeature))).all()
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
            db.add(
                PlatformPlanFeature(
                    id=f"{plan_code}-{key.replace('.', '-')}",
                    plan_id=plan.id,
                    feature_id=feature.id,
                    enabled=True,
                    value=(None if plan_code == "group" else {"solo": 1, "clinic": 3}[plan_code]) if is_location_limit else None,
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
