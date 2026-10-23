import hashlib
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, select

from app.billing.pricing import estimate_options
from app.clinical.models import (
    ChartEntry,
    ConditionTreatmentLink,
    Encounter,
    PerioExam,
    QuickChartSet,
    Quote,
    RecordAddendum,
    TreatmentCatalogueItem,
    TreatmentCatalogueOption,
    TreatmentPlan,
)
from app.clinical.defaults import ensure_catalogue_options, ensure_default_treatments
from app.clinical.schemas import (
    Acceptance,
    AddendumInput,
    CatalogueItemInput,
    ConditionTreatmentLinkInput,
    CatalogueOptionInput,
    ChartInput,
    ClinicalChartSettingsInput,
    EncounterCompletionInput,
    EncounterInput,
    MissingToothReturnInput,
    PerioInput,
    QuickChartSetInput,
    QuoteInput,
    ResolutionProcedureLinksInput,
    TreatmentInput,
)
from app.clinical.service import close_encounter
from app.consents.models import Consent
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.forms.models import FormSubmission
from app.identity.models import StaffUser
from app.identity.service import current_actor, db_session, user_has_module
from app.organizations.configuration import DEFAULT_CLINICAL_CHART, tenant_settings
from app.patients.access import (
    needs_assigned_patient_filter,
    needs_location_patient_filter,
    patient_read_decision,
    visible_location_ids,
)
from app.patients.models import Patient
from app.rbac.dependencies import permit_any_tenant, permit_tenant
from app.rbac.models import TenantApprovalPolicy, TenantChangeDecision, TenantChangeRequest
from app.rbac.runtime import decide_tenant, tenant_policy_context
from app.rbac.workflow import (
    authorize_runtime_action,
    complete_runtime_action,
    create_runtime_action_request,
    request_payload,
)
from app.scheduling.models import Appointment
from app.surgery.models import DaySurgeryAdmission

router = APIRouter(prefix="/clinical", tags=["Clinical charting"])

MISSING_TOOTH_CONDITIONS = frozenset({"missing", "shed", "extraction"})


def is_missing_tooth_entry(row: ChartEntry | ChartInput) -> bool:
    return (
        getattr(row, "status", "active") == "active"
        and row.surface == "whole"
        and row.condition.strip().casefold() in MISSING_TOOTH_CONDITIONS
    )


@router.get("/settings")
async def clinical_chart_settings(
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.chart_settings.read")),
):
    """Return tenant-scoped chart preferences without unrelated settings."""
    settings = await tenant_settings(db)
    audit(db, actor.user_id, "read", "clinical_chart_settings")
    return settings.clinical_chart or DEFAULT_CLINICAL_CHART


@router.put("/settings")
async def update_clinical_chart_settings(
    body: ClinicalChartSettingsInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.chart_settings.update")),
):
    """Persist reviewed chart display preferences for every user in this tenant."""
    settings = await tenant_settings(db)
    settings.clinical_chart = body.model_dump()
    settings.updated_by = actor.user_id
    audit(db, actor.user_id, "update", "clinical_chart_settings")
    await db.flush()
    return settings.clinical_chart


ADDENDUM_PERMISSIONS = {
    "encounter": "clinical.clinical_note.add_addendum",
    "perio_exam": "clinical.periodontal_chart.add_addendum",
    "treatment_plan": "clinical.treatment_plan.add_addendum",
    "day_surgery": "clinical.admission_day_surgery_record.add_addendum",
    "form_submission": "clinical.completed_patient_form.add_addendum",
}


# Handle addendum permission actor for this module.
def addendum_permission_actor():
    # Handle guard for this module.
    async def guard(request: Request, body: AddendumInput, actor=Depends(current_actor)):
        return await permit_tenant(
            ADDENDUM_PERMISSIONS[body.record_type],
            workflow_handles_approval=True,
        )(request, actor)

    return guard


def record_read_permission_actor():
    async def guard(request: Request, actor=Depends(current_actor)):
        record_type = request.path_params.get("record_type")
        addendum_permission = ADDENDUM_PERMISSIONS.get(record_type)
        if not addendum_permission:
            raise HTTPException(422, "Unknown clinical record type")
        read_permission = addendum_permission.rsplit(".", 1)[0] + ".read"
        return await permit_tenant(read_permission)(request, actor)

    return guard


# Validate or enforce validate encounter before the operation continues.
async def validate_encounter(db, identifier, patient_id):
    if identifier:
        encounter = await required(db, Encounter, identifier)
        if encounter.patient_id != patient_id or encounter.status != "open":
            raise HTTPException(409, "An open encounter for this patient is required")


async def validate_encounter_provider(db, provider_id: str, location_id: str):
    """Ensure an encounter is assigned to an active clinical provider for its location."""
    provider = await required(db, StaffUser, provider_id)
    if (
        not provider.active
        or not provider.is_provider
        or provider.archived_at is not None
        or (provider.suspended_until and provider.suspended_until > datetime.now(UTC))
        or not await user_has_module(db, provider, "clinical")
        or (provider.location_ids and location_id not in provider.location_ids)
    ):
        raise HTTPException(422, "Assignee must be an active clinical provider assigned to this location")
    return provider


async def ensure_patient_visibility(db, actor, patient_id: str):
    """Apply the patient's canonical RBAC visibility scope to charting.

    Provider status is intentionally ignored. Organization-scoped patient
    access lets a dentist work across the tenant; Assigned scope is the
    explicit role choice that narrows the chart to appointments for them.
    """
    decision = await patient_read_decision(db, actor)
    if decision is not None and not decision.allowed:
        raise HTTPException(403, {"message": "Permission denied", "required_permissions": ["patients.patient_profile.read"]})
    if needs_location_patient_filter(decision, actor):
        row = await db.get(Patient, patient_id)
        if row is None or row.location_id not in visible_location_ids(actor):
            raise HTTPException(403, "Patient is outside the staff member's assigned clinics")
    if decision is not None and needs_assigned_patient_filter(decision):
        assigned = await db.scalar(
            select(Appointment.id).where(
                Appointment.patient_id == patient_id,
                Appointment.provider_id == actor.user_id,
                Appointment.status != "cancelled",
            )
        )
        if not assigned:
            raise HTTPException(403, "Patient is not assigned to this provider")


@router.get("/catalogue")
async def catalogue(
    item_type: str | None = Query(default=None, pattern="^(treatment|condition|tooth_status)$"),
    include_inactive: bool = False,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=1000),
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.read")),
):
    """List tenant catalogue entries without duplicating service prices."""
    await ensure_default_treatments(db)
    query = select(TreatmentCatalogueItem)
    if item_type:
        query = query.where(TreatmentCatalogueItem.item_type == item_type)
    if not include_inactive:
        query = query.where(TreatmentCatalogueItem.active)
    total = await db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = (
        await db.scalars(
            query.order_by(TreatmentCatalogueItem.item_type, TreatmentCatalogueItem.name)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    audit(db, actor.user_id, "read", "treatment_catalogue_items", count=len(rows))
    return {
        "items": [serialize(row) for row in rows],
        "page": page,
        "page_size": page_size,
        "total": total,
        "pages": (total + page_size - 1) // page_size if total else 0,
    }


@router.get("/catalogue/options")
async def catalogue_options(
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.read")),
):
    """Return the tenant-scoped type/category table used by catalogue setup."""
    await ensure_catalogue_options(db)
    rows = (
        await db.scalars(
            select(TreatmentCatalogueOption)
            .where(TreatmentCatalogueOption.active)
            .order_by(
                TreatmentCatalogueOption.option_type,
                TreatmentCatalogueOption.item_type,
                TreatmentCatalogueOption.sort_order,
                TreatmentCatalogueOption.label,
            )
        )
    ).all()
    audit(db, actor.user_id, "read", "treatment_catalogue_options", count=len(rows))
    return {
        "types": [
            {"id": row.id, "item_type": row.item_type, "value": row.value, "label": row.label, "sort_order": row.sort_order}
            for row in rows
            if row.option_type == "type"
        ],
        "categories": {
            item_type: [
                {"id": row.id, "item_type": row.item_type, "value": row.value, "label": row.label, "sort_order": row.sort_order}
                for row in rows
                if row.option_type == "category" and row.item_type == item_type
            ]
            for item_type in ("treatment", "condition", "tooth_status")
        },
    }


@router.post("/catalogue/options", status_code=201)
async def create_catalogue_option(
    body: CatalogueOptionInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.create")),
):
    """Create a tenant-owned category used by catalogue setup dropdowns."""
    value = body.value.strip().lower()
    label = body.label.strip()
    existing = await db.scalar(
        select(TreatmentCatalogueOption).where(
            TreatmentCatalogueOption.option_type == body.option_type,
            TreatmentCatalogueOption.item_type == body.item_type,
            TreatmentCatalogueOption.value == value,
        )
    )
    if existing:
        if existing.active:
            raise HTTPException(409, "That category already exists")
        existing.active = True
        existing.label = label
        existing.sort_order = body.sort_order
        existing.updated_by = actor.user_id
        await db.flush()
        audit(db, actor.user_id, "reactivate", "treatment_catalogue_options", existing.id)
        return serialize(existing)
    row = await add(
        db,
        TreatmentCatalogueOption,
        {
            **body.model_dump(),
            "value": value,
            "label": label,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "create", "treatment_catalogue_options", row.id)
    return serialize(row)


@router.put("/catalogue/options/{identifier}")
async def update_catalogue_option(
    identifier: str,
    body: CatalogueOptionInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.update")),
):
    """Update a category label and ordering without changing its stable value."""
    row = await required(db, TreatmentCatalogueOption, identifier, lock=True)
    if row.option_type != "category" or row.item_type != body.item_type or row.value != body.value.strip().lower():
        raise HTTPException(422, "Category type and value cannot be changed; create a new category instead")
    row.label = body.label.strip()
    row.sort_order = body.sort_order
    row.updated_by = actor.user_id
    await db.flush()
    audit(db, actor.user_id, "update", "treatment_catalogue_options", row.id)
    return serialize(row)


@router.post("/catalogue/options/{identifier}/archive")
async def archive_catalogue_option(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.archive")),
):
    """Archive a category while retaining existing catalogue item values."""
    row = await required(db, TreatmentCatalogueOption, identifier, lock=True)
    if row.option_type != "category":
        raise HTTPException(422, "Catalogue types cannot be archived")
    row.active = False
    row.updated_by = actor.user_id
    await db.flush()
    audit(db, actor.user_id, "archive", "treatment_catalogue_options", row.id)
    return serialize(row)


@router.post("/catalogue", status_code=201)
async def create_catalogue_item(
    body: CatalogueItemInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.create")),
):
    """Create a tenant catalogue item, validating any linked service."""
    if body.item_type != "treatment" and body.service_id:
        raise HTTPException(422, "Only treatment/procedure entries can link a Services & fees entry")
    if body.service_id:
        from app.billing.models import Service

        await required(db, Service, body.service_id)
    if body.item_type != "treatment" and body.fee_cents:
        raise HTTPException(422, "Conditions and tooth statuses cannot have a procedure fee")
    row = await add(db, TreatmentCatalogueItem, body.model_dump(), actor.user_id)
    audit(db, actor.user_id, "create", "treatment_catalogue_items", row.id)
    return serialize(row)


@router.put("/catalogue/{identifier}")
async def update_catalogue_item(
    identifier: str,
    body: CatalogueItemInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.update")),
):
    """Update catalogue metadata while retaining the linked fee source."""
    row = await required(db, TreatmentCatalogueItem, identifier, lock=True)
    if body.item_type != "treatment" and body.service_id:
        raise HTTPException(422, "Only treatment/procedure entries can link a Services & fees entry")
    if body.service_id:
        from app.billing.models import Service

        await required(db, Service, body.service_id)
    if body.item_type != "treatment" and body.fee_cents:
        raise HTTPException(422, "Conditions and tooth statuses cannot have a procedure fee")
    for key, value in body.model_dump().items():
        # ``resolved_by`` is a legacy display field. Resolution mappings are
        # maintained exclusively through the normalized condition-centric API.
        if key == "resolved_by":
            continue
        setattr(row, key, value)
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "update", "treatment_catalogue_items", row.id)
    await db.flush()
    return serialize(row)


@router.post("/catalogue/{identifier}/archive")
async def archive_catalogue_item(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.archive")),
):
    """Soft-archive a catalogue item without changing mappings or chart history."""
    row = await required(db, TreatmentCatalogueItem, identifier, lock=True)
    row.active = False
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "archive", "treatment_catalogue_items", row.id)
    await db.flush()
    return serialize(row)


@router.post("/catalogue/{identifier}/reactivate")
async def reactivate_catalogue_item(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.archive")),
):
    """Reactivate an administratively archived catalogue item without rewriting history."""
    row = await required(db, TreatmentCatalogueItem, identifier, lock=True)
    if row.active:
        raise HTTPException(409, "Catalogue item is already active")
    row.active = True
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "reactivate", "treatment_catalogue_items", row.id)
    await db.flush()
    return serialize(row)


@router.get("/catalogue/condition-treatment-links")
async def condition_treatment_links(
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.read")),
):
    rows = (await db.scalars(select(ConditionTreatmentLink))).all()
    item_ids = {value for row in rows for value in (row.condition_id, row.treatment_id)}
    items = (await db.scalars(select(TreatmentCatalogueItem).where(TreatmentCatalogueItem.id.in_(item_ids)))).all() if item_ids else []
    by_id = {item.id: serialize(item) for item in items}
    audit(db, actor.user_id, "read", "condition_treatment_links", count=len(rows))
    return [{"id": row.id, "condition_id": row.condition_id, "treatment_id": row.treatment_id, "relationship_type": row.relationship_type, "condition": by_id.get(row.condition_id), "treatment": by_id.get(row.treatment_id)} for row in rows]


@router.put("/catalogue/{identifier}/resolution-links")
async def update_condition_resolution_links(
    identifier: str,
    body: ResolutionProcedureLinksInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.update")),
):
    """Replace a condition's potential resolving procedures from Condition setup."""
    condition = await required(db, TreatmentCatalogueItem, identifier, lock=True)
    if condition.item_type != "condition":
        raise HTTPException(422, "Only condition entries can configure resolving procedures")
    existing = (
        await db.scalars(
            select(ConditionTreatmentLink).where(
                ConditionTreatmentLink.condition_id == condition.id,
                ConditionTreatmentLink.relationship_type == "may_resolve",
            )
        )
    ).all()
    existing_ids = {row.treatment_id for row in existing}
    requested_ids = list(dict.fromkeys(body.treatment_ids))
    procedures = (
        await db.scalars(
            select(TreatmentCatalogueItem).where(
                TreatmentCatalogueItem.id.in_(requested_ids),
                TreatmentCatalogueItem.item_type == "treatment",
                or_(TreatmentCatalogueItem.active, TreatmentCatalogueItem.id.in_(existing_ids)),
            )
        )
    ).all() if requested_ids else []
    if len(procedures) != len(requested_ids):
        raise HTTPException(422, "Every new resolving procedure must be an active treatment/procedure catalogue entry")
    for row in existing:
        await db.delete(row)
    for procedure in procedures:
        await add(
            db,
            ConditionTreatmentLink,
            {
                "condition_id": condition.id,
                "treatment_id": procedure.id,
                "relationship_type": "may_resolve",
            },
            actor.user_id,
        )
    await db.flush()
    audit(db, actor.user_id, "update", "condition_treatment_links", condition.id)
    return {"condition_id": condition.id, "treatment_ids": requested_ids, "relationship_type": "may_resolve"}


@router.put("/catalogue/{identifier}/condition-links", include_in_schema=False)
async def update_condition_treatment_links(
    identifier: str,
    body: ConditionTreatmentLinkInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_catalogue_item.update")),
):
    """Reject the legacy reverse editor so Condition setup stays authoritative."""
    raise HTTPException(410, "Resolution mappings are managed from Condition setup")


@router.get("/quick-chart-sets")
async def quick_chart_sets(
    include_inactive: bool = False,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.quick_chart_set.read")),
):
    """List active tenant Quick chart sets in their stored item order."""
    query = select(QuickChartSet).order_by(QuickChartSet.name)
    if not include_inactive:
        query = query.where(QuickChartSet.active)
    rows = (await db.scalars(query)).all()
    audit(db, actor.user_id, "read", "quick_chart_sets", count=len(rows))
    return [serialize(row) for row in rows]


@router.post("/quick-chart-sets", status_code=201)
async def create_quick_chart_set(
    body: QuickChartSetInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.quick_chart_set.create")),
):
    """Create an ordered Quick chart set without introducing per-set roles."""
    items = list(dict.fromkeys(body.items))
    known_codes = set((await db.scalars(select(TreatmentCatalogueItem.code).where(TreatmentCatalogueItem.active, TreatmentCatalogueItem.item_type == "condition"))).all())
    invalid = sorted(set(items) - known_codes)
    if invalid:
        raise HTTPException(422, f"Quick chart sets may contain active condition codes only: {', '.join(invalid)}")
    row = await add(db, QuickChartSet, {**body.model_dump(), "items": items}, actor.user_id)
    audit(db, actor.user_id, "create", "quick_chart_sets", row.id)
    return serialize(row)


@router.put("/quick-chart-sets/{identifier}")
async def update_quick_chart_set(
    identifier: str,
    body: QuickChartSetInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.quick_chart_set.update")),
):
    """Update a Quick chart set while preserving ordered shortcut semantics."""
    row = await required(db, QuickChartSet, identifier, lock=True)
    items = list(dict.fromkeys(body.items))
    known_codes = set((await db.scalars(select(TreatmentCatalogueItem.code).where(TreatmentCatalogueItem.active, TreatmentCatalogueItem.item_type == "condition"))).all())
    invalid = sorted(set(items) - known_codes)
    if invalid:
        raise HTTPException(422, f"Quick chart sets may contain active condition codes only: {', '.join(invalid)}")
    row.name = body.name
    row.description = body.description
    row.items = items
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "update", "quick_chart_sets", row.id)
    await db.flush()
    return serialize(row)


@router.post("/quick-chart-sets/{identifier}/archive")
async def archive_quick_chart_set(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.quick_chart_set.archive")),
):
    """Soft-archive a Quick chart set without deleting chart history."""
    row = await required(db, QuickChartSet, identifier, lock=True)
    row.active = False
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "archive", "quick_chart_sets", row.id)
    await db.flush()
    return serialize(row)


@router.get("/quick-chart-sets/{identifier}/use")
async def use_quick_chart_set(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.quick_chart_set.use")),
):
    """Return one active shortcut set after enforcing use permission."""
    row = await required(db, QuickChartSet, identifier)
    if not row.active:
        raise HTTPException(404, "Quick chart set is inactive")
    audit(db, actor.user_id, "use", "quick_chart_sets", row.id)
    return serialize(row)


async def _quote_option(db, plan: TreatmentPlan, option_index: int, provider_id: str):
    """Reprice one plan option from the existing tenant Services & fees rows."""
    if option_index >= len(plan.options):
        raise HTTPException(422, "Unknown treatment option")
    option = plan.options[option_index]
    treatment_input = TreatmentInput(
        patient_id=plan.patient_id,
        provider_id=provider_id,
        title=plan.title,
        options=[option],
    )
    priced = (await estimate_options(db, treatment_input, await required(db, Patient, plan.patient_id)))[0]
    return priced


@router.get("/quotes")
async def patient_quotes(
    patient_id: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("reports.quote.read")),
):
    """Return immutable quote revisions for one patient."""
    await required(db, Patient, patient_id)
    rows = (
        await db.scalars(
            select(Quote).where(Quote.patient_id == patient_id).order_by(Quote.created_at.desc())
        )
    ).all()
    audit(db, actor.user_id, "read", "quotes", patient_id=patient_id, count=len(rows))
    return [serialize(row) for row in rows]


@router.post("/treatment-plans/{identifier}/quotes", status_code=201)
async def create_quote(
    identifier: str,
    body: QuoteInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("reports.quote.create")),
):
    """Create a versioned quote snapshot without changing the treatment plan."""
    plan = await required(db, TreatmentPlan, identifier)
    priced = await _quote_option(db, plan, body.option_index, plan.provider_id or actor.user_id)
    latest = await db.scalar(
        select(func.max(Quote.version)).where(
            Quote.treatment_plan_id == plan.id,
            Quote.option_index == body.option_index,
        )
    )
    row = await add(
        db,
        Quote,
        {
            "patient_id": plan.patient_id,
            "location_id": plan.location_id,
            "treatment_plan_id": plan.id,
            "option_index": body.option_index,
            "version": (latest or 0) + 1,
            "snapshot": priced,
            "total_cents": priced["total_cents"],
            "estimated_insurance_cents": priced["estimated_insurance_cents"],
            "estimated_patient_cents": priced["estimated_patient_cents"],
            "status": "draft",
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "create", "quotes", row.id, patient_id=plan.patient_id, plan_id=plan.id)
    return serialize(row)


@router.post("/quotes/{identifier}/recalculate", status_code=201)
async def recalculate_quote(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("reports.quote.recalculate")),
):
    """Create a new quote revision using current Services & fees values."""
    previous = await required(db, Quote, identifier)
    plan = await required(db, TreatmentPlan, previous.treatment_plan_id)
    if previous.status == "accepted":
        raise HTTPException(409, "Accepted quotes cannot be recalculated")
    priced = await _quote_option(db, plan, previous.option_index, plan.provider_id or actor.user_id)
    previous.status = "superseded"
    previous.updated_by = actor.user_id
    latest = await db.scalar(
        select(func.max(Quote.version)).where(
            Quote.treatment_plan_id == plan.id,
            Quote.option_index == previous.option_index,
        )
    )
    row = await add(
        db,
        Quote,
        {
            "patient_id": plan.patient_id,
            "location_id": plan.location_id,
            "treatment_plan_id": plan.id,
            "option_index": previous.option_index,
            "version": (latest or 0) + 1,
            "snapshot": priced,
            "total_cents": priced["total_cents"],
            "estimated_insurance_cents": priced["estimated_insurance_cents"],
            "estimated_patient_cents": priced["estimated_patient_cents"],
            "status": "draft",
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "recalculate", "quotes", row.id, supersedes_id=previous.id)
    await db.flush()
    return serialize(row)


@router.post("/quotes/{identifier}/status")
async def update_quote_status(
    identifier: str,
    status: str = Query(pattern="^(presented|declined|expired)$"),
    db=Depends(db_session),
    actor=Depends(permit_tenant("reports.quote.present")),
):
    """Record a quote presentation or outcome without rewriting its snapshot."""
    row = await required(db, Quote, identifier, lock=True)
    if row.status == "superseded" or row.status == "accepted":
        raise HTTPException(409, "This quote revision is no longer changeable")
    row.status = status
    row.updated_by = actor.user_id
    audit(db, actor.user_id, status, "quotes", row.id, patient_id=row.patient_id)
    await db.flush()
    return serialize(row)


@router.post("/quotes/{identifier}/accept")
async def accept_quote(
    identifier: str,
    db=Depends(db_session),
    actor=Depends(permit_tenant("reports.quote.accept")),
):
    """Record acceptance against this immutable quote revision."""
    row = await required(db, Quote, identifier, lock=True)
    if row.status == "superseded":
        raise HTTPException(409, "Superseded quote revisions cannot be accepted")
    row.status = "accepted"
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "accepted", "quotes", row.id, patient_id=row.patient_id)
    await db.flush()
    return serialize(row)


CLINICAL_CHART_READ_PERMISSIONS = {
    "entries": "clinical.odontogram.read",
    "perio_exams": "clinical.periodontal_chart.read",
    "encounters": "clinical.clinical_encounter.read",
    "treatment_plans": "clinical.treatment_plan.read",
}


# Handle chart for this module.
@router.get("/{patient_id}")
async def chart(
    patient_id: str,
    request: Request,
    include: str | None = Query(default=None, description="Comma-separated clinical collections to load"),
    db=Depends(db_session),
    # The container is available when at least one charting/encounter tab is
    # readable. Each collection is filtered again below by its own permission.
    actor=Depends(permit_any_tenant(*CLINICAL_CHART_READ_PERMISSIONS.values())),
):
    """Load only the patient-chart collections the actor can read."""
    await required(db, Patient, patient_id)
    await ensure_patient_visibility(db, actor, patient_id)
    requested = set(include.split(",")) if include else set(CLINICAL_CHART_READ_PERMISSIONS)
    requested &= {"entries", "perio_exams", "encounters", "treatment_plans"}
    allowed_permissions = getattr(request.state, "rbac_allowed_permissions", set())
    requested = {
        key for key in requested
        if CLINICAL_CHART_READ_PERMISSIONS[key] in allowed_permissions
    }
    result = {}
    for key, model in [
        ("entries", ChartEntry),
        ("perio_exams", PerioExam),
        ("encounters", Encounter),
        ("treatment_plans", TreatmentPlan),
    ]:
        if key not in requested:
            result[key] = []
            continue
        rows = (
            await db.scalars(
                select(model).where(model.patient_id == patient_id).order_by(model.created_at.desc())
            )
        ).all()
        if key == "encounters":
            provider_ids = {row.provider_id for row in rows}
            providers = (
                await db.scalars(select(StaffUser).where(StaffUser.id.in_(provider_ids)))
            ).all() if provider_ids else []
            provider_names = {provider.id: provider.name or provider.email for provider in providers}
            result[key] = [{**serialize(row), "provider_name": provider_names.get(row.provider_id, "")} for row in rows]
        else:
            if key == "entries":
                # Keep the chart view idempotent for historical duplicate declarations.
                # The newest missing status is the effective one; the audit trail still
                # retains every underlying row.
                seen_missing_teeth: set[str] = set()
                unique_rows = []
                for row in rows:
                    if is_missing_tooth_entry(row):
                        if row.tooth in seen_missing_teeth:
                            continue
                        seen_missing_teeth.add(row.tooth)
                    unique_rows.append(row)
                rows = unique_rows
            result[key] = [serialize(x) for x in rows]
    complete = [x for x in result["perio_exams"] if x["status"] == "complete"]
    result["perio_comparison"] = {}
    if len(complete) >= 2:
        for tooth, current in complete[0]["measurements"].items():
            prior = complete[1]["measurements"].get(tooth)
            if isinstance(prior, dict):
                result["perio_comparison"][tooth] = [
                    a - b for a, b in zip(current["depths"], prior["depths"], strict=True)
                ]
    audit(db, actor.user_id, "read", "clinical", patient_id, patient_id=patient_id)
    return result


# Handle addendum for this module.
@router.post("/addenda", status_code=201)
async def addendum(
    body: AddendumInput,
    db=Depends(db_session),
    actor=Depends(addendum_permission_actor()),
):
    models = {
        "encounter": Encounter,
        "perio_exam": PerioExam,
        "treatment_plan": TreatmentPlan,
        "day_surgery": DaySurgeryAdmission,
        "form_submission": FormSubmission,
    }
    row = await required(db, models[body.record_type], body.record_id, lock=True)
    patient_id = getattr(row, "patient_id", None)
    if not patient_id:
        raise HTTPException(409, "The selected record is not patient-linked")
    patient = await required(db, Patient, patient_id)
    finalized = (
        (body.record_type == "encounter" and row.status == "completed")
        or (body.record_type == "perio_exam" and row.status == "complete")
        or (body.record_type == "treatment_plan" and row.status in {"accepted", "declined", "expired"})
        or (body.record_type == "day_surgery" and row.status in {"discharged", "completed", "finalized"})
        or (body.record_type == "form_submission" and row.status in {"completed", "finalized"})
    )
    if not finalized:
        raise HTTPException(409, "Addenda can only be added to finalized records")
    permission_key = ADDENDUM_PERMISSIONS[body.record_type]
    snapshot = jsonable_encoder(serialize(row))
    payload = {
        "record_type": body.record_type,
        "record_id": row.id,
        "patient_id": patient.id,
        "reason": body.reason.strip(),
        "content": body.content,
        "source_hash": hashlib.sha256(
            json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    decision = await decide_tenant(
        db,
        actor.user_id,
        permission_key,
        selected_location_id=patient.location_id,
    )
    if not decision.allowed or decision.needs_step_up:
        raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission_key]})
    approval = None
    if decision.needs_approval:
        if body.approval_request_id:
            approval = await authorize_runtime_action(
                db,
                request_id=body.approval_request_id,
                permission_key=permission_key,
                payload=payload,
                maker_id=actor.user_id,
                request_model=TenantChangeRequest,
            )
        else:
            approval, created = await create_runtime_action_request(
                db,
                permission_key=permission_key,
                payload=payload,
                reason=body.reason,
                maker_id=actor.user_id,
                context=await tenant_policy_context(db),
                request_model=TenantChangeRequest,
                policy_model=TenantApprovalPolicy,
            )
            return JSONResponse(
                status_code=202,
                content=jsonable_encoder({
                    "status": "approval_required",
                    "request": await request_payload(db, approval, TenantChangeDecision),
                    "created": created,
                }),
            )
    previous = await db.scalar(
        select(RecordAddendum)
        .where(RecordAddendum.record_id == row.id)
        .order_by(RecordAddendum.created_at.desc())
    )
    addendum_row = await add(
        db,
        RecordAddendum,
        {
            "record_type": body.record_type,
            "record_id": row.id,
            "patient_id": patient.id,
            "parent_id": previous.id if previous else None,
            "reason": body.reason.strip(),
            "content": body.content,
            "source_snapshot": snapshot,
            "source_hash": payload["source_hash"],
            "finalized_at": datetime.now(UTC),
            "finalized_by": actor.user_id,
        },
        actor.user_id,
    )
    audit(
        db,
        actor.user_id,
        "addendum",
        "record_addenda",
        addendum_row.id,
        patient_id=patient.id,
        record_type=body.record_type,
        record_id=row.id,
        reason=body.reason,
        source_hash=payload["source_hash"],
    )
    if approval:
        await complete_runtime_action(
            approval,
            {"resource": "record_addendum", "resource_id": addendum_row.id},
        )
    await db.flush()
    return serialize(addendum_row)


# Retrieve list addenda for the current request or workflow.
@router.get("/{record_type}/{identifier}/addenda")
async def list_addenda(
    record_type: str,
    identifier: str,
    db=Depends(db_session),
    actor=Depends(record_read_permission_actor()),
):
    rows = (
        await db.scalars(
            select(RecordAddendum)
            .where(
                RecordAddendum.record_type == record_type,
                RecordAddendum.record_id == identifier,
            )
            .order_by(RecordAddendum.created_at)
        )
    ).all()
    audit(db, actor.user_id, "read-addenda", "record_addenda", identifier, record_type=record_type)
    return [serialize(row) for row in rows]


# Handle entry for this module.
@router.post("/entries", status_code=201)
async def entry(body: ChartInput, db=Depends(db_session), actor=Depends(permit_tenant("clinical.odontogram.create"))):
    patient = await required(db, Patient, body.patient_id)
    await ensure_patient_visibility(db, actor, patient.id)
    await validate_encounter(db, body.encounter_id, patient.id)
    if is_missing_tooth_entry(body):
        existing_missing = await db.scalar(
            select(ChartEntry)
            .where(
                ChartEntry.patient_id == patient.id,
                ChartEntry.tooth == body.tooth,
                ChartEntry.surface == "whole",
                func.lower(ChartEntry.condition).in_(MISSING_TOOTH_CONDITIONS),
                ChartEntry.status == "active",
            )
            .limit(1)
        )
        if existing_missing:
            raise HTTPException(
                status_code=409,
                detail="This tooth is already declared missing for this patient.",
            )
    catalogue_item = await db.scalar(
        select(TreatmentCatalogueItem).where(
            TreatmentCatalogueItem.active,
            TreatmentCatalogueItem.item_type.in_(["condition", "tooth_status"]),
            (func.lower(TreatmentCatalogueItem.code) == body.condition.strip().casefold())
            | (func.lower(TreatmentCatalogueItem.name) == body.condition.strip().casefold()),
        ).order_by(TreatmentCatalogueItem.item_type == "condition")
    )
    rendering_snapshot = None
    if catalogue_item:
        rendering_snapshot = {
            "schema_version": 1,
            "catalogue_item_id": catalogue_item.id,
            "catalogue_item_type": catalogue_item.item_type,
            "appearance_key": catalogue_item.appearance_key or "healthy",
            "draw_on": catalogue_item.draw_on or "",
            "surfaces": [body.surface],
            "renderer_version": "1",
        }
    row = await add(db, ChartEntry, {**body.model_dump(), "location_id": patient.location_id, "rendering_snapshot": rendering_snapshot}, actor.user_id)
    audit(db, actor.user_id, "create", "chart_entries", row.id, patient_id=patient.id)
    return serialize(row)


@router.post("/entries/{identifier}/return")
async def return_missing_tooth(
    identifier: str,
    body: MissingToothReturnInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.odontogram.return_missing", workflow_handles_approval=True)),
):
    """Request or apply the maker-approved return of a missing tooth.

    The original chart entry remains in place for clinical history and audit;
    only its status is changed from ``active`` to ``returned``.
    """
    row = await required(db, ChartEntry, identifier, lock=True)
    await ensure_patient_visibility(db, actor, row.patient_id)
    if not is_missing_tooth_entry(row):
        raise HTTPException(409, "Only an active missing-tooth declaration can be returned")

    permission_key = "clinical.odontogram.return_missing"
    payload = {
        "chart_entry_id": row.id,
        "patient_id": row.patient_id,
        "location_id": row.location_id,
        "action": "return_missing",
        "reason": body.reason.strip(),
    }
    decision = await decide_tenant(
        db,
        actor.user_id,
        permission_key,
        selected_location_id=row.location_id,
    )
    if not decision.allowed or decision.needs_step_up:
        raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission_key]})

    # Returning a missing tooth is always maker-checker governed, including
    # for the tenant-super-admin bootstrap role. The role bypass used for
    # initial RBAC setup must not silently reinstate clinical history.
    approval = None
    if body.approval_request_id:
        approval = await authorize_runtime_action(
            db,
            request_id=body.approval_request_id,
            permission_key=permission_key,
            payload=payload,
            maker_id=actor.user_id,
            request_model=TenantChangeRequest,
        )
    else:
        approval, created = await create_runtime_action_request(
            db,
            permission_key=permission_key,
            payload=payload,
            reason=body.reason,
            maker_id=actor.user_id,
            context=await tenant_policy_context(db),
            request_model=TenantChangeRequest,
            policy_model=TenantApprovalPolicy,
        )
        # A previously approved request can be safely replayed by the maker
        # after a page reload; pending requests remain explicitly un-applied.
        if approval.status != "approved":
            audit(
                db,
                actor.user_id,
                "chart-entry.return.approval-requested",
                "chart_entries",
                row.id,
                request_id=approval.id,
                created=created,
                patient_id=row.patient_id,
                tooth=row.tooth,
                reason=body.reason.strip(),
            )
            return JSONResponse(
                status_code=202,
                content=jsonable_encoder(
                    {
                        "status": "approval_required",
                        "request": await request_payload(db, approval, TenantChangeDecision),
                    }
                ),
            )

    row.status = "returned"
    row.status_reason = body.reason.strip()
    row.status_changed_at = datetime.now(UTC)
    row.status_changed_by = actor.user_id
    row.updated_by = actor.user_id
    audit(
        db,
        actor.user_id,
        "return",
        "chart_entries",
        row.id,
        patient_id=row.patient_id,
        tooth=row.tooth,
        reason=row.status_reason,
        request_id=approval.id if approval else None,
    )
    if approval:
        await complete_runtime_action(
            approval,
            {"resource": "chart_entry", "resource_id": row.id, "status": row.status},
        )
    await db.flush()
    return serialize(row)


# Handle perio for this module.
@router.post("/perio", status_code=201)
async def perio(body: PerioInput, db=Depends(db_session), actor=Depends(permit_tenant("clinical.periodontal_chart.create"))):
    patient = await required(db, Patient, body.patient_id)
    await ensure_patient_visibility(db, actor, patient.id)
    await validate_encounter(db, body.encounter_id, patient.id)
    row = await add(db, PerioExam, {**body.model_dump(), "location_id": patient.location_id}, actor.user_id)
    audit(db, actor.user_id, "create", "perio_exams", row.id, patient_id=patient.id)
    return serialize(row)


# Handle encounter update for this module.
@router.put("/encounters/{identifier}")
async def encounter_update(
    identifier: str, body: EncounterInput, db=Depends(db_session), actor=Depends(permit_tenant("clinical.clinical_encounter.update"))
):
    row = await required(db, Encounter, identifier, lock=True)
    await ensure_patient_visibility(db, actor, row.patient_id)
    if row.status != "open":
        raise HTTPException(409, "Closed encounter cannot be changed")
    from app.billing.models import Service

    for p in body.procedures:
        await required(db, Service, p.service_id)
    if body.provider_id is not None:
        await validate_encounter_provider(db, body.provider_id, row.location_id)
        row.provider_id = body.provider_id
    row.soap = body.soap
    row.procedures = [p.model_dump() for p in body.procedures]
    row.updated_by = actor.user_id
    audit(db, actor.user_id, "update", "encounters", row.id, patient_id=row.patient_id)
    await db.flush()
    return serialize(row)


# Handle encounter complete for this module.
@router.post("/encounters/{identifier}/complete")
async def encounter_complete(
    identifier: str,
    body: EncounterCompletionInput = EncounterCompletionInput(),
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.clinical_encounter.close", workflow_handles_approval=True)),
):
    row = await required(db, Encounter, identifier, lock=True)
    await ensure_patient_visibility(db, actor, row.patient_id)
    permission_key = "clinical.clinical_encounter.close"
    payload = {
        "encounter_id": row.id,
        "patient_id": row.patient_id,
        "location_id": row.location_id,
    }
    decision = await decide_tenant(
        db,
        actor.user_id,
        permission_key,
        selected_location_id=row.location_id,
    )
    if not decision.allowed or decision.needs_step_up:
        raise HTTPException(403, {"message": "Permission denied", "required_permissions": [permission_key]})
    approval = None
    if decision.needs_approval:
        if body.approval_request_id:
            approval = await authorize_runtime_action(
                db,
                request_id=body.approval_request_id,
                permission_key=permission_key,
                payload=payload,
                maker_id=actor.user_id,
                request_model=TenantChangeRequest,
            )
        else:
            approval, created = await create_runtime_action_request(
                db,
                permission_key=permission_key,
                payload=payload,
                reason=body.reason,
                maker_id=actor.user_id,
                context=await tenant_policy_context(db),
                request_model=TenantChangeRequest,
                policy_model=TenantApprovalPolicy,
            )
            audit(
                db,
                actor.user_id,
                "encounter.completion.approval-requested",
                "encounters",
                row.id,
                request_id=approval.id,
                created=created,
                patient_id=row.patient_id,
            )
            return JSONResponse(
                status_code=202,
                content=jsonable_encoder(
                    {
                        "status": "approval_required",
                        "request": await request_payload(db, approval, TenantChangeDecision),
                    }
                ),
            )
    completed = await close_encounter(db, actor, row)
    if approval:
        await complete_runtime_action(
            approval,
            {"resource": "encounter", "resource_id": row.id},
        )
    return serialize(completed)


@router.post("/treatment-plans/estimate")
async def estimate_treatment_plan(
    body: TreatmentInput,
    db=Depends(db_session),
    actor=Depends(permit_tenant("clinical.treatment_estimate.create")),
):
    """Price an in-progress plan without persisting it."""
    patient = await required(db, Patient, body.patient_id)
    await ensure_patient_visibility(db, actor, patient.id)
    provider = await required(db, StaffUser, body.provider_id)
    if (
        not provider.active
        or not provider.is_provider
        or provider.archived_at is not None
        or (provider.suspended_until and provider.suspended_until > datetime.now(UTC))
    ):
        raise HTTPException(422, "Treatment provider is not an active patient-facing provider")
    options = await estimate_options(db, body, patient)
    audit(db, actor.user_id, "estimate", "treatment_plans", patient_id=patient.id)
    return {"options": options}


# Handle plan for this module.
@router.post("/treatment-plans", status_code=201)
async def plan(body: TreatmentInput, db=Depends(db_session), actor=Depends(permit_tenant("clinical.treatment_plan.create"))):
    patient = await required(db, Patient, body.patient_id)
    await ensure_patient_visibility(db, actor, patient.id)
    provider = await required(db, StaffUser, body.provider_id)
    if (
        not provider.active
        or not provider.is_provider
        or provider.archived_at is not None
        or (provider.suspended_until and provider.suspended_until > datetime.now(UTC))
    ):
        raise HTTPException(422, "Treatment provider is not an active patient-facing provider")
    options = await estimate_options(db, body, patient)
    row = await add(
        db,
        TreatmentPlan,
        {
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "provider_id": body.provider_id,
            "title": body.title,
            "options": options,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "create", "treatment_plans", row.id, patient_id=patient.id)
    return serialize(row)


# Handle accept for this module.
@router.post("/treatment-plans/{identifier}/accept")
async def accept(
    identifier: str, body: Acceptance, db=Depends(db_session), actor=Depends(permit_tenant("clinical.treatment_plan.accept"))
):
    plan = await required(db, TreatmentPlan, identifier, lock=True)
    if body.option >= len(plan.options):
        raise HTTPException(422, "Unknown treatment option")
    if plan.status != "proposed":
        if plan.accepted_option != body.option:
            raise HTTPException(409, "A different option already has a signature request")
        return serialize(plan)
    consent = await add(
        db,
        Consent,
        {
            "patient_id": plan.patient_id,
            "location_id": plan.location_id,
            "title": plan.title + " — " + plan.options[body.option]["name"],
        },
        actor.user_id,
    )
    plan.accepted_option = body.option
    plan.consent_id = consent.id
    plan.status = "awaiting_signature"
    plan.updated_by = actor.user_id
    audit(db, actor.user_id, "request-acceptance", "treatment_plans", plan.id, patient_id=plan.patient_id)
    await db.flush()
    return serialize(plan)
