from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import func, select

from app.analytics.catalogue import DEFINITIONS
from app.analytics.models import AnalyticsActionItem
from app.analytics.scope import AnalyticsScope
from app.billing.models import Invoice, LedgerEntry, PaymentPlan
from app.care_coordination.models import LabCase
from app.claims.models import Claim
from app.clinical.models import Encounter, TreatmentPlan
from app.core.repository import serialize
from app.identity.models import StaffInvite, StaffUser
from app.identity.service import role_names_with_module
from app.notifications.models import OutboxMessage
from app.organizations.models import Location
from app.scheduling.models import Appointment

ROLE_METRICS = {
    "organization-executive": [
        "production", "collections", "collection_rate", "ar_balance", "visits",
        "chair_utilization", "no_show_rate", "case_acceptance",
    ],
    "clinic-admin": [
        "production", "collections", "ar_balance", "visits", "chair_utilization",
        "no_show_rate", "case_acceptance",
    ],
    "system-admin": ["active_staff", "failed_notifications"],
    "dentist": ["visits", "completed_encounters", "case_acceptance", "no_show_rate"],
    "hygienist": ["visits", "completed_encounters", "chair_utilization", "no_show_rate"],
    "dental-assistant": ["visits", "completed_encounters"],
    "treatment-coordinator": ["case_acceptance", "visits", "ar_balance"],
    "front-desk": ["visits", "no_show_rate", "chair_utilization", "failed_notifications"],
    "accounting": [
        "production", "collections", "collection_rate", "ar_balance", "pending_claims",
        "denied_claims",
    ],
}


def boundaries(start: date, end: date):
    return (
        datetime.combine(start, time.min, tzinfo=UTC),
        datetime.combine(end + timedelta(days=1), time.min, tzinfo=UTC),
    )


def scoped(query, model, scope: AnalyticsScope):
    if scope.location_ids and hasattr(model, "location_id"):
        query = query.where(model.location_id.in_(scope.location_ids))
    if scope.provider_id:
        provider_column = getattr(model, "provider_id", None)
        if provider_column is None:
            provider_column = getattr(model, "prescriber_id", None)
        if provider_column is not None:
            query = query.where(provider_column == scope.provider_id)
    return query


def metric(key, value, *, available=True):
    definition = DEFINITIONS[key]
    return {
        "key": key,
        "label": definition.label,
        "definition": definition.definition,
        "unit": definition.unit,
        "version": definition.version,
        "value": value if available else None,
        "available": available,
        "drilldown": f"/analytics/worklists/{key}",
    }


async def calculate_metrics(db, scope: AnalyticsScope, start: date, end: date):
    beginning, ending = boundaries(start, end)
    invoice_query = scoped(
        select(Invoice).where(Invoice.created_at >= beginning, Invoice.created_at < ending),
        Invoice,
        scope,
    )
    collection_query = scoped(
        select(LedgerEntry).where(
            LedgerEntry.created_at >= beginning,
            LedgerEntry.created_at < ending,
            LedgerEntry.kind.in_(["payment", "insurance"]),
        ),
        LedgerEntry,
        scope,
    )
    appointment_query = scoped(
        select(Appointment).where(
            Appointment.starts_at >= beginning,
            Appointment.starts_at < ending,
            Appointment.status != "cancelled",
        ),
        Appointment,
        scope,
    )
    encounter_query = scoped(
        select(Encounter).where(
            Encounter.updated_at >= beginning,
            Encounter.updated_at < ending,
            Encounter.status == "completed",
        ),
        Encounter,
        scope,
    )
    treatment_query = scoped(
        select(TreatmentPlan).where(
            TreatmentPlan.created_at >= beginning,
            TreatmentPlan.created_at < ending,
        ),
        TreatmentPlan,
        scope,
    )
    invoices = (await db.scalars(invoice_query)).all()
    collections = (await db.scalars(collection_query)).all()
    appointments = (await db.scalars(appointment_query)).all()
    encounters = (await db.scalars(encounter_query)).all()
    treatments = (await db.scalars(treatment_query)).all()
    production = sum(row.total_cents + row.adjustment_cents for row in invoices)
    collected = sum(-row.amount_cents for row in collections)
    all_ar_query = scoped(select(Invoice), Invoice, scope)
    all_invoices = (await db.scalars(all_ar_query)).all()
    ar_balance = sum(
        max(0, row.total_cents + row.adjustment_cents - row.paid_cents)
        for row in all_invoices
    )
    accepted = sum(row.status == "accepted" for row in treatments)
    presented = len(treatments)
    no_shows = sum(row.status == "no-show" for row in appointments)
    scheduled_minutes = sum(
        max(0, int((row.ends_at - row.starts_at).total_seconds() // 60))
        for row in appointments
    )
    location_query = select(Location)
    if scope.location_ids:
        location_query = location_query.where(Location.id.in_(scope.location_ids))
    locations = (await db.scalars(location_query)).all()
    days = max(1, (end - start).days + 1)
    capacity = sum(
        max(0, row.closing_hour - row.opening_hour) * 60 * len(row.chairs) * days
        for row in locations
    )
    pending_claim_query = select(func.count()).select_from(Claim).where(
        Claim.status.not_in(["paid", "denied"])
    )
    denied_claim_query = select(func.count()).select_from(Claim).where(Claim.status == "denied")
    pending_claim_query = scoped(pending_claim_query, Claim, scope)
    denied_claim_query = scoped(denied_claim_query, Claim, scope)
    failed_notifications = await db.scalar(
        select(func.count()).select_from(OutboxMessage).where(
            OutboxMessage.status.in_(["failed", "retry"])
        )
    )
    staff_rows = (await db.scalars(select(StaffUser).where(StaffUser.active))).all()
    if scope.location_ids:
        staff_rows = [
            row
            for row in staff_rows
            if not row.location_ids or set(row.location_ids).intersection(scope.location_ids)
        ]
    values = {
        "production": production,
        "collections": collected,
        "collection_rate": round(collected * 100 / production, 1) if production else 0,
        "ar_balance": ar_balance,
        "visits": len(appointments),
        "no_show_rate": round(no_shows * 100 / len(appointments), 1) if appointments else 0,
        "chair_utilization": round(scheduled_minutes * 100 / capacity, 1) if capacity else 0,
        "case_acceptance": round(accepted * 100 / presented, 1) if presented else 0,
        "pending_claims": await db.scalar(pending_claim_query) or 0,
        "denied_claims": await db.scalar(denied_claim_query) or 0,
        "active_staff": len(staff_rows),
        "failed_notifications": failed_notifications or 0,
        "completed_encounters": len(encounters),
    }
    keys = ROLE_METRICS.get(scope.profile, [])
    if not scope.can_view_financial:
        keys = [key for key in keys if DEFINITIONS[key].unit != "currency"]
    return [metric(key, values[key]) for key in keys]


async def organization_breakdown(db, scope: AnalyticsScope, start: date, end: date):
    """Return real location and provider rows for organization dashboard tables."""
    if scope.profile not in {"organization-executive", "clinic-admin"}:
        raise PermissionError("Organization breakdown is outside this role scope")
    beginning, ending = boundaries(start, end)
    location_query = select(Location).order_by(Location.name)
    if scope.location_ids:
        location_query = location_query.where(Location.id.in_(scope.location_ids))
    locations = (await db.scalars(location_query)).all()
    location_ids = {row.id for row in locations}

    appointment_query = select(Appointment).where(
        Appointment.starts_at >= beginning,
        Appointment.starts_at < ending,
        Appointment.status != "cancelled",
    )
    invoice_query = select(Invoice).where(
        Invoice.created_at >= beginning,
        Invoice.created_at < ending,
    )
    treatment_query = select(TreatmentPlan).where(
        TreatmentPlan.created_at >= beginning,
        TreatmentPlan.created_at < ending,
    )
    if scope.location_ids:
        appointment_query = appointment_query.where(Appointment.location_id.in_(location_ids))
        invoice_query = invoice_query.where(Invoice.location_id.in_(location_ids))
        treatment_query = treatment_query.where(TreatmentPlan.location_id.in_(location_ids))
    appointments = (await db.scalars(appointment_query)).all()
    invoices = (await db.scalars(invoice_query)).all()
    treatments = (await db.scalars(treatment_query)).all()
    providers = (
        await db.scalars(
            select(StaffUser)
            .where(StaffUser.active, StaffUser.role.in_(await role_names_with_module(db, "clinical")))
            .order_by(StaffUser.name)
        )
    ).all()
    days = max(1, (end - start).days + 1)

    location_rows = []
    for location in locations:
        visits = [row for row in appointments if row.location_id == location.id]
        billed = [row for row in invoices if row.location_id == location.id]
        plans = [row for row in treatments if row.location_id == location.id]
        scheduled_minutes = sum(
            max(0, int((row.ends_at - row.starts_at).total_seconds() // 60)) for row in visits
        )
        capacity = max(0, location.closing_hour - location.opening_hour) * 60 * len(location.chairs) * days
        location_rows.append(
            {
                "id": location.id,
                "name": location.name,
                "visits": len(visits),
                "production_cents": sum(row.total_cents + row.adjustment_cents for row in billed),
                "chair_utilization": round(scheduled_minutes * 100 / capacity, 1) if capacity else 0,
                "case_acceptance": (
                    round(sum(row.status == "accepted" for row in plans) * 100 / len(plans), 1)
                    if plans
                    else 0
                ),
            }
        )

    provider_rows = []
    for provider in providers:
        visits = [row for row in appointments if row.provider_id == provider.id]
        billed = [row for row in invoices if row.provider_id == provider.id]
        if scope.location_ids:
            visits = [row for row in visits if row.location_id in scope.location_ids]
            billed = [row for row in billed if row.location_id in scope.location_ids]
        primary_location = next(
            (location.name for location in locations if any(row.location_id == location.id for row in visits)),
            "—",
        )
        provider_rows.append(
            {
                "id": provider.id,
                "name": provider.name,
                "location": primary_location,
                "production_cents": sum(row.total_cents + row.adjustment_cents for row in billed),
                "visits": len(visits),
                "no_show_rate": (
                    round(sum(row.status == "no-show" for row in visits) * 100 / len(visits), 1)
                    if visits
                    else 0
                ),
            }
        )
    return {"locations": location_rows, "providers": provider_rows}


async def upsert_action(db, *, dedupe_key: str, actor_id: str, **values):
    row = await db.scalar(
        select(AnalyticsActionItem).where(AnalyticsActionItem.dedupe_key == dedupe_key)
    )
    now = datetime.now(UTC)
    if row is None:
        row = AnalyticsActionItem(
            dedupe_key=dedupe_key,
            source_updated_at=now,
            created_by=actor_id,
            updated_by=actor_id,
            **values,
        )
        db.add(row)
    else:
        for key, value in values.items():
            setattr(row, key, value)
        row.source_updated_at = now
        row.updated_by = actor_id
    return row


async def project_actions(db, actor, scope: AnalyticsScope):
    failed = (
        await db.scalars(
            select(OutboxMessage).where(OutboxMessage.status.in_(["failed", "retry"]))
        )
    ).all()
    if failed:
        await upsert_action(
            db,
            dedupe_key="notifications:delivery-failures",
            actor_id=actor.user_id,
            category="operations",
            title=f"{len(failed)} notification deliveries need attention",
            detail="Open failed notification jobs and retry after correcting the provider or destination.",
            severity="urgent",
            role_scopes=["system-admin", "organization-executive", "front-desk"],
            target={"nav": "settings", "worklist": "notifications"},
        )
    claim_query = scoped(select(Claim).where(Claim.status == "denied"), Claim, scope)
    denied = (await db.scalars(claim_query.limit(50))).all()
    for claim in denied:
        await upsert_action(
            db,
            dedupe_key=f"claim:{claim.id}:denied",
            actor_id=actor.user_id,
            category="claims",
            title="Denied claim requires review",
            detail=f"Claim {claim.reference or claim.id} is denied and may require correction or appeal.",
            severity="urgent",
            role_scopes=["accounting", "organization-executive", "clinic-admin"],
            location_id=getattr(claim, "location_id", None),
            target={"nav": "claims", "claim_id": claim.id},
        )
    expired_invites = (
        await db.scalars(
            select(StaffInvite).where(
                StaffInvite.used.is_(False), StaffInvite.expires < int(datetime.now(UTC).timestamp())
            )
        )
    ).all()
    for invite in expired_invites:
        await upsert_action(
            db,
            dedupe_key=f"staff-invite:{invite.id}:expired",
            actor_id=actor.user_id,
            category="access",
            title="Staff invitation expired",
            detail=f"{invite.name} · {invite.email}",
            severity="info",
            role_scopes=["system-admin", "organization-executive", "clinic-admin"],
            target={"nav": "settings", "section": "staff", "invite_id": invite.id},
        )
    lab_query = scoped(
        select(LabCase).where(
            LabCase.due_at < datetime.now(UTC),
            LabCase.status.not_in(["received", "closed", "cancelled"]),
        ),
        LabCase,
        scope,
    )
    overdue_labs = (await db.scalars(lab_query.limit(50))).all()
    for lab in overdue_labs:
        await upsert_action(
            db,
            dedupe_key=f"lab:{lab.id}:overdue",
            actor_id=actor.user_id,
            category="clinical-operations",
            title="Lab case is overdue",
            detail=f"{lab.case_type} from {lab.laboratory}",
            severity="watch",
            role_scopes=["dentist", "dental-assistant", "clinic-admin"],
            location_id=lab.location_id,
            provider_id=lab.provider_id,
            patient_id=lab.patient_id,
            target={"nav": "care", "lab_id": lab.id},
        )
    plans_query = scoped(select(PaymentPlan), PaymentPlan, scope)
    plans = (await db.scalars(plans_query)).all()
    invoice_ids = [row.invoice_id for row in plans]
    invoice_rows = (
        (await db.scalars(select(Invoice).where(Invoice.id.in_(invoice_ids)))).all()
        if invoice_ids
        else []
    )
    invoice_map = {row.id: row for row in invoice_rows}
    today = datetime.now(UTC).date()
    for plan in plans:
        invoice = invoice_map.get(plan.invoice_id)
        if not invoice or invoice.total_cents + invoice.adjustment_cents <= invoice.paid_cents:
            continue
        upcoming = [
            installment
            for installment in plan.installments
            if date.fromisoformat(installment["due"]) <= today + timedelta(days=3)
        ]
        if not upcoming:
            continue
        next_due = min(upcoming, key=lambda item: item["due"])
        due = date.fromisoformat(next_due["due"])
        overdue = due < today
        await upsert_action(
            db,
            dedupe_key=f"payment-plan:{plan.id}:{next_due['due']}",
            actor_id=actor.user_id,
            category="receivables",
            title="Installment overdue" if overdue else "Installment due soon",
            detail=f"{next_due['amount_cents']} cents due {next_due['due']}",
            severity="urgent" if overdue else "watch",
            role_scopes=["accounting", "front-desk", "organization-executive"],
            location_id=plan.location_id,
            patient_id=plan.patient_id,
            target={"nav": "billing", "payment_plan_id": plan.id},
        )
    await db.flush()


async def visible_actions(db, scope: AnalyticsScope, *, status: str | None = None, limit=10):
    query = select(AnalyticsActionItem).order_by(
        AnalyticsActionItem.severity, AnalyticsActionItem.source_updated_at.desc()
    )
    if status:
        query = query.where(AnalyticsActionItem.status == status)
    if scope.location_ids:
        query = query.where(
            (AnalyticsActionItem.location_id.is_(None))
            | (AnalyticsActionItem.location_id.in_(scope.location_ids))
        )
    if scope.provider_id:
        query = query.where(
            (AnalyticsActionItem.provider_id.is_(None))
            | (AnalyticsActionItem.provider_id == scope.provider_id)
        )
    rows = (await db.scalars(query.limit(max(limit * 5, 50)))).all()
    rows = [row for row in rows if not row.role_scopes or scope.profile in row.role_scopes]
    return [serialize(row) for row in rows[:limit]]


async def worklist(
    db,
    key: str,
    scope: AnalyticsScope,
    start: date,
    end: date,
    *,
    page: int,
    page_size: int,
    search: str = "",
):
    beginning, ending = boundaries(start, end)
    if key in {"production", "ar_balance"}:
        model = Invoice
        query = select(model)
        if key == "production":
            query = query.where(model.created_at >= beginning, model.created_at < ending)
        else:
            query = query.where(
                model.total_cents + model.adjustment_cents - model.paid_cents > 0
            )
    elif key == "collections":
        model = LedgerEntry
        query = select(model).where(
            model.created_at >= beginning,
            model.created_at < ending,
            model.kind.in_(["payment", "insurance"]),
        )
    elif key in {"visits", "no_show_rate", "chair_utilization"}:
        model = Appointment
        query = select(model).where(
            model.starts_at >= beginning,
            model.starts_at < ending,
            model.status != "cancelled",
        )
        if key == "no_show_rate":
            query = query.where(model.status == "no-show")
    elif key == "case_acceptance":
        model = TreatmentPlan
        query = select(model).where(
            model.created_at >= beginning,
            model.created_at < ending,
        )
    elif key in {"pending_claims", "denied_claims"}:
        model = Claim
        query = select(model)
        query = (
            query.where(model.status == "denied")
            if key == "denied_claims"
            else query.where(model.status.not_in(["paid", "denied"]))
        )
    elif key == "completed_encounters":
        model = Encounter
        query = select(model).where(
            model.updated_at >= beginning,
            model.updated_at < ending,
            model.status == "completed",
        )
    elif key == "active_staff":
        model = StaffUser
        query = select(model).where(model.active)
    elif key == "failed_notifications":
        model = OutboxMessage
        query = select(model).where(model.status.in_(["failed", "retry"]))
    else:
        raise KeyError(key)
    query = scoped(query, model, scope)
    if search:
        patterns = []
        for name in ("reference", "procedure", "title", "name", "email", "kind"):
            column = getattr(model, name, None)
            if column is not None:
                patterns.append(column.ilike(f"%{search}%"))
        if patterns:
            from sqlalchemy import or_

            query = query.where(or_(*patterns))
    count_query = select(func.count()).select_from(query.order_by(None).subquery())
    total = await db.scalar(count_query) or 0
    rows = (
        await db.scalars(
            query.order_by(getattr(model, "created_at").desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    return {
        "key": key,
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [serialize(row) for row in rows],
    }
