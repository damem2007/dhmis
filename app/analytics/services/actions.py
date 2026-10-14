"""Analytics action projection and role-scoped action queries."""

from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select

from app.analytics.models import AnalyticsActionItem
from app.analytics.scope import AnalyticsScope
from app.analytics.services.metrics import scoped
from app.billing.models import Invoice, PaymentPlan
from app.care_coordination.models import LabCase
from app.claims.models import Claim
from app.core.repository import serialize
from app.identity.models import StaffInvite
from app.notifications.models import OutboxMessage


# Handle upsert action for this module.
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


# Handle project actions for this module.
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


# Handle visible actions for this module.
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
