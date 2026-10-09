from datetime import datetime, timezone

from sqlalchemy import or_, select

from app.billing.models import FeeVersion, Invoice, LedgerEntry, Service
from app.claims.models import InsurancePlan
from app.core.audit import audit
from app.core.repository import add, required
from app.patients.models import Patient


async def price(db, service_id, location_id, provider_id=None, at=None):
    service = await required(db, Service, service_id)
    at = at or datetime.now(timezone.utc)
    versions = (
        await db.scalars(
            select(FeeVersion).where(
                FeeVersion.service_id == service_id,
                FeeVersion.effective_at <= at,
                or_(FeeVersion.location_id.is_(None), FeeVersion.location_id == location_id),
                or_(FeeVersion.provider_id.is_(None), FeeVersion.provider_id == provider_id),
            )
        )
    ).all()
    versions.sort(
        key=lambda v: (
            int(v.provider_id is not None) * 2 + int(v.location_id is not None),
            v.effective_at,
            v.created_at,
        ),
        reverse=True,
    )
    selected = versions[0] if versions else None
    return {
        "service_id": service.id,
        "code": service.code,
        "name": service.name,
        "fee_cents": selected.fee_cents if selected else service.fee_cents,
        "fee_version_id": selected.id if selected else None,
    }


async def create_invoice(db, actor, patient_id, procedures, provider_id=None):
    patient = await required(db, Patient, patient_id)
    lines = []
    for item in procedures:
        line = await price(db, item["service_id"], patient.location_id, provider_id)
        quantity = item.get("quantity", 1)
        lines.append(
            {
                **line,
                "quantity": quantity,
                "tooth": item.get("tooth"),
                "line_total_cents": line["fee_cents"] * quantity,
            }
        )
    total = sum(x["line_total_cents"] for x in lines)
    invoice = await add(
        db,
        Invoice,
        {
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "provider_id": provider_id,
            "lines": lines,
            "total_cents": total,
        },
        actor.user_id,
    )
    await add(
        db,
        LedgerEntry,
        {
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "invoice_id": invoice.id,
            "kind": "charge",
            "amount_cents": total,
            "idempotency_key": "charge:" + invoice.id,
        },
        actor.user_id,
    )
    audit(db, actor.user_id, "create", "invoices", invoice.id, patient_id=patient.id)
    return invoice


async def estimate_options(db, body, patient):
    plans = (
        await db.scalars(
            select(InsurancePlan)
            .where(InsurancePlan.patient_id == patient.id)
            .order_by(InsurancePlan.priority)
        )
    ).all()
    options = []
    now = datetime.now(timezone.utc)
    for option in body.options:
        phases = []
        total = 0
        for phase in option.phases:
            procedures = []
            for procedure in phase.procedures:
                fee = await price(db, procedure.service_id, patient.location_id, body.provider_id)
                amount = fee["fee_cents"] * procedure.quantity
                total += amount
                procedures.append({**procedure.model_dump(), **fee, "line_total_cents": amount})
            phases.append({"name": phase.name, "procedures": procedures})
        remaining = total
        for plan in plans:
            if plan.waiting_until and plan.waiting_until > now:
                continue
            remaining -= min(
                remaining * plan.coverage_pct // 100, max(0, plan.maximum_cents - plan.used_cents)
            )
        options.append(
            {
                "name": option.name,
                "phases": phases,
                "total_cents": total,
                "estimated_insurance_cents": total - remaining,
                "estimated_patient_cents": remaining,
                "estimate_only": True,
            }
        )
    return options
