from datetime import date, datetime, timezone

from fastapi import HTTPException
from sqlalchemy import or_, select

from app.billing.models import FeeVersion, Invoice, LedgerEntry, Service
from app.claims.models import InsurancePlan
from app.code_library.models import CodeLibraryActivation
from app.clinical.models import TreatmentCatalogueItem
from app.core.audit import audit
from app.core.repository import add, required
from app.patients.models import Patient
from app.organizations.configuration import tenant_settings


def _procedure_fee_cents(catalogue_item=None, procedure=None) -> int:
    """Return the catalogue procedure surcharge, never a Services fee."""
    if catalogue_item is not None:
        return max(0, int(getattr(catalogue_item, "fee_cents", 0) or 0))
    return max(0, int((procedure or {}).get("procedure_fee_cents", 0) or 0))


def discount_amount_cents(subtotal_cents: int, discount: dict | None) -> int:
    """Calculate a reusable percentage/fixed discount and cap it at the subtotal."""
    if not discount or not discount.get("active", True):
        return 0
    today = date.today().isoformat()
    if discount.get("starts_on") and today < discount["starts_on"]:
        return 0
    if not discount.get("perpetual", True) and discount.get("ends_on") and today > discount["ends_on"]:
        return 0
    percentage = subtotal_cents * int(discount.get("percentage_bps", 0) or 0) // 10000
    fixed = int(discount.get("fixed_cents", 0) or 0)
    return min(max(0, subtotal_cents), max(0, percentage + fixed))


async def active_discounts(db):
    settings = await tenant_settings(db)
    return list((settings.policy or {}).get("discounts", []))


async def _price_procedure(db, procedure, location_id, provider_id=None):
    """Price an optional service plus an optional catalogue procedure fee."""
    catalogue_item = None
    catalogue_item_id = procedure.get("catalogue_item_id")
    if catalogue_item_id:
        catalogue_item = await required(db, TreatmentCatalogueItem, catalogue_item_id)
        if not catalogue_item.active or catalogue_item.item_type != "treatment":
            raise HTTPException(422, "The selected treatment catalogue item is not active")
        if procedure.get("service_id") and catalogue_item.service_id and procedure["service_id"] != catalogue_item.service_id:
            raise HTTPException(422, "The selected service does not match the treatment catalogue link")
    service_id = procedure.get("service_id") or (catalogue_item.service_id if catalogue_item else None)
    service_fee = await price(db, service_id, location_id, provider_id) if service_id else None
    procedure_fee = _procedure_fee_cents(catalogue_item, procedure)
    if not service_fee and procedure_fee < 0:
        raise HTTPException(422, "A procedure must have a service or a non-negative procedure fee")
    service_fee_cents = int(service_fee["fee_cents"]) if service_fee else 0
    total_fee_cents = service_fee_cents + procedure_fee
    if not service_fee and catalogue_item is None and procedure_fee == 0:
        raise HTTPException(422, "A procedure must have a service or a non-negative procedure fee")
    return {
        "catalogue_item": catalogue_item,
        "service": service_fee,
        "service_id": service_id,
        "service_fee_cents": service_fee_cents,
        "procedure_fee_cents": procedure_fee,
        "fee_cents": total_fee_cents,
        "name": catalogue_item.name if catalogue_item else (service_fee["name"] if service_fee else "Procedure"),
    }


# Handle price for this module.
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


# Create or issue create invoice while applying existing validation and authorization.
async def create_invoice(db, actor, patient_id, procedures, provider_id=None, discount_id=None):
    patient = await required(db, Patient, patient_id)
    lines = []
    for item in procedures:
        priced = await _price_procedure(db, item, patient.location_id, provider_id)
        quantity = item.get("quantity", 1)
        lines.append(
            {
                "service_id": priced["service_id"],
                "catalogue_item_id": item.get("catalogue_item_id"),
                "name": priced["name"],
                "fee_cents": priced["fee_cents"],
                "service_fee_cents": priced["service_fee_cents"],
                "procedure_fee_cents": priced["procedure_fee_cents"],
                "quantity": quantity,
                "tooth": item.get("tooth"),
                "line_total_cents": priced["fee_cents"] * quantity,
            }
        )
    total = sum(x["line_total_cents"] for x in lines)
    discount = next((item for item in await active_discounts(db) if item.get("id") == discount_id), None) if discount_id else None
    if discount_id and discount is None:
        raise HTTPException(422, "The selected discount is not available")
    discount_cents = discount_amount_cents(total, discount)
    settings = await tenant_settings(db)
    discount_mode = (settings.policy or {}).get("discount_application_mode", "invoice_before_insurance")
    invoice = await add(
        db,
        Invoice,
        {
            "patient_id": patient.id,
            "location_id": patient.location_id,
            "provider_id": provider_id,
            "lines": lines,
            "total_cents": total,
            "adjustment_cents": -discount_cents,
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
            "amount_cents": total - discount_cents,
            "idempotency_key": "charge:" + invoice.id,
        },
        actor.user_id,
    )
    if discount:
        invoice.lines = [*lines, {"kind": "discount", "discount_id": discount.get("id"), "name": discount.get("name"), "amount_cents": -discount_cents, "application_mode": discount_mode}]
    audit(db, actor.user_id, "create", "invoices", invoice.id, patient_id=patient.id, discount_id=discount_id or "")
    return invoice


# Handle estimate options for this module.
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
    code_library_active = bool(await db.scalar(select(CodeLibraryActivation.id).where(CodeLibraryActivation.status == "active")))
    for option in body.options:
        phases = []
        total = 0
        for phase in option.phases:
            procedures = []
            for procedure in phase.procedures:
                priced = await _price_procedure(db, procedure.model_dump(), patient.location_id, body.provider_id)
                catalogue_item = priced["catalogue_item"]
                amount = priced["fee_cents"] * procedure.quantity
                total += amount
                procedures.append({
                    **procedure.model_dump(),
                    "service_id": priced["service_id"],
                    "service_fee_cents": priced["service_fee_cents"],
                    "procedure_fee_cents": priced["procedure_fee_cents"],
                    "fee_cents": priced["fee_cents"],
                    "name": priced["name"],
                    "catalogue_code": catalogue_item.code if catalogue_item and code_library_active else None,
                    "line_total_cents": amount,
                })
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
