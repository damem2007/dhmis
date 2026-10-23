from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, select

from app.billing.models import FeeVersion, Invoice, LedgerEntry, Service
from app.billing.defaults import ensure_default_services
from app.clinical.models import TreatmentCatalogueItem
from app.billing.service import payment
from app.core.audit import audit
from app.core.repository import add, required, serialize
from app.identity.service import db_session, permit
from app.rbac.dependencies import permit_tenant
from app.patients.models import Patient
from app.organizations.configuration import tenant_settings

router = APIRouter(prefix="/billing", tags=["Billing and ledger"])


# Defines the service input model, contract, or value object.
class ServiceInput(BaseModel):
    code: str = Field(min_length=1, max_length=30)
    name: str = Field(min_length=1, max_length=180)
    fee_cents: int = Field(ge=0, le=10000000)
    description: str = Field(default="", max_length=1000)


# Defines the invoice input model, contract, or value object.
class InvoiceInput(BaseModel):
    patient_id: str
    service_ids: list[str] = Field(min_length=1, max_length=100)
    discount_id: str | None = Field(default=None, max_length=80)


# Defines the payment input model, contract, or value object.
class PaymentInput(BaseModel):
    payment_method_token: str | None = None
    amount_cents: int = Field(gt=0)
    idempotency_key: str = Field(min_length=8, max_length=100)


async def services_with_catalogue_links(db):
    """Return tenant services with the catalogue links already stored on them."""
    rows = (await db.scalars(select(Service).order_by(Service.name))).all()
    links = (await db.execute(
        select(
            TreatmentCatalogueItem.service_id,
            TreatmentCatalogueItem.id,
            TreatmentCatalogueItem.name,
            TreatmentCatalogueItem.code,
            TreatmentCatalogueItem.item_type,
            TreatmentCatalogueItem.active,
        ).where(TreatmentCatalogueItem.service_id.is_not(None), TreatmentCatalogueItem.item_type == "treatment")
    )).all()
    links_by_service: dict[str, list[dict]] = {}
    for service_id, item_id, name, code, item_type, active in links:
        links_by_service.setdefault(service_id, []).append({
            "id": item_id,
            "name": name,
            "code": code,
            "item_type": item_type,
            "active": active,
        })
    return [
        {
            **serialize(row),
            "catalogue_links": links_by_service.get(row.id, []),
        }
        for row in rows
    ]


# Handle services for this module.
@router.get("/services")
async def services(db=Depends(db_session), actor=Depends(permit_tenant("billing.service_catalogue_item.read"))):
    await ensure_default_services(db)
    return await services_with_catalogue_links(db)


# Handle service for this module.
@router.post("/services", status_code=201)
async def service(body: ServiceInput, db=Depends(db_session), actor=Depends(permit_tenant("billing.service_catalogue_item.create"))):
    if await db.scalar(select(Service).where(Service.code == body.code)):
        raise HTTPException(409, "Service code already exists")
    row = await add(db, Service, body.model_dump(), actor.user_id)
    audit(db, actor.user_id, "create", "services", row.id)
    return serialize(row)


# Update update service while preserving existing validation and audit behavior.
@router.put("/services/{identifier}")
async def update_service(identifier: str, body: ServiceInput, db=Depends(db_session), actor=Depends(permit_tenant("billing.service_catalogue_item.update"))):
    row = await required(db, Service, identifier)
    duplicate = await db.scalar(select(Service).where(Service.code == body.code, Service.id != identifier))
    if duplicate:
        raise HTTPException(409, "Service code already exists")
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    audit(db, actor.user_id, "update", "services", row.id)
    return serialize(row)


# Apply the delete service lifecycle transition and its existing safeguards.
@router.delete("/services/{identifier}")
async def delete_service(identifier: str, db=Depends(db_session), actor=Depends(permit_tenant("billing.service_catalogue_item.archive"))):
    row = await required(db, Service, identifier)
    if await db.scalar(select(FeeVersion.id).where(FeeVersion.service_id == identifier).limit(1)):
        raise HTTPException(409, "This service has fee history and cannot be deleted")
    invoices = (await db.scalars(select(Invoice))).all()
    if any(any(line.get("service_id") == identifier for line in (invoice.lines or [])) for invoice in invoices):
        raise HTTPException(409, "This service is used by an invoice and cannot be deleted")
    await db.execute(delete(Service).where(Service.id == identifier))
    audit(db, actor.user_id, "delete", "services", identifier)
    return {"deleted": True, "id": identifier}


# Handle invoices for this module.
@router.get("/invoices")
async def invoices(
    patient_id: str = Query("", max_length=36),
    db=Depends(db_session),
    actor=Depends(permit("billing")),
):
    query = select(Invoice).order_by(Invoice.created_at.desc())
    if patient_id:
        query = query.where(Invoice.patient_id == patient_id)
    rows = (await db.scalars(query.limit(200))).all()
    audit(db, actor.user_id, "read", "invoices", count=len(rows))
    return [serialize(x) for x in rows]


# Handle invoice for this module.
@router.post("/invoices", status_code=201)
async def invoice(body: InvoiceInput, db=Depends(db_session), actor=Depends(permit("billing"))):
    from app.billing.pricing import create_invoice

    return serialize(
        await create_invoice(
            db,
            actor,
            body.patient_id,
            [{"service_id": identifier, "quantity": 1} for identifier in body.service_ids],
            discount_id=body.discount_id,
        )
    )


@router.get("/discounts")
async def discounts(db=Depends(db_session), actor=Depends(permit_tenant("billing.discount.read"))):
    """Return the tenant's reusable discounts for billing selection."""
    settings = await tenant_settings(db)
    return settings.policy.get("discounts", [])


# Handle pay for this module.
@router.post("/invoices/{identifier}/payments")
async def pay(identifier: str, body: PaymentInput, db=Depends(db_session), actor=Depends(permit("billing"))):
    return serialize(
        await payment(
            db,
            actor,
            identifier,
            body.amount_cents,
            body.idempotency_key,
            payment_method_token=body.payment_method_token,
        )
    )


# Handle ledger for this module.
@router.get("/ledger/{patient_id}")
async def ledger(patient_id: str, db=Depends(db_session), actor=Depends(permit("billing"))):
    await required(db, Patient, patient_id)
    rows = (
        await db.scalars(
            select(LedgerEntry).where(LedgerEntry.patient_id == patient_id).order_by(LedgerEntry.created_at)
        )
    ).all()
    audit(db, actor.user_id, "read", "ledger", patient_id)
    return {"entries": [serialize(x) for x in rows], "balance_cents": sum(x.amount_cents for x in rows)}


# Handle catalog for this module.
@router.get("/catalog")
async def catalog(db=Depends(db_session), actor=Depends(permit_tenant("billing.service_catalogue_item.read"))):
    # Keep existing tenant schemas aligned with the catalogue defaults even
    # when they were provisioned before the default-services migration ran.
    await ensure_default_services(db)
    return await services_with_catalogue_links(db)
