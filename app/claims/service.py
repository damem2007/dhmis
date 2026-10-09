from datetime import datetime, timezone

from fastapi import HTTPException

from app.billing.models import Invoice
from app.billing.service import payment
from app.claims.models import InsurancePlan
from app.core.audit import audit
from app.core.repository import required
from app.integrations.contracts import RemittanceRequest
from app.integrations.registry import resolve


async def adjudicate_claim(db, actor, claim):
    if claim.status not in ("submitted", "appealed"):
        return claim
    plan = await required(db, InsurancePlan, claim.plan_id, lock=True)
    result = await resolve(actor.organization, "claims_network").reconcile_remittance(
        RemittanceRequest(
            reference=claim.reference,
            amount_cents=claim.submitted_cents,
            coverage_pct=plan.coverage_pct,
            remaining_cents=max(0, plan.maximum_cents - plan.used_cents),
            waiting=bool(plan.waiting_until and plan.waiting_until > datetime.now(timezone.utc)),
        )
    )
    claim.status = result["status"]
    claim.covered_cents = result["covered_cents"]
    claim.remittance = result
    claim.updated_by = actor.user_id
    audit(db, actor.user_id, "adjudicate", "claims", claim.id, patient_id=plan.patient_id, sandbox=True)
    await db.flush()
    return claim


async def reconcile_claim(db, actor, claim):
    if claim.status == "paid":
        return claim
    if claim.status not in ("adjudicated", "review_required"):
        raise HTTPException(409, "Claim must be adjudicated first")
    plan = await required(db, InsurancePlan, claim.plan_id, lock=True)
    invoice = await required(db, Invoice, claim.invoice_id, lock=True)
    balance = invoice.total_cents + invoice.adjustment_cents - invoice.paid_cents
    if claim.covered_cents > balance or claim.covered_cents > plan.maximum_cents - plan.used_cents:
        claim.status = "review_required"
        claim.discrepancy = "Remittance exceeds invoice balance or remaining plan maximum"
        audit(
            db, actor.user_id, "reconciliation.discrepancy", "claims", claim.id, patient_id=invoice.patient_id
        )
        await db.flush()
        return claim
    if claim.covered_cents:
        await payment(
            db,
            actor,
            claim.invoice_id,
            claim.covered_cents,
            "remittance:" + claim.id,
            "insurance",
            claim.reference,
        )
    plan.used_cents += claim.covered_cents
    claim.status = "paid"
    claim.discrepancy = ""
    claim.updated_by = actor.user_id
    audit(db, actor.user_id, "reconcile", "claims", claim.id, patient_id=invoice.patient_id, sandbox=True)
    await db.flush()
    return claim
