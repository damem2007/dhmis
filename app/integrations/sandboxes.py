"""Deterministic domain-level simulators; no CDAnet/EDI wire-format certification implied."""

import asyncio
from hashlib import sha256

from app.integrations.contracts import IntegrationFailure, PaymentResult, SignatureResult


def reference(kind, key):
    return f"sandbox_{kind}_{sha256(key.encode()).hexdigest()[:20]}"


class Scenario:
    def __init__(self, mode="success", latency_ms=0):
        self.mode = mode
        self.latency_ms = latency_ms

    async def check(self):
        if self.latency_ms:
            await asyncio.sleep(self.latency_ms / 1000)
        if self.mode in ("timeout", "decline"):
            raise IntegrationFailure("Sandbox provider " + self.mode)


class SandboxPayments(Scenario):
    async def capture(self, request):
        amount_cents = request.amount_cents
        idempotency_key = request.idempotency_key
        await self.check()
        if amount_cents <= 0:
            raise ValueError("Payment must be positive")
        return PaymentResult(reference("payment", idempotency_key), amount_cents)

    async def refund(self, payment_reference, amount_cents, idempotency_key):
        await self.check()
        return PaymentResult(reference("refund", payment_reference + idempotency_key), amount_cents)


class SandboxClaims(Scenario):
    def __init__(self, region="CA", mode="success", latency_ms=0):
        super().__init__(mode, latency_ms)
        self.region = region

    async def check_eligibility(self, request):
        await self.check()
        return {
            "eligible": not request.waiting,
            "coverage_pct": request.coverage_pct,
            "remaining_cents": max(0, request.maximum_cents - request.used_cents),
            "waiting": request.waiting,
            "sandbox": True,
            "notice": "Seeded plan estimate; carrier eligibility support varies",
        }

    async def submit_claim(self, request):
        await self.check()
        if self.region == "US":
            transaction_type = "837D"
        elif self.region == "CA":
            if request.payer_order == 2:
                capability = request.context.get("cob_07_capability", "Y")
                if capability == "Y":
                    transaction_type = "07"
                elif capability == "X":
                    if request.context.get("primary_eob_version", 4) != 4:
                        raise IntegrationFailure(
                            "Carrier accepts COB 07 only with a CDAnet v4. Primary EOB"
                    )
                    transaction_type = "07"
                elif capability == "N":
                    raise IntegrationFailure(
                        "Carrier does not support COB 07 for this payer order"
                    )
                elif capability == "Z":
                    # Supported only for blue-on-blue claims
                    if not request.context.get("is_blue_on_blue", False):
                        raise IntegrationFailure(
                        "Carrier supports COB 07 only for blue-on-blue claims"
                    )
                    transaction_type = "07"
                else:
                    raise IntegrationFailure(
                    f"Unknown COB 07 capability: {capability}"
                )
            else:
                transaction_type = "01"
        else:
            raise IntegrationFailure(f"Unsupported claims region {self.region}")
        return {
            "reference": reference(self.region, request.idempotency_key),
            "status": "submitted",
            "acknowledgement": "accepted_for_processing",
            "transaction_type": transaction_type,
        }

    async def get_claim_status(self, claim_reference, persisted_status):
        await self.check()
        return {"reference": claim_reference, "status": persisted_status, "sandbox": True}

    async def reconcile_remittance(self, request):
        await self.check()
        denied = self.mode == "deny" or request.waiting
        covered = (
            0 if denied else min(request.amount_cents * request.coverage_pct // 100, request.remaining_cents)
        )
        return {
            "reference": request.reference,
            "status": "denied" if denied else "adjudicated",
            "covered_cents": covered,
            "patient_responsibility_cents": request.amount_cents - covered,
            "adjustment_code": "WAITING_PERIOD"
            if request.waiting
            else "SIMULATED_DENIAL"
            if denied
            else "COVERAGE_LIMIT",
            "format": "CDAnet-v4-domain" if self.region == "CA" else "835-domain",
            "sandbox": True,
        }


class SandboxSignatures(Scenario):
    async def request_signature(self, request):
        await self.check()
        return SignatureResult(
            reference=reference("signature", request.idempotency_key), status="requested", sandbox=True
        )

    async def get_signature(self, signature_reference):
        await self.check()
        return SignatureResult(
            reference=signature_reference,
            status="simulated",
            sandbox=True,
            certificate={
                "reference": signature_reference,
                "sandbox": True,
                "notice": "SIMULATED ONLY — not a legally signed consent",
            },
        )


class SandboxMessaging(Scenario):
    async def send(self, request):
        await self.check()
        return {
            "reference": reference("message", request.idempotency_key),
            "status": "simulated",
            "sandbox": True,
        }


class SandboxAccounting(Scenario):
    async def export(self, records, idempotency_key):
        await self.check()
        return {"reference": reference("export", idempotency_key), "count": len(records), "sandbox": True}
