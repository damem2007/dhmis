from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class IntegrationFailure(Exception):
    pass


class PaymentRequest(BaseModel):
    idempotency_key: str
    amount_cents: int = Field(gt=0)
    currency: str = Field(pattern="^[A-Z]{3}$")
    patient_id: str
    invoice_id: str
    payment_method_token: str | None = None


class MessageRequest(BaseModel):
    idempotency_key: str
    channel: Literal["email", "sms"]
    destination: str
    subject: str
    body: str


class SignatureRequest(BaseModel):
    idempotency_key: str
    document_id: str
    document_digest: str
    signer_name: str
    signer_email: str


class SignatureResult(BaseModel):
    reference: str
    status: Literal["requested", "completed", "simulated", "failed"]
    sandbox: bool
    certificate: dict = Field(default_factory=dict)


@dataclass(frozen=True)
class PaymentResult:
    reference: str
    amount_cents: int
    sandbox: bool = True
    status: str = "captured"


class EligibilityRequest(BaseModel):
    coverage_pct: int = Field(ge=0, le=100)
    maximum_cents: int = Field(ge=0)
    used_cents: int = Field(ge=0)
    waiting: bool = False


class ClaimRequest(BaseModel):
    idempotency_key: str
    amount_cents: int = Field(ge=0)
    payer_order: int = Field(ge=1, le=2)
    context: dict = Field(default_factory=dict)


class RemittanceRequest(BaseModel):
    reference: str
    amount_cents: int = Field(ge=0)
    coverage_pct: int = Field(ge=0, le=100)
    remaining_cents: int = Field(ge=0)
    waiting: bool = False


@runtime_checkable
class PaymentGateway(Protocol):
    async def capture(self, request: PaymentRequest) -> PaymentResult: ...
    async def refund(
        self, payment_reference: str, amount_cents: int, idempotency_key: str
    ) -> PaymentResult: ...


@runtime_checkable
class ClaimsNetwork(Protocol):
    async def check_eligibility(self, request: EligibilityRequest) -> dict: ...
    async def submit_claim(self, request: ClaimRequest) -> dict: ...
    async def get_claim_status(self, reference: str, persisted_status: str) -> dict: ...
    async def reconcile_remittance(self, request: RemittanceRequest) -> dict: ...


@runtime_checkable
class SignatureProvider(Protocol):
    async def request_signature(self, request: SignatureRequest) -> SignatureResult: ...
    async def get_signature(self, reference: str) -> SignatureResult: ...


@runtime_checkable
class MessagingProvider(Protocol):
    async def send(self, request: MessageRequest) -> dict: ...


@runtime_checkable
class GeocodingProvider(Protocol):
    async def search(self, query: str, region: str, limit: int = 5) -> list[dict]: ...


@runtime_checkable
class MapProvider(Protocol):
    def location_links(
        self,
        latitude: float,
        longitude: float,
        address: str = "",
    ) -> dict[str, str]: ...


@runtime_checkable
class AccountingExporter(Protocol):
    async def export(self, records: list[dict], idempotency_key: str) -> dict: ...
