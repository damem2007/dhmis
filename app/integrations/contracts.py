from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


# Defines the integration failure model, contract, or value object.
class IntegrationFailure(Exception):
    pass


# Defines the payment request model, contract, or value object.
class PaymentRequest(BaseModel):
    idempotency_key: str
    amount_cents: int = Field(gt=0)
    currency: str = Field(pattern="^[A-Z]{3}$")
    patient_id: str
    invoice_id: str
    payment_method_token: str | None = None


# Defines the message request model, contract, or value object.
class MessageRequest(BaseModel):
    idempotency_key: str
    channel: Literal["email", "sms"]
    destination: str
    subject: str
    body: str


# Defines the signature request model, contract, or value object.
class SignatureRequest(BaseModel):
    idempotency_key: str
    document_id: str
    document_digest: str
    signer_name: str
    signer_email: str


# Defines the signature result model, contract, or value object.
class SignatureResult(BaseModel):
    reference: str
    status: Literal["requested", "completed", "simulated", "failed"]
    sandbox: bool
    certificate: dict = Field(default_factory=dict)


# Defines the payment result model, contract, or value object.
@dataclass(frozen=True)
class PaymentResult:
    reference: str
    amount_cents: int
    sandbox: bool = True
    status: str = "captured"


# Defines the eligibility request model, contract, or value object.
class EligibilityRequest(BaseModel):
    coverage_pct: int = Field(ge=0, le=100)
    maximum_cents: int = Field(ge=0)
    used_cents: int = Field(ge=0)
    waiting: bool = False


# Defines the claim request model, contract, or value object.
class ClaimRequest(BaseModel):
    idempotency_key: str
    amount_cents: int = Field(ge=0)
    payer_order: int = Field(ge=1, le=2)
    context: dict = Field(default_factory=dict)


# Defines the remittance request model, contract, or value object.
class RemittanceRequest(BaseModel):
    reference: str
    amount_cents: int = Field(ge=0)
    coverage_pct: int = Field(ge=0, le=100)
    remaining_cents: int = Field(ge=0)
    waiting: bool = False


# Defines the payment gateway model, contract, or value object.
@runtime_checkable
class PaymentGateway(Protocol):
    # Handle capture for this module.
    async def capture(self, request: PaymentRequest) -> PaymentResult: ...
    # Handle refund for this module.
    async def refund(
        self, payment_reference: str, amount_cents: int, idempotency_key: str
    ) -> PaymentResult: ...


# Defines the claims network model, contract, or value object.
@runtime_checkable
class ClaimsNetwork(Protocol):
    # Validate or enforce check eligibility before the operation continues.
    async def check_eligibility(self, request: EligibilityRequest) -> dict: ...
    # Create or issue submit claim while applying existing validation and authorization.
    async def submit_claim(self, request: ClaimRequest) -> dict: ...
    # Retrieve get claim status for the current request or workflow.
    async def get_claim_status(self, reference: str, persisted_status: str) -> dict: ...
    # Handle reconcile remittance for this module.
    async def reconcile_remittance(self, request: RemittanceRequest) -> dict: ...


# Defines the signature provider model, contract, or value object.
@runtime_checkable
class SignatureProvider(Protocol):
    # Create or issue request signature while applying existing validation and authorization.
    async def request_signature(self, request: SignatureRequest) -> SignatureResult: ...
    # Retrieve get signature for the current request or workflow.
    async def get_signature(self, reference: str) -> SignatureResult: ...


# Defines the messaging provider model, contract, or value object.
@runtime_checkable
class MessagingProvider(Protocol):
    # Handle send for this module.
    async def send(self, request: MessageRequest) -> dict: ...


# Defines the geocoding provider model, contract, or value object.
@runtime_checkable
class GeocodingProvider(Protocol):
    # Handle search for this module.
    async def search(self, query: str, region: str, limit: int = 5) -> list[dict]: ...


# Defines the map provider model, contract, or value object.
@runtime_checkable
class MapProvider(Protocol):
    # Handle location links for this module.
    def location_links(
        self,
        latitude: float,
        longitude: float,
        address: str = "",
    ) -> dict[str, str]: ...


# Defines the accounting exporter model, contract, or value object.
@runtime_checkable
class AccountingExporter(Protocol):
    # Handle export for this module.
    async def export(self, records: list[dict], idempotency_key: str) -> dict: ...
