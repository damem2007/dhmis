from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.exc import IntegrityError

from app.analytics.router import router as analytics
from app.billing.operations import router as financial_operations
from app.billing.router import router as billing
from app.care_coordination.router import router as care_coordination
from app.claims.router import router as claims
from app.clinical.router import router as clinical
from app.cms.router import router as cms
from app.code_library.router import router as code_library
from app.consents.router import router as consents
from app.core import all_models, scope  # noqa: F401
from app.core.audit import request_context
from app.core.config import settings
from app.core.key_management import KeyManagementUnavailable
from app.core.key_management import health as key_health
from app.dashboard.router import router as dashboard
from app.documents.router import router as documents
from app.forms.router import router as forms
from app.identity.router import router as identity
from app.integrations.contracts import IntegrationFailure
from app.messaging.router import router as messaging
from app.notifications.router import router as notifications
from app.operations.router import router as operations
from app.organizations.admin import router as administration
from app.organizations.router import router as organizations
from app.organizations.tenant_router import router as tenant_resolution
from app.patient_identity.router import router as patient_identity
from app.patients.router import router as patients
from app.platform_identity.router import router as platform_identity
from app.portal.router import router as portal
from app.prescriptions.router import router as prescriptions
from app.rbac.router import router as rbac
from app.regions.router import router as regions
from app.reporting.router import router as reporting
from app.scheduling.router import router as scheduling
from app.surgery.router import router as surgery
from app.widgets.cors import AppointmentWidgetCORSMiddleware
from app.widgets.router import router as appointment_widget

app = FastAPI(
    title="DHMIS Core Platform",
    version="0.1.0",
    description="Development sandbox. No production clinical use.",
)

# The appointment widget is a standalone browser asset.  It is served by the
# API origin so a tenant can copy one stable script URL into any website,
# including a site that does not use tenant-web.
@app.get("/widgets/appointments.js", include_in_schema=False)
async def appointment_widget_script():
    return FileResponse(
        Path(__file__).resolve().parent / "widgets" / "assets" / "appointments.js",
        media_type="application/javascript",
    )

@app.get("/widgets/appointments-frame.html", include_in_schema=False)
async def appointment_widget_frame():
    """Serve the isolated appointment-widget frame loaded by the embed script."""
    return FileResponse(
        Path(__file__).resolve().parent / "widgets" / "assets" / "appointments-frame.html",
        media_type="text/html",
    )

app.add_middleware(AppointmentWidgetCORSMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings().cors_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-DHMIS-Tenant",
        "X-DHMIS-Location",
        "X-Bootstrap-Key",
    ],
)
for router in [
    analytics,
    administration,
    identity,
    organizations,
    tenant_resolution,
    patients,
    scheduling,
    clinical,
    billing,
    claims,
    code_library,
    consents,
    dashboard,
    patient_identity,
    platform_identity,
    portal,
    documents,
    forms,
    messaging,
    cms,
    prescriptions,
    care_coordination,
    surgery,
    operations,
    reporting,
    rbac,
    regions,
    appointment_widget,
]:
    app.include_router(router, prefix="/v1")
app.include_router(financial_operations, prefix="/v1")
app.include_router(notifications, prefix="/v1")


@app.on_event("startup")
async def initialize_key_management():
    """Record encryption readiness without preventing health diagnostics."""

    app.state.key_management = key_health()
    app.state.maintenance_mode = not app.state.key_management.get("ready", False)


# Handle integrity error for this module.
@app.exception_handler(IntegrityError)
async def integrity_error(request, error):
    return JSONResponse(
        status_code=409, content={"detail": "Record conflicts with an existing record or a data constraint"}
    )


# Handle health for this module.
@app.get("/health")
async def health():
    key_status = key_health()
    return {
        "status": "ok" if key_status.get("ready") else "maintenance",
        "environment": settings().environment,
        "production_ready": False,
        "key_management": key_status,
    }


@app.middleware("http")
async def encryption_maintenance_gate(request: Request, call_next):
    """Keep encrypted-data routes closed when key custody is unavailable."""

    if request.url.path != "/health":
        key_status = key_health()
        app.state.maintenance_mode = not key_status.get("ready", False)
        if app.state.maintenance_mode:
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "Encryption key management is in maintenance mode",
                    "code": "encryption_maintenance",
                    "maintenance": True,
                },
            )
    return await call_next(request)


# Create or issue request audit context while applying existing validation and authorization.
@app.middleware("http")
async def request_audit_context(request: Request, call_next):
    marker = request_context.set(
        {"ip": request.client.host if request.client else "unknown", "method": request.method}
    )
    try:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    finally:
        request_context.reset(marker)


# Handle integration failure for this module.
@app.exception_handler(IntegrationFailure)
async def integration_failure(request, error):
    return JSONResponse(status_code=502, content={"detail": str(error)})


@app.exception_handler(KeyManagementUnavailable)
async def key_management_failure(request, error):
    """Fail closed when encrypted data cannot be safely opened or written."""

    return JSONResponse(
        status_code=503,
        content={
            "detail": "Encrypted data is temporarily unavailable",
            "code": "encryption_unavailable",
            "maintenance": True,
        },
    )
