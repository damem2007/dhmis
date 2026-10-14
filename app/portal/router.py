"""Compatibility facade for the patient portal routes."""

from .routes import router
from .routes.care import (
    PortalPayment,
    PortalPlan,
    appointments,
    cancel_appointment,
    create_appointment,
    create_plan,
    invoices,
    pay_invoice,
    reschedule_appointment,
    statement,
)
from .routes.core import notifications, portal_context, profiles, recent_activity
from .routes.forms import FormResponse, consents, forms, sign_consent, submit_form
from .routes.messaging import NewThread, Reply, create_thread, reply, thread, thread_page, threads

for _model in (PortalPayment, PortalPlan, FormResponse, NewThread, Reply):
    _model.__module__ = __name__
    _model.model_rebuild(force=True)

__all__ = [
    "router",
    "PortalPayment",
    "PortalPlan",
    "FormResponse",
    "NewThread",
    "Reply",
    "portal_context",
    "recent_activity",
    "notifications",
    "profiles",
    "appointments",
    "create_appointment",
    "reschedule_appointment",
    "cancel_appointment",
    "invoices",
    "pay_invoice",
    "create_plan",
    "statement",
    "forms",
    "submit_form",
    "consents",
    "sign_consent",
    "threads",
    "thread_page",
    "create_thread",
    "thread",
    "reply",
]
