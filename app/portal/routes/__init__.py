"""Route composition for the patient portal surface."""

from fastapi import APIRouter

from . import care, core, forms, messaging

router = APIRouter(prefix="/portal", tags=["Patient portal"])
router.include_router(core.router)
router.include_router(care.router)
router.include_router(forms.router)
router.include_router(messaging.router)

__all__ = ["router"]
