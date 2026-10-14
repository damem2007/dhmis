"""Route composition for the patient identity surface."""

from fastapi import APIRouter

from . import authentication, invites, sessions

router = APIRouter(prefix="/portal", tags=["Patient identity"])
router.include_router(invites.router)
router.include_router(authentication.router)
router.include_router(sessions.router)

__all__ = ["router"]
