"""Route composition for the CMS surface."""

from fastapi import APIRouter

from . import authoring, public

router = APIRouter(tags=["Front Office CMS"])
router.include_router(authoring.router)
router.include_router(public.router)

__all__ = ["router"]
