"""Compatibility facade for the CMS routes.

The authoring/preview and public booking implementations are grouped under
``app.cms.routes`` while this module preserves the historical import path.
"""

from .routes import router
from .routes.authoring import (
    ContentInput,
    cms,
    decode_preview_token,
    draft,
    draft_media,
    preview,
    preview_context,
    preview_media,
    preview_token,
    publication_preflight,
    publish,
    revisions,
    rollback_publication,
    save_draft,
    update_cms,
    upload_media,
)
from .routes.public import (
    PublicBooking,
    availability,
    availability_by_slug,
    booking_by_slug,
    booking_context,
    public_booking,
    public_organization,
    published_media,
    storefront,
    storefront_by_slug,
    storefront_data,
)

# Keep generated OpenAPI component names stable for existing clients.
for _model in (ContentInput, PublicBooking):
    _model.__module__ = __name__
    _model.model_rebuild(force=True)

__all__ = [
    "router",
    "ContentInput",
    "PublicBooking",
    "cms",
    "update_cms",
    "revisions",
    "draft",
    "save_draft",
    "upload_media",
    "draft_media",
    "publication_preflight",
    "preview_token",
    "publish",
    "rollback_publication",
    "decode_preview_token",
    "preview_context",
    "preview",
    "preview_media",
    "public_organization",
    "storefront",
    "storefront_data",
    "availability",
    "public_booking",
    "storefront_by_slug",
    "published_media",
    "booking_context",
    "availability_by_slug",
    "booking_by_slug",
]
