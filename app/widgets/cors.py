"""Origin-aware CORS for the public appointment widget.

The normal application CORS list is intentionally restricted to DHMIS apps.
Widget requests come from tenant-owned websites, so their origins are checked
against the tenant's verified origin records before CORS headers are emitted.
"""

from starlette.datastructures import Headers, MutableHeaders, URL
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.database import organization_session
from app.organizations.tenant_resolution import resolve_organization
from app.organizations.configuration import tenant_settings
from app.widgets.router import _verified_origins


class AppointmentWidgetCORSMiddleware:
    """Emit CORS headers only for verified tenant widget origins."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope["path"].startswith("/v1/widgets/appointments"):
            await self.app(scope, receive, send)
            return

        request_headers = Headers(scope=scope)
        origin = request_headers.get("origin")
        if not origin:
            await self.app(scope, receive, send)
            return

        query = URL(scope=scope).query_params
        organization_id = query.get("organization_id")
        allowed = False
        parent_origin = query.get("parent_origin", "")
        if organization_id:
            try:
                resolution = await resolve_organization(organization_id=organization_id, surface="booking")
                async with organization_session(resolution.organization) as db:
                    config = (await tenant_settings(db)).booking_widget or {}
                verified = _verified_origins(config)
                allowed = origin in verified or parent_origin in verified
            except Exception:
                allowed = False

        if scope["method"] == "OPTIONS":
            if not allowed:
                await self.app(scope, receive, send)
                return
            response_headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": request_headers.get(
                    "access-control-request-headers", "Content-Type"
                ),
                "Access-Control-Max-Age": "600",
                "Vary": "Origin",
            }
            await send({
                "type": "http.response.start",
                "status": 204,
                "headers": [(key.lower().encode(), value.encode()) for key, value in response_headers.items()],
            })
            await send({"type": "http.response.body", "body": b""})
            return

        async def send_with_cors(message: Message) -> None:
            if message["type"] == "http.response.start" and allowed:
                headers = MutableHeaders(scope=message)
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                headers["Access-Control-Allow-Headers"] = "Content-Type"
                headers.add_vary_header("Origin")
            await send(message)

        await self.app(scope, receive, send_with_cors)
