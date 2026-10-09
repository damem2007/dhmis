import re
from uuid import uuid4

from sqlalchemy import delete, select

from app.core.config import settings
from app.core.database import control_session
from app.identity.passwords import verify_password
from app.platform_identity.delivery import platform_tick
from app.platform_identity.models import (
    PlatformInvite,
    PlatformOutboxMessage,
    PlatformPasswordResetChallenge,
    PlatformUser,
)


async def test_platform_invitation_and_password_reset_delivery(client):
    marker = uuid4().hex[:12]
    email = f"platform-delivery-{marker}@example.test"
    headers = {"X-Bootstrap-Key": settings().bootstrap_key.get_secret_value()}
    invite_id = user_id = reset_id = None
    try:
        response = await client.post(
            "/v1/platform/invites",
            headers=headers,
            json={"name": "Platform Delivery Verification", "email": email},
        )
        assert response.status_code == 201, response.text
        assert "token" not in response.json()
        invite_id = response.json()["invite_id"]

        await platform_tick({})
        jobs = await client.get("/v1/platform/jobs", headers=headers)
        assert jobs.status_code == 200, jobs.text
        assert jobs.json()["control_plane_queue"]["name"] == "platform notification outbox"
        async with control_session() as db:
            invitation_message = await db.scalar(
                select(PlatformOutboxMessage).where(
                    PlatformOutboxMessage.id == response.json()["delivery_id"]
                )
            )
            assert invitation_message.status in {"simulated", "sent", "delivered", "accepted"}
            match = re.search(r"[?&]invite=([^\s]+)", invitation_message.payload["body"])
            assert match
            invitation_token = match.group(1)

        response = await client.post(
            "/v1/platform/auth/invites/accept",
            json={"token": invitation_token, "password": "Delivery-verification-2026!"},
        )
        assert response.status_code == 201, response.text
        async with control_session() as db:
            user = await db.scalar(select(PlatformUser).where(PlatformUser.email == email))
            assert user is not None
            user_id = user.id

        response = await client.post(
            f"/v1/platform/users/{user_id}/password-reset",
            headers=headers,
            json={"reason": "Focused control-plane delivery verification"},
        )
        assert response.status_code == 201, response.text
        assert "token" not in response.json()
        reset_id = response.json()["delivery_id"]

        await platform_tick({})
        async with control_session() as db:
            reset_message = await db.get(PlatformOutboxMessage, reset_id)
            assert reset_message.status in {"simulated", "sent", "delivered", "accepted"}
            match = re.search(r"[?&]reset=([^\s]+)", reset_message.payload["body"])
            assert match
            reset_token = match.group(1)

        response = await client.post(
            "/v1/platform/auth/password-reset/complete",
            json={"token": reset_token, "password": "Updated-delivery-verification-2026!"},
        )
        assert response.status_code == 200, response.text
        async with control_session() as db:
            user = await db.get(PlatformUser, user_id)
            assert verify_password("Updated-delivery-verification-2026!", user.password_hash)
    finally:
        async with control_session() as db:
            if user_id:
                await db.execute(
                    delete(PlatformPasswordResetChallenge).where(
                        PlatformPasswordResetChallenge.user_id == user_id
                    )
                )
                await db.execute(delete(PlatformUser).where(PlatformUser.id == user_id))
            if invite_id:
                await db.execute(delete(PlatformInvite).where(PlatformInvite.id == invite_id))
            await db.execute(
                delete(PlatformOutboxMessage).where(
                    PlatformOutboxMessage.payload["destination"].as_string() == email
                )
            )
