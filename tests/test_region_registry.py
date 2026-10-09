import pytest
from uuid import uuid4

from app.core.config import settings
from app.organizations.provisioning import provision


@pytest.mark.asyncio
async def test_region_registry_seeds_ca_us_and_blocks_disabled_onboarding(client, tenants):
    headers = {"X-Bootstrap-Key": settings().bootstrap_key.get_secret_value()}
    listed = await client.get("/v1/platform/regions", headers=headers)
    assert listed.status_code == 200, listed.text
    regions = {item["code"]: item for item in listed.json()}
    assert set(regions) == {"CA", "US"}
    assert all(item["enabled"] for item in regions.values())

    disabled = await client.put(
        "/v1/platform/regions/US/status",
        headers=headers,
        json={"enabled": False, "reason": "Pause new United States assignments"},
    )
    assert disabled.status_code == 200, disabled.text
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as error:
        await provision(f"Disabled region test {uuid4().hex[:8]}", region="US")
    assert error.value.status_code == 409
    restored = await client.put(
        "/v1/platform/regions/US/status",
        headers=headers,
        json={"enabled": True, "reason": "Restore United States assignments"},
    )
    assert restored.status_code == 200, restored.text
