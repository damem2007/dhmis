import argparse
import asyncio
import json

from app.core.config import settings
from app.core.database import dispose_engines
from app.organizations.provisioning import (
    activate,
    migrate_all,
    migrate_schema,
    provision,
    reset_development_schemas,
)
from app.organizations.seed import DEMO_ORG_ID, seed


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=["bootstrap", "migrate", "reset-development", "dispatch"]
    )
    args = parser.parse_args()
    try:
        if args.command == "bootstrap":
            if settings().environment != "development":
                raise RuntimeError("Demo bootstrap requires development mode")
            await migrate_schema("dhmis_control")
            org = await provision("DHMIS Demonstration", DEMO_ORG_ID)
            result = await seed(org)
            await activate(org.id)
            print(json.dumps(result))
        elif args.command == "migrate":
            results = await migrate_all()
            print(json.dumps(results))
            if any(not result["migrated"] for result in results):
                raise SystemExit(1)
        elif args.command == "reset-development":
            dropped = await reset_development_schemas()
            await migrate_schema("dhmis_control")
            await migrate_schema("dhmis_template")
            org = await provision("DHMIS Demonstration", DEMO_ORG_ID, slug="dhmis-demo")
            result = await seed(org)
            await activate(org.id)
            print(json.dumps({"dropped_schemas": len(dropped), "bootstrap": result}))
        else:
            from app.notifications.worker import tick
            from app.platform_identity.delivery import platform_tick

            print(
                json.dumps(
                    {
                        "control_plane": await platform_tick({}),
                        "tenants": await tick({}),
                    }
                )
            )
    except Exception as error:
        # Operational output must never leak credentials or patient data.
       # print(json.dumps({"success": False, "error_type": type(error).__name__, "verbose-error": type(error)}))
        print(json.dumps({"success": False, "error_type": type(error).__name__}))
        raise SystemExit(1) from None
    finally:
        await dispose_engines()


if __name__ == "__main__":
    asyncio.run(main())
