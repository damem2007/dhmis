import argparse
import asyncio
import json
import traceback

from app.core.config import settings
from app.core.database import control_session, dispose_engines
from app.organizations.models import Organization
from app.organizations.provisioning import (
    activate,
    migrate_all,
    migrate_schema,
    provision,
    reset_development_schemas,
)
from app.organizations.seed import DEMO_ORG_ID, seed_demo_data, seed_system_configuration


# Run the main entry point for this module.
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "bootstrap",
            "migrate",
            "reset-development",
            "demo-seed",
            "dispatch",
            "key-health",
            "rotate-tenant-keys",
            "migrate-encryption",
            "recovery-test",
        ],
    )
    parser.add_argument("--organization-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rewrap-only", action="store_true")
    parser.add_argument("--no-reencrypt", action="store_true")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--restore-dsn", default=None, help="Read-only restored database URL for recovery verification")
    args = parser.parse_args()
    try:
        if args.command == "bootstrap":
            if settings().environment != "development":
                raise RuntimeError("Development bootstrap requires development mode")
            await migrate_schema("dhmis_control")
            org = await provision("DHMIS Demonstration", DEMO_ORG_ID)
            result = await seed_system_configuration(org)
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
            result = await seed_system_configuration(org)
            await activate(org.id)
            print(json.dumps({"dropped_schemas": len(dropped), "bootstrap": result}))
        elif args.command == "demo-seed":
            if settings().environment != "development":
                raise RuntimeError("Demo data seeding is disabled outside development")
            async with control_session() as db:
                org = await db.get(Organization, DEMO_ORG_ID)
            if org is None:
                raise RuntimeError("The canonical demonstration organization is not provisioned")
            result = await seed_demo_data(org)
            print(json.dumps(result))
        elif args.command == "key-health":
            from app.core.key_management import health

            result = health()
            print(json.dumps(result))
            if not result.get("ready"):
                raise SystemExit(1)
        elif args.command == "rotate-tenant-keys":
            from app.core.key_management import rotate_tenant_keys

            print(
                json.dumps(
                    {
                        "rotated": await rotate_tenant_keys(
                            reencrypt=not args.no_reencrypt,
                            rewrap_only=args.rewrap_only,
                            organization_id=args.organization_id,
                            dry_run=args.dry_run,
                            batch_size=args.batch_size,
                        )
                    }
                )
            )
        elif args.command == "migrate-encryption":
            from app.core.key_management import migrate_tenant_encryption

            print(
                json.dumps(
                    {
                        "migrated": await migrate_tenant_encryption(
                            organization_id=args.organization_id,
                            dry_run=args.dry_run,
                            batch_size=args.batch_size,
                        )
                    }
                )
            )
        elif args.command == "recovery-test":
            from app.core.key_management import run_recovery_test, run_restore_test

            if args.restore_dsn:
                print(json.dumps({"results": await run_restore_test(args.restore_dsn)}))
            else:
                print(json.dumps({"results": await run_recovery_test()}))
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
        print(json.dumps({"success": False, "error_type": type(error).__name__, "verbose-error": str(error), "trackback": traceback.format_exc()}))
        # print(json.dumps({"success": False, "error_type": type(error).__name__}))
        raise SystemExit(1) from None
    finally:
        await dispose_engines()


if __name__ == "__main__":
    asyncio.run(main())
