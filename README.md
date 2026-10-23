# DHMIS Backend

FastAPI control-plane and tenant services for DHMIS.

## Installation

Requirements: Python 3.12+, PostgreSQL, and Redis for queue-backed workers.

```bash
cd Backend
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.lock.txt
cp .env.example .env
```

Set the database, JWT, bootstrap, demo-password, vault, Redis, and provider values in `.env` (the file is `Backend/.env` from the repository root).

Use the application CLI for schema-aware migrations. It applies the control-plane migration chain, the tenant template chain, and the approved setup seed where appropriate. Running raw Alembic commands does not enumerate onboarded tenant schemas.

### Schema and seed commands

Run an upgrade across the control plane, template, and every existing onboarded tenant:

```bash
.venv/bin/python -m app.cli migrate
```

`migrate` is the deployment migration command for every subsequent migration release. Each run upgrades the control plane, tenant template, and every existing onboarded tenant schema to the current Alembic head. A tenant onboarded later receives the same migration chain during provisioning. If any tenant migration fails, the command reports the affected tenant and exits with status 1 so deployment can be stopped. It does not create organizations, users, patients, locations, appointments, invoices, ledger entries, chart entries, consents, or demo records. It does run existing data migrations, such as ledger-to-journal conversion, condition-treatment link conversion, and legacy patient encryption, for schemas that contain those records. It also applies the approved system-configuration seed idempotently.

The same operation is available to the Platform Super Admin through the protected API endpoint `POST /v1/platform/migrations/tenants`. It accepts the authenticated Platform Super Admin session or the configured bootstrap key and returns one result per onboarded tenant. The endpoint also migrates the control plane and tenant template before processing tenant schemas. It returns `207 Multi-Status` when one or more tenant migrations fail, while preserving the result for every tenant.

In development, create the canonical demonstration organization and apply setup configuration:

```bash
.venv/bin/python -m app.cli bootstrap
```

`bootstrap` is development-only. It provisions `d1100000-0000-4000-8000-000000000001` and applies platform and tenant setup configuration, but it does not create demo users or operational demo records.

To discard disposable development schemas and rebuild the canonical demonstration organization:

```bash
.venv/bin/python -m app.cli reset-development
```

`reset-development` is destructive and development-only. It drops `dhmis_control`, `dhmis_template`, and provisioned `dhmis_t_*` schemas, reapplies migrations, and recreates the demonstration organization with setup configuration only.

Load the excluded demonstration records explicitly, after `bootstrap` or `reset-development`:

```bash
.venv/bin/python -m app.cli demo-seed
```

`demo-seed` is development-only and restricted to the canonical demonstration organization. It is the only CLI command that creates demo users, locations, patients, appointments, invoices, ledger entries, chart entries, consents, demo providers, and demo operational records. Existing patient-data encryption is never part of this seed.

Run one notification and platform-delivery dispatcher pass:

```bash
.venv/bin/python -m app.cli dispatch
```

Start the API:

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Run the backend checks with `pytest`. Keep `.env`, `.venv/`, Python caches, and local test caches out of version control.

Address autocomplete and coordinate lookup use the registered `tomtom`
geocoding provider. Set `PROVIDER_OPTIONS.tomtom.api_key` in `.env` before
running migration `0024`. Migration `0025` configures the independent
`map_provider` capability. The storefront map and directions links consume
saved coordinates through the configured map provider and do not send patient
data to the geocoder. `openstreetmap` and `tomtom` are available map
providers; TomTom map rendering uses the same configured TomTom key as
geocoding. Geocoding and map rendering can therefore be changed independently
through the provider registry.
