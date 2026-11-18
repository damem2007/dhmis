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

Set the database, JWT, bootstrap, demo-password, key-provider, Redis, and provider values in `.env` (the file is `Backend/.env` from the repository root). `KEY_PROVIDER=local` is for development and tests. Production must use the selected managed KMS/HSM adapter and must not rely on a single process-local vault secret.

### Key-management implementation status

The repository contains the application-side key-management and migration
boundary. Production still requires provider-specific operational approval,
but the application workflows below are implemented:

| Capability | Current state |
| --- | --- |
| Provider contract | `KeyProvider` defines health, wrap and unwrap operations. |
| Local provider | AES-GCM wrapping provider using `VAULT_KEY`, for local development and tests only. |
| Versioned envelopes | New protected values use the `dhmis-v2` envelope; malformed envelopes fail closed. |
| Tenant DEKs | `organization_keys` stores a wrapped DEK and non-secret recovery metadata per Organization. Provisioning creates a key for new Organizations. |
| Legacy compatibility | Existing `VAULT_KEY` ciphertext is dual-read while migration is in progress. New writes use the versioned path. |
| Rotation | `rotate-tenant-keys` supports DEK rotation, provider-only re-wrapping, and tenant-scoped ciphertext re-encryption. Retired wrapped keys remain in the control plane for the approved retention window. |
| Readiness and maintenance | `/health` reports key-provider readiness; protected routes return a structured 503 when encryption readiness is unavailable. |
| Recovery verification | `recovery-test` validates live provider unwrap; `recovery-test --restore-dsn <read-only-restore>` verifies wrapped keys from an isolated restored database without writing to it. |

The four managed provider adapters are now available behind optional SDKs:

| `KEY_PROVIDER` | Adapter | Required configuration/credential source |
| --- | --- | --- |
| `aws-kms` (or `aws`) | AWS KMS | `AWS_KMS_KEY_ID`, `AWS_KMS_REGION`, and the boto3 default credential chain. |
| `gcp-kms` (or `gcp`) | Google Cloud KMS | `GCP_KMS_KEY_NAME` and Google Application Default Credentials. |
| `azure-key-vault` (or `azure`) | Azure Key Vault | `AZURE_KEY_VAULT_KEY_URL` and `DefaultAzureCredential`. |
| `vault-transit` (or `vault`) | HashiCorp Vault Transit | `VAULT_TRANSIT_ADDR`, `VAULT_TRANSIT_MOUNT`, `VAULT_TRANSIT_KEY`, `VAULT_TRANSIT_TOKEN`, and optional namespace. |

Install the provider SDKs from `requirements.kms.txt` in the deployment image,
or install only the selected SDK. Provider credentials are intentionally not
stored in this repository. The adapters use the platform SDK credential
chains, so deployment only needs to supply the selected key reference and
secret/identity configuration.

The remaining production gates are provider-specific IAM and region policy,
backup ownership and restore scheduling, deletion/retention enforcement, and
an approved dual-read retirement plan. The application migration and restore
verification commands are available but must be rehearsed in staging.

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

### Historical UUID migration replay (development only)

The migration history now creates UUID primary keys for the seeded platform
catalogue/configuration records and tenant configuration/governance records.
Human-readable values remain in business columns: plan `code`, feature `key`,
and governance-rule `key`. They are not database primary keys.

Before replaying this edited history, create a complete PostgreSQL backup. The
script is read-only and does not print connection credentials:

```bash
cd Backend
DHMIS_BACKUP_DATABASE_URL="$DATABASE_URL" \
  bash scripts/backup-database-before-schema-rebuild.sh
```

Validate the generated dump before any destructive development reset:

```bash
pg_restore --list backups/dhmis-before-uuid-history-rebuild-*.dump >/dev/null
.venv/bin/python -m app.cli reset-development
```

Do **not** replay edited historical migrations against a database that has
already recorded the old migration versions. Alembic will not revisit those
versions, and changing an applied primary-key type requires a reviewed forward
data migration. The no-new-migration approach is therefore limited to a clean
development database (or a new database restored from verified source data).
Staging and production must retain the backup and use an approved forward
migration/change window before their existing varchar primary keys can change.

Load the excluded demonstration records explicitly, after `bootstrap` or `reset-development`:

```bash
.venv/bin/python -m app.cli demo-seed
```

`demo-seed` is development-only and restricted to the canonical demonstration organization. It is the only CLI command that creates demo users, locations, patients, appointments, invoices, ledger entries, chart entries, consents, demo providers, and demo operational records. Existing patient-data encryption is never part of this seed.

Run one notification and platform-delivery dispatcher pass:

```bash
.venv/bin/python -m app.cli dispatch
```

Inspect encryption-provider readiness without printing key material:

```bash
.venv/bin/python -m app.cli key-health
```

Rotate tenant DEKs and re-encrypt all encrypted patient, identity, outbox and
secure-messaging values for each tenant during a reviewed maintenance window:

```bash
.venv/bin/python -m app.cli rotate-tenant-keys
```

Use `--organization-id` for one tenant, `--batch-size` to bound each read,
`--dry-run` to count rows without writing, `--no-reencrypt` to rotate only the
wrapped key row, or `--rewrap-only` to preserve the DEK and change only its
provider envelope.
Legacy `VAULT_KEY` values are read during this migration and are replaced by
the active tenant-DEK envelope when the command completes.

To run the idempotent migration/backfill without rotating keys:

```bash
.venv/bin/python -m app.cli migrate-encryption --batch-size 500
```

Run the provider and tenant-key recovery probe:

```bash
.venv/bin/python -m app.cli recovery-test
```

After restoring a staging backup into an isolated database, verify its
control-plane wrapped keys without modifying the restore target:

```bash
.venv/bin/python -m app.cli recovery-test --restore-dsn "$RESTORED_DATABASE_URL"
```

### Staging checklist

Staging is a compatibility and migration rehearsal environment. Use a
staging-only KMS/Vault key and identity when validating the selected managed
adapter; never copy a production key or token into staging. If the provider
integration is not under test, `KEY_PROVIDER=local` remains acceptable for a
disposable staging run. This exercises the envelope, tenant-key, dual-read and
maintenance contracts without making a local wrapping secret look like
production key custody.

Before opening staging traffic:

1. Apply the schema chain with `.venv/bin/python -m app.cli migrate` and confirm
   that the current head—including `0060_tenant_key_management`,
   `0061_provider_key_version`, `0062_plan_visibility_addons`,
   `0063_commercial_domains`, and
   `0064_disable_legacy_optional_plan_features`—is applied for the control
   plane, template, and every onboarded tenant.
2. Run `.venv/bin/python -m app.cli key-health` and verify that the provider is
   `local`, `ready` is `true`, and no key material is printed.
3. Provision a disposable test Organization and confirm that its
   `organization_keys` record contains a wrapped key, an active status and only
   non-secret recovery metadata.
4. Exercise a legacy `VAULT_KEY` ciphertext fixture and a `dhmis-v2` value in
   the same test cycle. The versioned value must be preferred, and the legacy
   value must remain readable only through the compatibility path.
5. Run `.venv/bin/python -m app.cli migrate-encryption --dry-run`, review the
   per-tenant counts, then run it without `--dry-run` and verify that legacy
   patient and messaging ciphertext is replaced by tenant envelopes.
6. Run `.venv/bin/python -m app.cli rotate-tenant-keys --dry-run`, approve the
   change, then run the rotation and inspect the active/retired key rows.
7. Restore a staging database backup into an isolated staging database and run
   `recovery-test --restore-dsn` to verify the restored wrapped-key records and
   tenant-key probes.
7. Check `/health` during each step. A failed provider check must report
   `status: maintenance` and protected application routes must fail closed with
   HTTP 503 rather than serving encrypted data without a usable key.

### Production readiness and deployment checklist

Do not deploy the current `KEY_PROVIDER=local` path to production. Production
activation is blocked until the following decisions and implementation work are
approved and evidenced:

1. **Managed provider:** select one of the implemented KMS/HSM adapters, install
   its optional SDK, and configure it. The adapter must support health, wrap
   and unwrap without returning master-key material to the application.
2. **Region and jurisdiction:** document the KMS key region, encrypted-backup
   regions, Canada-first residency requirements and any permitted
   cross-border recovery path.
3. **Service identity:** create a dedicated backend service identity with
   least-privilege wrap/unwrap access. Separate deployment, rotation,
   recovery and key-administration permissions, and record emergency access.
4. **Deletion and retention:** enable KMS deletion protection, define scheduled
   deletion controls, retain old key versions for the migration and rollback
   window, and publish the retention/legal-hold policy.
5. **Backup and recovery ownership:** assign the operational owner and
   approver for encrypted backups, wrapped-key records, restore tests and
   incident recovery. Record a successful restore test before go-live.
6. **Migration timing:** approve a change window for existing patient and
   messaging ciphertext. Inventory legacy rows, create or verify a DEK for
   every Organization, backfill/re-encrypt in resumable batches, verify counts
   and decryptability, retain the dual-read path through the rollback period,
   and only then plan legacy-key retirement.

The deployment sequence should be:

```text
backup and restore rehearsal
        ↓
managed-provider health check (no application traffic yet)
        ↓
control-plane/template/tenant migration via app.cli migrate
        ↓
all-tenant DEK backfill and legacy ciphertext migration
        ↓
verification, audit review and recovery test
        ↓
enable application traffic
        ↓
scheduled rotation and eventual legacy compatibility retirement
```

Run the operational commands only inside an approved change window:

```bash
.venv/bin/python -m app.cli key-health
.venv/bin/python -m app.cli migrate
.venv/bin/python -m app.cli migrate-encryption
.venv/bin/python -m app.cli rotate-tenant-keys
.venv/bin/python -m app.cli recovery-test
```

### Commercial plans and tenant-routing release checks

Before enabling the domain-routing and commercial-plan release in staging or
production:

1. Run `.venv/bin/python -m app.cli migrate`; do not apply individual
   migrations directly. `0063` adds structured domain requests, hosts,
   verification state, activation history, priced add-on products, and
   immutable refund links. `0064` disables only migration-created optional
   legacy plan features so every legacy plan is Back Office-only until a plan
   operator authors a validated bundle. The edited `0063` domain-host
   constraint includes the managed Back Office fallback role for a clean
   migration replay; an existing deployed database needs a reviewed forward
   migration before that stored role can be added.
2. In **Billing → Plans**, validate each plan before it can be assigned or
   published. Public self-onboarding accepts only an active, validated plan
   with public availability enabled. Private curated plans remain assignable
   by Platform Admin but are not returned by the public plan endpoint.
3. Configure Appointment Widget pricing as a named add-on product. A tenant
   add-on purchase uses its configured price and external-origin allowance;
   it produces its own append-only SaaS ledger entry. Refunds append negative
   reversal entries and never mutate historic charges.
4. Install the one-time edge routes for public custom hosts and derived
   `admin.<customer-domain>` Back Office hosts. The proxy must preserve
   `Host` and forward `/v1/` to FastAPI. See
   [`docs/custom-domain-routing-proposal.md`](../docs/custom-domain-routing-proposal.md)
   for the generic proxy pattern. Do not add a server block for each tenant.
5. Exercise managed, pending-custom, active-custom, Back Office-only,
   Portal-plus-Widget, and Widget-only cases in staging. A custom request is
   tenant-owned: Platform Admin can monitor, resend the tenant-administrator
   notification, cancel, or suspend it, but cannot prove ownership.

The backend validates manual DNS TXT and HTTPS-file proofs. It also exposes a
`domain_dns_provider` integration contract and a tenant-controlled automatic
TXT-record setup endpoint. DHMIS intentionally includes no guessed DNS vendor
or customer-zone credential flow. Automatic setup is visible only after a
reviewed provider plugin is installed, selected in **Settings → Integrations**,
and authorised for the customer's zone. Provider setup never activates a
domain by itself: the tenant must still run the independent verification check
and wait for DNS/TLS propagation.

### Database-backed integration tests

The full pytest suite provisions schemas and tenant fixtures, so it must not
target a shared staging or production `DATABASE_URL`. Run it through the
isolated local PostgreSQL harness:

```bash
cd Backend
./scripts/run-integration-tests.sh
```

The script starts `docker-compose.integration.yml`, accepts only a loopback
`DHMIS_TEST_DATABASE_URL`, runs pytest with that URL as the child process's
`DATABASE_URL`, and tears down the disposable volume afterward. Docker is
needed only for the default disposable database; an already-running loopback
test database may be supplied through `DHMIS_TEST_DATABASE_URL`.

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
