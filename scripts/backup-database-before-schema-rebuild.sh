#!/usr/bin/env bash
# Create a complete PostgreSQL backup before rebuilding a disposable database
# from the edited migration history. This script never changes the database.

set -euo pipefail

backup_url="${DHMIS_BACKUP_DATABASE_URL:-${DATABASE_URL:-}}"
backup_dir="${DHMIS_BACKUP_DIR:-./backups}"

if [[ -z "${backup_url}" ]]; then
  echo "Set DHMIS_BACKUP_DATABASE_URL (preferred) or DATABASE_URL before running this script." >&2
  exit 2
fi

if ! command -v pg_dump >/dev/null 2>&1; then
  echo "pg_dump is required. Install PostgreSQL client tools and retry." >&2
  exit 2
fi

# SQLAlchemy async URLs are valid application configuration but are not valid
# libpq URLs. Convert only the driver prefix; credentials are never printed.
backup_url="${backup_url/postgresql+asyncpg:\/\//postgresql:\/\/}"
mkdir -p "${backup_dir}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_file="${backup_dir%/}/dhmis-before-uuid-history-rebuild-${timestamp}.dump"

pg_dump --format=custom --no-owner --no-acl --file="${backup_file}" "${backup_url}"
printf '%s\n' "Backup written: ${backup_file}"
printf '%s\n' "Verify it with: pg_restore --list \"${backup_file}\" >/dev/null"
