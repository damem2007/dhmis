#!/usr/bin/env bash
set -euo pipefail

# Database-backed tests create schemas and tenant fixtures. They must never
# run against the application's normal DATABASE_URL. This script starts an
# isolated disposable PostgreSQL service and overrides DATABASE_URL only for
# the pytest child process.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
backend_dir="$(cd "${script_dir}/.." && pwd)"
compose_file="${backend_dir}/docker-compose.integration.yml"
provided_test_dsn="${DHMIS_TEST_DATABASE_URL:-}"
test_dsn="${provided_test_dsn:-postgresql://dhmis_integration:dhmis_integration@127.0.0.1:54329/dhmis_integration}"

case "${test_dsn}" in
  *"@127.0.0.1:"*|*"@localhost:"*) ;;
  *)
    echo "Refusing to run integration tests against a non-local database. Set DHMIS_TEST_DATABASE_URL to a loopback PostgreSQL database." >&2
    exit 2
    ;;
esac

if [ -z "${provided_test_dsn}" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required for the default isolated integration-test database. Install Docker Desktop or set DHMIS_TEST_DATABASE_URL to an existing loopback PostgreSQL database." >&2
    exit 2
  fi
  docker compose -f "${compose_file}" up -d --wait
  trap 'docker compose -f "${compose_file}" down --volumes --remove-orphans' EXIT
fi

cd "${backend_dir}"
DATABASE_URL="${test_dsn}" .venv/bin/pytest -q "$@"
