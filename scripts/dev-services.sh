#!/usr/bin/env bash
# Starts the backing services the backend test suite needs (PostgreSQL for
# RLS-dependent tests, Redis for EventBus tests) when you are running tests
# outside Docker Compose. Idempotent: safe to re-run.
set -euo pipefail

PG_USER="${POSTGRES_USER:-lunatic}"
PG_PASSWORD="${POSTGRES_PASSWORD:-dev-only-change-me}"
TEST_DB="${TEST_DB:-lunatic_siem_test}"

echo "==> PostgreSQL"
if ! pg_isready -q 2>/dev/null; then
    service postgresql start >/dev/null
    until pg_isready -q 2>/dev/null; do sleep 0.5; done
fi

su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'\"" | grep -q 1 || \
    su postgres -c "psql -q -c \"CREATE USER ${PG_USER} WITH PASSWORD '${PG_PASSWORD}' CREATEDB\""

su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${TEST_DB}'\"" | grep -q 1 || \
    su postgres -c "psql -q -c \"CREATE DATABASE ${TEST_DB} OWNER ${PG_USER}\""

su postgres -c "psql -q -d ${TEST_DB} -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto'"
echo "    ready (database: ${TEST_DB})"

echo "==> Redis"
redis-cli ping >/dev/null 2>&1 || redis-server --daemonize yes --port 6379
until redis-cli ping >/dev/null 2>&1; do sleep 0.5; done
echo "    ready"
