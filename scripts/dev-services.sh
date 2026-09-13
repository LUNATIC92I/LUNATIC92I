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

# OpenSearch is optional: only the app/tests/test_opensearch.py suite needs
# it, and it is far heavier than Postgres/Redis. Set OPENSEARCH_HOME to a
# local install to have this script manage it too.
OPENSEARCH_HOME="${OPENSEARCH_HOME:-/opt/os}"
OPENSEARCH_PASSWORD="${OPENSEARCH_INITIAL_ADMIN_PASSWORD:-LunaticDev-Test-1!}"
if [ -x "${OPENSEARCH_HOME}/bin/opensearch" ]; then
    echo "==> OpenSearch"
    if ! curl -sk -u "admin:${OPENSEARCH_PASSWORD}" https://localhost:9200 >/dev/null 2>&1; then
        su opensearch -c "unset JAVA_TOOL_OPTIONS; cd ${OPENSEARCH_HOME} && nohup ./bin/opensearch > /tmp/opensearch.log 2>&1 &"
        until curl -sk -u "admin:${OPENSEARCH_PASSWORD}" https://localhost:9200 >/dev/null 2>&1; do
            sleep 3
        done
    fi
    echo "    ready"
else
    echo "==> OpenSearch: not installed at ${OPENSEARCH_HOME}, skipping"
fi
