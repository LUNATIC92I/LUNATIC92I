#!/usr/bin/env bash
# One-time ops bootstrap for OpenSearch point-in-time recovery, same
# reasoning and same "run once by an operator, not by the application"
# posture as scripts/bootstrap_backup_role.sql for PostgreSQL
# (docs/BACKUP_RESTORE.md): registering a snapshot repository is a
# rare, credentialed, environment-specific action, not something a
# worker process should be doing on every startup.
#
# Requires the repository-s3 plugin, which the stock
# opensearchproject/opensearch image does NOT ship with by default
# (verified directly against a real instance — `_nodes/plugins` lists
# opensearch-index-management, opensearch-security, etc., but no
# repository-s3). Install it into your image before running this:
#   opensearch-plugin install repository-s3
# (either baked into a custom image, or via an init container that
# writes into a shared plugins volume before the main container starts —
# kubernetes/data-tier/values-opensearch-ha.yaml documents this).
#
# Usage:
#   OPENSEARCH_URL=https://opensearch-cluster-master.lunatic-data.svc.cluster.local:9200 \
#   OPENSEARCH_PASSWORD=... \
#   S3_BUCKET=lunatic-siem-opensearch-snapshots \
#   S3_BASE_PATH=lunatic-siem \
#   S3_REGION=us-east-1 \
#   bash scripts/bootstrap_opensearch_snapshots.sh
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:?set OPENSEARCH_URL}"
OPENSEARCH_USERNAME="${OPENSEARCH_USERNAME:-admin}"
OPENSEARCH_PASSWORD="${OPENSEARCH_PASSWORD:?set OPENSEARCH_PASSWORD}"
S3_BUCKET="${S3_BUCKET:?set S3_BUCKET}"
S3_BASE_PATH="${S3_BASE_PATH:-lunatic-siem}"
S3_REGION="${S3_REGION:?set S3_REGION}"

auth=(-sk -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}")

echo "==> Registering S3 snapshot repository"
curl "${auth[@]}" -X PUT "${OPENSEARCH_URL}/_snapshot/lunatic_backups" \
    -H 'Content-Type: application/json' \
    -d "{
      \"type\": \"s3\",
      \"settings\": {
        \"bucket\": \"${S3_BUCKET}\",
        \"base_path\": \"${S3_BASE_PATH}\",
        \"region\": \"${S3_REGION}\"
      }
    }"
echo

echo "==> Verifying repository"
curl "${auth[@]}" -X POST "${OPENSEARCH_URL}/_snapshot/lunatic_backups/_verify"
echo

# Daily automated snapshots via OpenSearch's own Snapshot Management
# (part of the index-management plugin, already present in the stock
# image — no extra plugin needed for this half). Retention deletes
# snapshots older than 30 days, matching the PostgreSQL retention policy
# in kubernetes/data-tier/postgres-cluster.yaml.
echo "==> Creating the daily snapshot management policy"
curl "${auth[@]}" -X POST "${OPENSEARCH_URL}/_plugins/_sm/policies/lunatic-daily-snapshots" \
    -H 'Content-Type: application/json' \
    -d '{
      "description": "Daily snapshot of every lunatic-* index, 30-day retention",
      "creation": {
        "schedule": {"cron": {"expression": "0 3 * * *", "timezone": "UTC"}},
        "time_limit": "1h"
      },
      "deletion": {
        "schedule": {"cron": {"expression": "0 4 * * *", "timezone": "UTC"}},
        "condition": {"max_age": "30d"},
        "time_limit": "1h"
      },
      "snapshot_config": {
        "indices": "lunatic-*",
        "repository": "lunatic_backups",
        "ignore_unavailable": true,
        "include_global_state": false
      }
    }'
echo

echo "==> Done. Restore procedure: docs/BACKUP_RESTORE.md"
