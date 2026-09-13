"""Index templates, aliases and lifecycle policies (spec §4, Phase 0's
`docs/database/opensearch_indices.md`).

Applied idempotently at worker/API startup rather than by a human running
curl commands: an index created before its template exists gets a
guessed dynamic mapping, and once a field is mapped wrongly in OpenSearch it
cannot be changed without a reindex. Bootstrapping in code means a fresh
cluster is always correct on first write.

Two properties of the mapping below carry real weight:

- `dynamic: false` — an unexpected field is stored but not indexed, so a
  log source that suddenly emits 400 new keys cannot explode the cluster's
  field count. The cost is that fields must be declared; a test asserts the
  normalizer never emits an undeclared one.
- `ignore_above` on free-form keywords — one absurd value from a malformed
  event cannot blow up field-data memory.
"""

import logging
from typing import Any

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import ConflictError, NotFoundError, RequestError

from app.core.config import get_settings

logger = logging.getLogger(__name__)

INDEX_VERSION = "v1"

RAW_ALIAS = "events-raw-write"
NORMALIZED_ALIAS = "events-normalized-write"
DEADLETTER_ALIAS = "deadletter-write"

RAW_PATTERN = f"lunatic-events-raw-{INDEX_VERSION}-*"
NORMALIZED_PATTERN = f"lunatic-events-normalized-{INDEX_VERSION}-*"
DEADLETTER_PATTERN = f"lunatic-deadletter-{INDEX_VERSION}-*"

_KEYWORD = {"type": "keyword"}
_KEYWORD_LONG = {"type": "keyword", "ignore_above": 4096}


def normalized_mapping() -> dict[str, Any]:
    """Field-for-field the mapping documented in
    `docs/database/opensearch_indices.md` §3."""
    return {
        "dynamic": "false",
        "properties": {
            "event_id": _KEYWORD,
            "timestamp": {"type": "date"},
            "ingestion_timestamp": {"type": "date"},
            "tenant_id": _KEYWORD,
            "source": _KEYWORD,
            "source_type": _KEYWORD,
            "category": _KEYWORD,
            "class": _KEYWORD,
            "event_code": _KEYWORD,
            "severity": _KEYWORD,
            "activity": _KEYWORD,
            "actor": {
                "properties": {
                    "user": _KEYWORD,
                    "process": _KEYWORD,
                    "session_id": _KEYWORD,
                }
            },
            "user": {"properties": {"name": _KEYWORD, "domain": _KEYWORD, "uid": _KEYWORD}},
            "device": {
                "properties": {
                    "hostname": _KEYWORD,
                    "ip": {"type": "ip"},
                    "os": _KEYWORD,
                    "asset_id": _KEYWORD,
                }
            },
            "source_ip": {"type": "ip"},
            "destination_ip": {"type": "ip"},
            "source_port": {"type": "integer"},
            "destination_port": {"type": "integer"},
            "protocol": _KEYWORD,
            "hostname": _KEYWORD,
            "process": {
                "properties": {
                    "name": _KEYWORD,
                    "pid": {"type": "integer"},
                    "path": _KEYWORD,
                    "parent_name": _KEYWORD,
                    "cmd_line": _KEYWORD_LONG,
                }
            },
            "command_line": {"type": "text", "fields": {"raw": _KEYWORD_LONG}},
            "file": {
                "properties": {"name": _KEYWORD, "path": _KEYWORD, "size": {"type": "long"}}
            },
            "hash": {"properties": {"md5": _KEYWORD, "sha1": _KEYWORD, "sha256": _KEYWORD}},
            "domain": _KEYWORD,
            "url": _KEYWORD_LONG,
            "cloud": {
                "properties": {"provider": _KEYWORD, "account_id": _KEYWORD, "region": _KEYWORD}
            },
            "authentication": {
                "properties": {
                    "method": _KEYWORD,
                    "outcome": _KEYWORD,
                    "logon_type": _KEYWORD,
                    "mfa_used": {"type": "boolean"},
                }
            },
            "mitre_techniques": _KEYWORD,
            "ioc_matches": _KEYWORD,
            "risk_context": {
                "properties": {
                    "asset_criticality": _KEYWORD,
                    "user_risk_score": {"type": "float"},
                }
            },
            "geo": {
                "properties": {
                    "source_country": _KEYWORD,
                    "source_is_private": {"type": "boolean"},
                    "destination_is_private": {"type": "boolean"},
                }
            },
            "asset": {
                "properties": {
                    "id": _KEYWORD,
                    "criticality": _KEYWORD,
                    "environment": _KEYWORD,
                    "owner": _KEYWORD,
                }
            },
            "enrichment_partial": {"type": "boolean"},
            "enrichment_errors": _KEYWORD,
            "schema_version": _KEYWORD,
            # Stored and returned with the document, but not indexed
            # field-by-field: heterogeneous source payloads would otherwise
            # blow the field limit. Specific fields worth querying are
            # promoted to the typed fields above by the normalizer.
            "raw_event": {"type": "object", "enabled": False},
            "normalized_event": {"type": "object", "enabled": False},
        },
    }


def _raw_mapping() -> dict[str, Any]:
    return {
        "dynamic": "false",
        "properties": {
            "event_id": _KEYWORD,
            "tenant_id": _KEYWORD,
            "collector_id": _KEYWORD,
            "source_type": _KEYWORD,
            "received_at": {"type": "date"},
            "content_hash": _KEYWORD,
            "raw_payload": {"type": "object", "enabled": False},
        },
    }


def _deadletter_mapping() -> dict[str, Any]:
    return {
        "dynamic": "false",
        "properties": {
            "tenant_id": _KEYWORD,
            "stage": _KEYWORD,
            "failure_reason": {"type": "text"},
            "failed_at": {"type": "date"},
            "raw_payload": {"type": "object", "enabled": False},
        },
    }


def _template_body(
    *, pattern: str, alias: str, mapping: dict[str, Any], policy_id: str, shards: int
) -> dict[str, Any]:
    return {
        "index_patterns": [pattern],
        "template": {
            "settings": {
                "number_of_shards": shards,
                "number_of_replicas": 1,
                "index.plugins.index_state_management.policy_id": policy_id,
                "index.plugins.index_state_management.rollover_alias": alias,
                "index.mapping.total_fields.limit": 2000,
            },
            "mappings": mapping,
        },
    }


def _ism_policy(*, description: str, alias: str, hot_days: int, delete_days: int) -> dict[str, Any]:
    """Hot -> warm -> delete. Rollover at 50GB or 1 day, whichever first, so
    a quiet tenant still gets daily indices (predictable retention deletes)
    and a loud one does not end up with one enormous shard."""
    return {
        "policy": {
            "description": description,
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [{"rollover": {"min_size": "50gb", "min_index_age": "1d"}}],
                    "transitions": [
                        {"state_name": "warm", "conditions": {"min_index_age": f"{hot_days}d"}}
                    ],
                },
                {
                    "name": "warm",
                    "actions": [{"replica_count": {"number_of_replicas": 1}}],
                    "transitions": [
                        {"state_name": "delete", "conditions": {"min_index_age": f"{delete_days}d"}}
                    ],
                },
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": [{"index_patterns": [], "priority": 100}],
        }
    }


async def bootstrap_indices(client: AsyncOpenSearch) -> None:
    """Idempotent: safe to run on every start of every worker and API
    replica, including concurrently."""
    settings = get_settings()

    families = (
        (
            "lunatic-events-raw",
            RAW_PATTERN,
            RAW_ALIAS,
            _raw_mapping(),
            2,
            settings.opensearch_raw_retention_days,
            7,
        ),
        (
            "lunatic-events-normalized",
            NORMALIZED_PATTERN,
            NORMALIZED_ALIAS,
            normalized_mapping(),
            3,
            settings.opensearch_normalized_retention_days,
            14,
        ),
        (
            "lunatic-deadletter",
            DEADLETTER_PATTERN,
            DEADLETTER_ALIAS,
            _deadletter_mapping(),
            1,
            settings.opensearch_deadletter_retention_days,
            30,
        ),
    )

    for name, pattern, alias, mapping, shards, retention_days, hot_days in families:
        policy_id = f"{name}-policy"
        await _put_ism_policy(
            client,
            policy_id,
            _ism_policy(
                description=f"Lifecycle for {name}",
                alias=alias,
                hot_days=hot_days,
                delete_days=retention_days,
            ),
            pattern,
        )
        await client.indices.put_index_template(
            name=f"{name}-template",
            body=_template_body(
                pattern=pattern, alias=alias, mapping=mapping, policy_id=policy_id, shards=shards
            ),
        )
        await _ensure_write_index(client, pattern=pattern, alias=alias)
        await _apply_mapping_to_existing(client, alias=alias, mapping=mapping)

    logger.info("opensearch index templates and lifecycle policies applied")


async def _put_ism_policy(
    client: AsyncOpenSearch, policy_id: str, policy: dict[str, Any], pattern: str
) -> None:
    policy["policy"]["ism_template"] = [{"index_patterns": [pattern], "priority": 100}]
    try:
        await client.transport.perform_request(
            "PUT", f"/_plugins/_ism/policies/{policy_id}", body=policy
        )
    except ConflictError:
        # The policy already exists. Updating it requires the current
        # sequence number, and clobbering a policy an operator may have
        # tuned is worse than leaving it alone — so this is a deliberate
        # no-op and policy changes are an explicit operational action.
        # (ConflictError is a sibling of RequestError, not a subclass:
        # catching only RequestError here made every restart after the
        # first one crash.)
        logger.debug("ISM policy already present", extra={"policy_id": policy_id})
    except RequestError as exc:
        if exc.status_code != 400:
            raise
        logger.debug("ISM policy rejected as already present", extra={"policy_id": policy_id})
    except NotFoundError:
        # The ISM plugin is absent (e.g. the `min` distribution). Templates
        # and mappings still apply; only automatic rollover/retention is
        # unavailable, which must be loud rather than silent.
        logger.warning(
            "ISM plugin unavailable: index lifecycle/retention will NOT be enforced",
            extra={"policy_id": policy_id},
        )


async def _apply_mapping_to_existing(
    client: AsyncOpenSearch, *, alias: str, mapping: dict[str, Any]
) -> None:
    """Pushes newly declared fields onto the indices that already exist.

    A template only applies to indices created after it, so adding a field
    to the mapping would otherwise leave it unindexed until the next
    rollover — and with `dynamic: false` that means documents carrying the
    new field are stored but silently unsearchable, which for a detection
    rule keyed on that field is a silent coverage gap. Adding fields is a
    permitted mapping update; changing an existing field's type is not, and
    that case is logged loudly rather than swallowed, because it needs a
    reindex and a human.
    """
    try:
        await client.indices.put_mapping(index=alias, body=mapping)
    except NotFoundError:
        return  # nothing created yet; the template will cover the first index
    except RequestError:
        logger.exception(
            "could not update the mapping of existing indices: an incompatible "
            "mapping change needs a reindex",
            extra={"alias": alias},
        )


async def _ensure_write_index(client: AsyncOpenSearch, *, pattern: str, alias: str) -> None:
    """Rollover needs a concrete index carrying `is_write_index` behind the
    alias. Without it the first write auto-creates an index with the alias
    pointing at it but no rollover target, and lifecycle silently never
    runs."""
    if await client.indices.exists_alias(name=alias):
        return
    initial_index = pattern.replace("*", "000001")
    try:
        await client.indices.create(
            index=initial_index, body={"aliases": {alias: {"is_write_index": True}}}
        )
    except RequestError as exc:
        if exc.error != "resource_already_exists_exception":
            raise
