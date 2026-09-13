"""Document-Level Security: tenant isolation enforced by OpenSearch itself.

This is the event-store half of the defense-in-depth promised in
ARCHITECTURE.md §1 row 3 and THREAT_MODEL.md §3.2. PostgreSQL has RLS; the
event store has DLS. In both cases the point is the same: a forgotten
`tenant_id` filter in application code must not be sufficient to leak one
tenant's events to another, because the datastore refuses independently.

One role, not one role per tenant. OpenSearch substitutes user attributes
into a DLS query, so a single `lunatic_tenant_reader` role carrying

    {"term": {"tenant_id": "${attr.internal.tenant_id}"}}

scopes every query to whichever tenant the authenticated user belongs to.
Per-tenant roles would work too, but would mean thousands of role
definitions and a security config that has to be rewritten on every
signup — the failure mode being a tenant whose role was never created
falling back to whatever the default permissions allow.

The application's own service account deliberately does NOT hold this role:
workers must write events for every tenant. Those writes are what the
per-tenant readers then see, filtered.
"""

import logging
from typing import Any

from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import NotFoundError

logger = logging.getLogger(__name__)

TENANT_READER_ROLE = "lunatic_tenant_reader"
_READABLE_PATTERNS = ["lunatic-events-*", "lunatic-deadletter-*"]

_DLS_QUERY = '{"term": {"tenant_id": "${attr.internal.tenant_id}"}}'


async def ensure_tenant_reader_role(client: AsyncOpenSearch) -> None:
    """Idempotent. Read-only by design: an analyst's credentials must never
    be able to alter or delete events — the event store is evidence
    (THREAT_MODEL.md §4 'evidence tampering')."""
    body: dict[str, Any] = {
        "cluster_permissions": ["cluster_composite_ops_ro"],
        "index_permissions": [
            {
                "index_patterns": _READABLE_PATTERNS,
                "dls": _DLS_QUERY,
                "allowed_actions": ["read", "search"],
            }
        ],
    }
    await client.transport.perform_request(
        "PUT", f"/_plugins/_security/api/roles/{TENANT_READER_ROLE}", body=body
    )
    logger.info("tenant DLS reader role applied", extra={"role": TENANT_READER_ROLE})


async def provision_tenant_reader(
    client: AsyncOpenSearch, *, username: str, password: str, tenant_id: str
) -> None:
    """Creates (or updates) an OpenSearch user whose every query is confined
    to `tenant_id` by the DLS role above.

    The tenant id lives in a user *attribute*, not in anything the client
    sends: a caller cannot widen their own scope by changing a request,
    only by having a different account.
    """
    await client.transport.perform_request(
        "PUT",
        f"/_plugins/_security/api/internalusers/{username}",
        body={
            "password": password,
            "backend_roles": [],
            "attributes": {"tenant_id": tenant_id},
        },
    )
    existing = await _existing_mapped_users(client)
    await client.transport.perform_request(
        "PUT",
        f"/_plugins/_security/api/rolesmapping/{TENANT_READER_ROLE}",
        # sorted(set(...)) so re-provisioning the same user is a no-op rather
        # than appending a duplicate entry every time.
        body={"users": sorted({*existing, username})},
    )
    logger.info(
        "provisioned tenant-scoped OpenSearch reader",
        extra={"username": username, "tenant_id": tenant_id},
    )


async def _existing_mapped_users(client: AsyncOpenSearch) -> list[str]:
    """Role mappings are replaced wholesale by the API, so the current list
    has to be read first — a naive PUT would silently revoke every other
    tenant's reader."""
    try:
        response = await client.transport.perform_request(
            "GET", f"/_plugins/_security/api/rolesmapping/{TENANT_READER_ROLE}"
        )
    except NotFoundError:
        return []
    mapping = response.get(TENANT_READER_ROLE, {})
    users: list[str] = mapping.get("users", [])
    return users
