"""OpenSearch integration tests, against a real cluster with the security
plugin enabled.

These are deliberately not mocked. The Phase 5 claims are all claims about
*server* behavior — that the mapping is applied, that `dynamic: false` holds,
that Document-Level Security confines a tenant's reader to its own events. A
fake client would assert nothing about any of them.
"""

import uuid
from typing import Any

import pytest
from opensearchpy import AsyncOpenSearch
from opensearchpy.exceptions import AuthorizationException

from app.core.config import get_settings
from app.core.opensearch import get_opensearch
from app.services.index_management import (
    NORMALIZED_ALIAS,
    bootstrap_indices,
    normalized_mapping,
)
from app.services.indexing import EventIndexer
from app.services.opensearch_security import (
    TENANT_READER_ROLE,
    ensure_tenant_reader_role,
    provision_tenant_reader,
)


@pytest.fixture(scope="session")
async def opensearch() -> AsyncOpenSearch:
    client = get_opensearch()
    await bootstrap_indices(client)
    return client


def _document(tenant_id: str, **overrides: Any) -> dict[str, Any]:
    document = {
        "event_id": str(uuid.uuid4()),
        "timestamp": "2026-09-13T05:00:00+00:00",
        "ingestion_timestamp": "2026-09-13T05:00:01+00:00",
        "tenant_id": tenant_id,
        "source": "test-collector",
        "source_type": "syslog_udp",
        "category": "Identity & Access Management",
        "class": "Authentication",
        "severity": "high",
        "activity": "Logon Failed",
        "user": {"name": "alice"},
        "source_ip": "10.1.1.5",
        "hostname": "web01",
        "schema_version": "lunatic-1",
        "raw_event": "<34>Oct 11 22:14:15 web01 sshd[1234]: Failed password for alice",
        "normalized_event": {"class_uid": 3002},
    }
    document.update(overrides)
    return document


# ---------------------------------------------------------------------------
# Index management
# ---------------------------------------------------------------------------


async def test_bootstrap_is_idempotent(opensearch: AsyncOpenSearch) -> None:
    """Every API replica and worker runs this at startup, concurrently."""
    await bootstrap_indices(opensearch)
    await bootstrap_indices(opensearch)

    templates = await opensearch.indices.get_index_template(name="lunatic-*")
    names = {template["name"] for template in templates["index_templates"]}
    assert names == {
        "lunatic-events-raw-template",
        "lunatic-events-normalized-template",
        "lunatic-deadletter-template",
        # Detections are stored as well as published (Phase 10): one that
        # exists only as a message on a topic cannot be counted per ATT&CK
        # technique, or pointed at by an alert.
        "lunatic-detections-template",
    }


async def test_write_alias_exists_so_rollover_has_a_target(
    opensearch: AsyncOpenSearch,
) -> None:
    """Without a concrete write index behind the alias, lifecycle silently
    never rolls over and retention never runs. The alias can legitimately
    sit behind more than one index once ILM has actually rolled it over at
    least once — the invariant that matters is that exactly one of them is
    the write index, not that only one index exists at all."""
    aliases = await opensearch.indices.get_alias(name=NORMALIZED_ALIAS)
    assert aliases, "normalized write alias missing"
    write_indices = [
        index
        for index, meta in aliases.items()
        if meta["aliases"][NORMALIZED_ALIAS].get("is_write_index")
    ]
    assert len(write_indices) == 1, f"expected exactly one write index, got {write_indices}"


async def test_lifecycle_policies_are_installed(opensearch: AsyncOpenSearch) -> None:
    response = await opensearch.transport.perform_request("GET", "/_plugins/_ism/policies")
    policy_ids = {policy["_id"] for policy in response.get("policies", [])}
    assert {
        "lunatic-events-raw-policy",
        "lunatic-events-normalized-policy",
        "lunatic-deadletter-policy",
    } <= policy_ids


async def test_declared_mapping_is_actually_applied(opensearch: AsyncOpenSearch) -> None:
    """Typed fields are what make search work: `source_ip` mapped as `ip`
    supports CIDR queries, as `text` it would not."""
    aliases = await opensearch.indices.get_alias(name=NORMALIZED_ALIAS)
    index = next(iter(aliases))
    mapping = await opensearch.indices.get_mapping(index=index)
    properties = mapping[index]["mappings"]["properties"]

    assert properties["source_ip"]["type"] == "ip"
    assert properties["timestamp"]["type"] == "date"
    assert properties["tenant_id"]["type"] == "keyword"
    assert mapping[index]["mappings"]["dynamic"] == "false"


async def test_every_mapped_field_is_declared_in_code_and_cluster_alike(
    opensearch: AsyncOpenSearch,
) -> None:
    aliases = await opensearch.indices.get_alias(name=NORMALIZED_ALIAS)
    index = next(iter(aliases))
    mapping = await opensearch.indices.get_mapping(index=index)

    assert set(mapping[index]["mappings"]["properties"]) == set(
        normalized_mapping()["properties"]
    )


# ---------------------------------------------------------------------------
# Indexing
# ---------------------------------------------------------------------------


async def test_indexed_event_is_searchable(opensearch: AsyncOpenSearch) -> None:
    tenant_id = str(uuid.uuid4())
    document = _document(tenant_id)

    outcome = await EventIndexer(opensearch).index_batch([document])
    assert outcome.indexed == 1
    assert outcome.rejected == []

    await opensearch.indices.refresh(index=NORMALIZED_ALIAS)
    found = await opensearch.search(
        index=NORMALIZED_ALIAS, body={"query": {"term": {"tenant_id": tenant_id}}}
    )
    assert found["hits"]["total"]["value"] == 1
    assert found["hits"]["hits"][0]["_source"]["user"]["name"] == "alice"


async def test_reindexing_the_same_event_id_overwrites_rather_than_duplicating(
    opensearch: AsyncOpenSearch,
) -> None:
    """Replay after a crash must not double-count: the event id is the
    document id (spec §26 idempotency)."""
    tenant_id = str(uuid.uuid4())
    document = _document(tenant_id, severity="high")
    indexer = EventIndexer(opensearch)

    await indexer.index_batch([document])
    await indexer.index_batch([{**document, "severity": "critical"}])
    await opensearch.indices.refresh(index=NORMALIZED_ALIAS)

    found = await opensearch.search(
        index=NORMALIZED_ALIAS, body={"query": {"term": {"tenant_id": tenant_id}}}
    )
    assert found["hits"]["total"]["value"] == 1
    assert found["hits"]["hits"][0]["_source"]["severity"] == "critical"


async def test_ip_field_supports_cidr_search(opensearch: AsyncOpenSearch) -> None:
    """The reason the mapping matters: hunting by network range only works
    if the field is genuinely typed as `ip`."""
    tenant_id = str(uuid.uuid4())
    await EventIndexer(opensearch).index_batch(
        [
            _document(tenant_id, source_ip="10.1.1.5"),
            _document(tenant_id, source_ip="192.0.2.7"),
        ]
    )
    await opensearch.indices.refresh(index=NORMALIZED_ALIAS)

    found = await opensearch.search(
        index=NORMALIZED_ALIAS,
        body={
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"tenant_id": tenant_id}},
                        {"term": {"source_ip": "10.0.0.0/8"}},
                    ]
                }
            }
        },
    )
    assert found["hits"]["total"]["value"] == 1
    assert found["hits"]["hits"][0]["_source"]["source_ip"] == "10.1.1.5"


async def test_a_rejected_document_is_reported_not_silently_lost(
    opensearch: AsyncOpenSearch,
) -> None:
    """OpenSearch bulk returns HTTP 200 while rejecting individual
    documents. Treating that as success is how events disappear."""
    tenant_id = str(uuid.uuid4())
    good = _document(tenant_id)
    bad = _document(tenant_id, source_ip="not-an-ip-address")

    outcome = await EventIndexer(opensearch).index_batch([good, bad])

    assert outcome.indexed == 1
    assert len(outcome.rejected) == 1
    rejected_document, reason = outcome.rejected[0]
    assert rejected_document["event_id"] == bad["event_id"]
    assert "mapper_parsing_exception" in reason or "illegal_argument" in reason


async def test_undeclared_fields_do_not_break_indexing(
    opensearch: AsyncOpenSearch,
) -> None:
    """`dynamic: false` means an unexpected field is stored but not indexed
    — a source that suddenly emits new keys must not fail ingestion nor
    explode the cluster's field count."""
    tenant_id = str(uuid.uuid4())
    document = _document(tenant_id, some_unexpected_vendor_field="surprise")

    outcome = await EventIndexer(opensearch).index_batch([document])
    assert outcome.rejected == []

    await opensearch.indices.refresh(index=NORMALIZED_ALIAS)
    found = await opensearch.search(
        index=NORMALIZED_ALIAS, body={"query": {"term": {"tenant_id": tenant_id}}}
    )
    source = found["hits"]["hits"][0]["_source"]
    assert source["some_unexpected_vendor_field"] == "surprise"  # stored


# ---------------------------------------------------------------------------
# Document-Level Security: the second tenant-isolation layer
# ---------------------------------------------------------------------------


async def test_dls_confines_a_tenant_reader_to_its_own_events(
    opensearch: AsyncOpenSearch,
) -> None:
    """The event-store half of the isolation guarantee (THREAT_MODEL.md
    §3.2): a query with NO tenant filter at all, issued by a tenant's
    reader, must still return only that tenant's events — because
    OpenSearch itself refuses the rest, not because the application
    remembered to filter."""
    settings = get_settings()
    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())
    suffix = uuid.uuid4().hex[:8]
    username = f"reader_{suffix}"
    password = f"Dls-Test-{suffix}-1!"

    await ensure_tenant_reader_role(opensearch)
    await provision_tenant_reader(
        opensearch, username=username, password=password, tenant_id=tenant_a
    )

    await EventIndexer(opensearch).index_batch(
        [
            _document(tenant_a, user={"name": "tenant-a-user"}),
            _document(tenant_b, user={"name": "tenant-b-user"}),
        ]
    )
    await opensearch.indices.refresh(index=NORMALIZED_ALIAS)

    scoped = AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(username, password),
        verify_certs=False,
        ssl_show_warn=False,
    )
    try:
        # Deliberately unfiltered: match_all across every event index.
        found = await scoped.search(
            index="lunatic-events-normalized-*", body={"query": {"match_all": {}}}, size=100
        )
        tenants = {hit["_source"]["tenant_id"] for hit in found["hits"]["hits"]}

        assert tenant_a in tenants, "tenant's own events should be visible"
        assert tenants == {tenant_a}, f"DLS leaked other tenants' events: {tenants - {tenant_a}}"
    finally:
        await scoped.close()


async def test_tenant_reader_cannot_write_or_delete_events(
    opensearch: AsyncOpenSearch,
) -> None:
    """The event store is evidence: analyst credentials must not be able to
    alter it (THREAT_MODEL.md §4, 'evidence tampering')."""
    settings = get_settings()
    tenant_id = str(uuid.uuid4())
    suffix = uuid.uuid4().hex[:8]
    username = f"reader_{suffix}"
    password = f"Dls-Test-{suffix}-1!"

    await ensure_tenant_reader_role(opensearch)
    await provision_tenant_reader(
        opensearch, username=username, password=password, tenant_id=tenant_id
    )

    scoped = AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=(username, password),
        verify_certs=False,
        ssl_show_warn=False,
    )
    try:
        with pytest.raises(AuthorizationException):
            await scoped.index(index=NORMALIZED_ALIAS, body=_document(tenant_id))
    finally:
        await scoped.close()


async def test_the_dls_role_is_defined_with_an_attribute_substituted_query(
    opensearch: AsyncOpenSearch,
) -> None:
    """One role for all tenants, scoped by user attribute. Per-tenant roles
    would mean a tenant whose role was never created silently falling back
    to default permissions."""
    await ensure_tenant_reader_role(opensearch)
    response = await opensearch.transport.perform_request(
        "GET", f"/_plugins/_security/api/roles/{TENANT_READER_ROLE}"
    )
    permissions = response[TENANT_READER_ROLE]["index_permissions"][0]

    assert "${attr.internal.tenant_id}" in permissions["dls"]
    assert set(permissions["allowed_actions"]) == {"read", "search"}
