"""Collector API keys — the credential a log collector presents to the
ingestion gateway (THREAT_MODEL.md §3.1: "forged ingestion API key").

Key format: ``lsk_<tenant_id>_<44 random url-safe chars>``

The tenant id travels in the clear, exactly as it does in refresh tokens and
for the same reason: the `api_keys` table enforces FORCE ROW LEVEL SECURITY,
so a lookup must know its tenant *before* it can query. A tenant id is an
identifier, not a secret, and only the hash of the whole key is stored —
knowing the prefix gets an attacker nothing.
"""

import hashlib
import secrets
import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.db import tenant_scoped_session
from app.models.identity import ApiKey

_KEY_PREFIX = "lsk"


def _hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def generate_api_key(tenant_id: uuid.UUID) -> tuple[str, str]:
    """Returns (plaintext, hash). The plaintext is shown to the operator
    exactly once at creation and never stored."""
    plaintext = f"{_KEY_PREFIX}_{tenant_id}_{secrets.token_urlsafe(32)}"
    return plaintext, _hash_key(plaintext)


def parse_tenant_id(plaintext: str) -> uuid.UUID | None:
    parts = plaintext.split("_", 2)
    if len(parts) != 3 or parts[0] != _KEY_PREFIX:
        return None
    try:
        return uuid.UUID(parts[1])
    except ValueError:
        return None


async def resolve_collector_key(plaintext: str) -> ApiKey | None:
    """Returns the ApiKey row if `plaintext` is a valid, active collector
    key, else None. Every rejection path returns None rather than a specific
    error so a caller cannot distinguish "no such key" from "revoked" or
    "wrong tenant" (THREAT_MODEL.md §3.1)."""
    tenant_id = parse_tenant_id(plaintext)
    if tenant_id is None:
        return None

    key_hash = _hash_key(plaintext)
    now = datetime.now(UTC)

    async with tenant_scoped_session(tenant_id) as db:
        api_key = await db.scalar(
            select(ApiKey).where(
                ApiKey.key_hash == key_hash,
                ApiKey.tenant_id == tenant_id,
                ApiKey.is_collector_key.is_(True),
                ApiKey.revoked_at.is_(None),
            )
        )
        if api_key is None:
            return None
        if api_key.expires_at is not None and api_key.expires_at <= now:
            return None

        api_key.last_used_at = now
        await db.commit()
        return api_key


async def create_collector_key(
    *, tenant_id: uuid.UUID, name: str, created_by: uuid.UUID | None
) -> tuple[str, ApiKey]:
    plaintext, key_hash = generate_api_key(tenant_id)
    async with tenant_scoped_session(tenant_id) as db:
        api_key = ApiKey(
            tenant_id=tenant_id,
            name=name,
            key_hash=key_hash,
            is_collector_key=True,
            created_by=created_by,
        )
        db.add(api_key)
        await db.commit()
    return plaintext, api_key
