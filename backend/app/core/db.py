import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Shared declarative base. Every ORM model (added from Phase 2 onward)
    registers its table here so a single Alembic target_metadata sees all of
    them — see alembic/env.py."""


_settings = get_settings()
engine = create_async_engine(_settings.database_url, pool_pre_ping=True)
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """Plain, tenant-unaware session — only for code paths that legitimately
    operate before a tenant is known (resolving an org slug at login,
    creating a new organization at registration). Anything that reads or
    writes tenant-scoped tables (users, sessions, api_keys, user_roles, and
    every tenant-scoped table added in later phases) must go through
    `tenant_scoped_session` instead, or PostgreSQL's FORCE ROW LEVEL
    SECURITY policy will simply return zero rows / reject the write."""
    async with async_session_factory() as session:
        yield session


@asynccontextmanager
async def tenant_scoped_session(tenant_id: uuid.UUID) -> AsyncIterator[AsyncSession]:
    """A session scoped to a single tenant via the `app.current_tenant_id`
    GUC that every tenant-scoped table's RLS policy checks
    (ARCHITECTURE.md §1 row 3, THREAT_MODEL.md §3.2).
    `set_config(..., is_local=true)` is the parameterized equivalent of
    `SET LOCAL` (plain `SET LOCAL` doesn't accept bind parameters) — it
    resets automatically when the transaction ends, which matters because
    connections are pooled and reused: the setting must never leak into a
    later, unrelated request that happens to reuse the same connection.

    Deliberately does NOT wrap the session in `session.begin()`: callers
    call `await session.commit()` themselves exactly when they want to
    persist (SQLAlchemy's AsyncSession autobegins a transaction on first
    use), which lets a caller commit more than once — or not at all for a
    pure read — within one `async with` block. Whatever isn't committed by
    the time the block exits is rolled back by `session.close()`, which is
    the fail-closed default for read-only routes that (correctly) never
    call commit."""
    async with async_session_factory() as session:
        await session.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": str(tenant_id)},
        )
        yield session
