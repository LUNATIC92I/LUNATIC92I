import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event, text
from sqlalchemy.engine import Connection
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

    The GUC is (re)applied on **every** transaction this session begins, not
    once when it is opened. `set_config(..., is_local=true)` is the
    parameterized equivalent of `SET LOCAL` (plain `SET LOCAL` doesn't accept
    bind parameters), and like SET LOCAL it lasts exactly as long as the
    transaction — which is what we want, because connections are pooled and
    a leaked setting would apply to somebody else's later request. The
    consequence is that a session which commits and then keeps working
    starts a *new* transaction with no tenant context, and every subsequent
    read would return nothing while every write would be refused. Hooking
    `after_begin` removes that trap instead of leaving each caller to
    remember it.

    Deliberately does NOT wrap the session in `session.begin()`: callers
    call `await session.commit()` themselves exactly when they want to
    persist (SQLAlchemy's AsyncSession autobegins a transaction on first
    use), which lets a caller commit more than once — or not at all for a
    pure read — within one `async with` block. Whatever isn't committed by
    the time the block exits is rolled back by `session.close()`, which is
    the fail-closed default for read-only routes that (correctly) never
    call commit."""
    async with async_session_factory() as session:
        _apply_on_every_transaction(session, "app.current_tenant_id", str(tenant_id))
        yield session


def _apply_on_every_transaction(session: AsyncSession, setting: str, value: str) -> None:
    """Sets a transaction-local GUC each time this session opens a
    transaction. Registered on the underlying sync Session because that is
    where SQLAlchemy emits `after_begin`."""

    @event.listens_for(session.sync_session, "after_begin")
    def _set_guc(_session: object, _transaction: object, connection: Connection) -> None:
        connection.execute(
            text("SELECT set_config(:setting, :value, true)"),
            {"setting": setting, "value": value},
        )


@asynccontextmanager
async def intel_sync_session() -> AsyncIterator[AsyncSession]:
    """A session allowed to write **shared** threat-intelligence rows.

    Global feed indicators belong to no tenant, so they cannot be written
    through `tenant_scoped_session`: that session's RLS policy only accepts
    rows stamped with its own tenant, and a NULL tenant fails the check. The
    `app.intel_sync` GUC enables a second policy whose WITH CHECK is the
    mirror image — it accepts *only* rows with no tenant, so this session
    cannot touch any tenant's private indicators either (see the Phase 9
    migration).

    Like `app.current_tenant_id`, this GUC is trusted infrastructure: it is
    set here and nowhere else, never from request input, and it is
    re-applied per transaction because it resets with each one.
    """
    async with async_session_factory() as session:
        _apply_on_every_transaction(session, "app.intel_sync", "on")
        yield session
