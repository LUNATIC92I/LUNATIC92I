from collections.abc import AsyncIterator

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
    """FastAPI dependency yielding a request-scoped session. Phase 2 wires
    tenant-scoping (`SET app.current_tenant_id`) into this same dependency —
    see ARCHITECTURE.md §1 row 3 and THREAT_MODEL.md §3.2."""
    async with async_session_factory() as session:
        yield session
