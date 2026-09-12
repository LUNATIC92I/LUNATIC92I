"""Guards the one real hazard of frozen migration seed data: drift.

Migrations deliberately duplicate the RBAC catalog as immutable snapshots
rather than importing app/auth/permissions.py (see the note atop the initial
RBAC migration). That duplication is only safe if something fails loudly
when the two disagree — adding a permission to the live catalog without a
migration would otherwise mean `require_permission()` gates on a permission
no role in the database can ever hold, i.e. a silently unreachable endpoint.
"""

from sqlalchemy import select

from app.auth.permissions import PERMISSION_CATALOG, ROLE_PERMISSIONS
from app.core.db import async_session_factory
from app.models.identity import Permission, Role, RolePermission


async def test_seeded_permission_catalog_matches_application_catalog() -> None:
    async with async_session_factory() as db:
        rows = (await db.execute(select(Permission.resource, Permission.action))).all()

    assert {(resource, action) for resource, action in rows} == set(PERMISSION_CATALOG)


async def test_seeded_role_grants_match_application_matrix() -> None:
    async with async_session_factory() as db:
        rows = (
            await db.execute(
                select(Role.name, Permission.resource, Permission.action)
                .join(RolePermission, RolePermission.role_id == Role.id)
                .join(Permission, Permission.id == RolePermission.permission_id)
            )
        ).all()

    seeded: dict[str, set[tuple[str, str]]] = {}
    for role_name, resource, action in rows:
        seeded.setdefault(role_name, set()).add((resource, action))

    expected = {role: set(perms) for role, perms in ROLE_PERMISSIONS.items()}
    assert seeded == expected
