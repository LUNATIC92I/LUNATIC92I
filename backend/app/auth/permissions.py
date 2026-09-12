"""The RBAC permission catalog and default role→permission matrix.

This is the single source of truth for what a resource/action permission
string looks like (`require_permission("incident", "write")`) and for the
seed data the initial Alembic migration loads. Deny-by-default: a resource
not listed here cannot be granted to any role, and a route that calls
`require_permission()` with a pair not in PERMISSION_CATALOG is a bug caught
at migration/seed time, not silently allowed.

NOTE: once this seed data has shipped to any real environment, changes to
ROLE_PERMISSIONS must land as a *new* Alembic migration, never as an edit to
the migration that first loaded it — migrations are an immutable history.
During Phase 2 development (nothing deployed yet) editing here and
re-generating the seed migration is fine.
"""

from app.models.identity import ROLE_NAMES

READ = "read"
WRITE = "write"
DELETE = "delete"
EXECUTE = "execute"
APPROVE = "approve"

# (resource, [allowed actions]) — resources match the spec §22 API groups
# that exist or are planned; actions are only the ones meaningful for that
# resource (e.g. events are never user-writable).
_RESOURCE_ACTIONS: dict[str, tuple[str, ...]] = {
    "user": (READ, WRITE, DELETE),
    "organization": (READ, WRITE),
    "asset": (READ, WRITE, DELETE),
    "event": (READ,),
    "alert": (READ, WRITE),
    "incident": (READ, WRITE, DELETE),
    "ioc": (READ, WRITE, DELETE),
    "rule": (READ, WRITE, DELETE, EXECUTE),
    "hunt": (READ, WRITE, EXECUTE),
    "mitre": (READ, WRITE),
    "playbook": (READ, WRITE, EXECUTE, APPROVE),
    "audit": (READ,),
}

PERMISSION_CATALOG: list[tuple[str, str]] = [
    (resource, action) for resource, actions in _RESOURCE_ACTIONS.items() for action in actions
]


def _all() -> list[tuple[str, str]]:
    return list(PERMISSION_CATALOG)


def _only(resource_actions: dict[str, tuple[str, ...]]) -> list[tuple[str, str]]:
    return [(r, a) for r, actions in resource_actions.items() for a in actions]


# Default seed matrix. SUPER_ADMIN and ORG_ADMIN get everything (super admin
# is cross-tenant; org admin is scoped to their own tenant by the normal
# tenant-isolation layer, not by this matrix). Every other role is deny by
# default except what's listed.
ROLE_PERMISSIONS: dict[str, list[tuple[str, str]]] = {
    "SUPER_ADMIN": _all(),
    "ORG_ADMIN": _all(),
    "SOC_MANAGER": _only(
        {
            "user": (READ, WRITE),
            "asset": (READ, WRITE, DELETE),
            "alert": (READ, WRITE),
            "incident": (READ, WRITE, DELETE),
            "ioc": (READ, WRITE, DELETE),
            "rule": (READ, WRITE, DELETE, EXECUTE),
            "hunt": (READ, WRITE, EXECUTE),
            "mitre": (READ, WRITE),
            "playbook": (READ, WRITE, EXECUTE, APPROVE),
            "audit": (READ,),
            "organization": (READ,),
        }
    ),
    "SOC_ANALYST_L1": _only(
        {
            "asset": (READ,),
            "alert": (READ, WRITE),
            "incident": (READ, WRITE),
            "ioc": (READ,),
            "event": (READ,),
            "mitre": (READ,),
            "hunt": (READ, EXECUTE),
        }
    ),
    "SOC_ANALYST_L2": _only(
        {
            "asset": (READ,),
            "alert": (READ, WRITE),
            "incident": (READ, WRITE),
            "ioc": (READ, WRITE),
            "event": (READ,),
            "mitre": (READ,),
            "rule": (READ, EXECUTE),
            "hunt": (READ, WRITE, EXECUTE),
            "playbook": (READ, EXECUTE),
        }
    ),
    "SOC_ANALYST_L3": _only(
        {
            "asset": (READ, WRITE),
            "alert": (READ, WRITE),
            "incident": (READ, WRITE, DELETE),
            "ioc": (READ, WRITE, DELETE),
            "event": (READ,),
            "mitre": (READ,),
            "rule": (READ, WRITE, EXECUTE),
            "hunt": (READ, WRITE, EXECUTE),
            "playbook": (READ, WRITE, EXECUTE),
        }
    ),
    "THREAT_HUNTER": _only(
        {
            "asset": (READ,),
            "alert": (READ,),
            "incident": (READ,),
            "ioc": (READ, WRITE),
            "event": (READ,),
            "mitre": (READ,),
            "hunt": (READ, WRITE, EXECUTE),
        }
    ),
    "DFIR_ANALYST": _only(
        {
            "asset": (READ, WRITE),
            "alert": (READ,),
            "incident": (READ, WRITE),
            "ioc": (READ, WRITE),
            "event": (READ,),
            "mitre": (READ,),
            "hunt": (READ, EXECUTE),
            "playbook": (READ, EXECUTE),
            "audit": (READ,),
        }
    ),
    "AUDITOR": _only(
        {
            "user": (READ,),
            "organization": (READ,),
            "asset": (READ,),
            "alert": (READ,),
            "incident": (READ,),
            "ioc": (READ,),
            "rule": (READ,),
            "playbook": (READ,),
            "audit": (READ,),
            "mitre": (READ,),
        }
    ),
    "READ_ONLY": _only(
        {
            "asset": (READ,),
            "alert": (READ,),
            "incident": (READ,),
            "ioc": (READ,),
            "event": (READ,),
            "rule": (READ,),
            "mitre": (READ,),
            "hunt": (READ,),
            "playbook": (READ,),
        }
    ),
}

if set(ROLE_PERMISSIONS) != set(ROLE_NAMES):
    raise RuntimeError("ROLE_PERMISSIONS must have exactly one entry per role in ROLE_NAMES")
