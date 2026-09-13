"""The RBAC permission catalog and default role→permission matrix.

This is the single source of truth for what a resource/action permission
string looks like (`require_permission("incident", "write")`) and for the
seed data the initial Alembic migration loads. Deny-by-default: a resource
not listed here cannot be granted to any role, and a route that calls
`require_permission()` with a pair not in PERMISSION_CATALOG is a bug caught
at migration/seed time, not silently allowed.

Changing this catalog takes TWO steps, always:

1. edit the constants here (what `require_permission()` enforces at runtime), and
2. add a NEW Alembic migration inserting the added rows (what the database
   actually contains).

Never edit an existing migration's seed data: migrations are immutable
history, and a migration that changed over time would seed different
catalogs into databases created at different times. `app/tests/
test_rbac_seed.py` fails the build if this module and the migrated database
disagree, so forgetting step 2 cannot slip through.
"""

from app.models.identity import ROLE_NAMES

READ = "read"
WRITE = "write"
DELETE = "delete"
EXECUTE = "execute"
APPROVE = "approve"
# Ending analyst work on an alert (resolve / false positive / close) is a
# separate action from triaging it, which is what makes the L1/L2 tier
# distinction real rather than a label: an L1 can pick an alert up and
# escalate it, only L2 and above can decide it is over (spec §13).
CLOSE = "close"

# (resource, [allowed actions]) — resources match the spec §22 API groups
# that exist or are planned; actions are only the ones meaningful for that
# resource (e.g. events are never user-writable).
_RESOURCE_ACTIONS: dict[str, tuple[str, ...]] = {
    "user": (READ, WRITE, DELETE),
    "organization": (READ, WRITE),
    "asset": (READ, WRITE, DELETE),
    "event": (READ,),
    "alert": (READ, WRITE, CLOSE),
    "incident": (READ, WRITE, DELETE),
    "ioc": (READ, WRITE, DELETE),
    "rule": (READ, WRITE, DELETE, EXECUTE),
    "hunt": (READ, WRITE, EXECUTE),
    "mitre": (READ, WRITE),
    "playbook": (READ, WRITE, EXECUTE, APPROVE),
    "audit": (READ,),
    # Collector credentials: a key holder can push events into the tenant,
    # so issuing one is an administrative act, not an analyst action.
    "api_key": (READ, WRITE, DELETE),
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
            "alert": (READ, WRITE, CLOSE),
            "incident": (READ, WRITE, DELETE),
            "ioc": (READ, WRITE, DELETE),
            "rule": (READ, WRITE, DELETE, EXECUTE),
            "hunt": (READ, WRITE, EXECUTE),
            "mitre": (READ, WRITE),
            "playbook": (READ, WRITE, EXECUTE, APPROVE),
            "audit": (READ,),
            "organization": (READ,),
            "api_key": (READ, WRITE, DELETE),
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
            "alert": (READ, WRITE, CLOSE),
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
            "alert": (READ, WRITE, CLOSE),
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
            "api_key": (READ,),
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
