"""identity, rbac, multi-tenancy

Revision ID: 3ed3c3c2dcfb
Revises: 
Create Date: 2026-09-12 04:15:12.777660

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '3ed3c3c2dcfb'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# NOTE: the RBAC seed data below is a FROZEN SNAPSHOT, deliberately
# duplicated from app/auth/permissions.py rather than imported from it. A
# migration must produce the same result forever: if it imported live
# application code, re-running this migration on a new database years from
# now would seed a different catalog than it seeded originally, and two
# environments built from the same migration chain would diverge. Changes to
# the catalog ship as NEW migrations (see the api_key migration) instead.
# app/tests/test_rbac_seed.py asserts the database's seeded catalog and the
# live app/auth/permissions.py stay in agreement, so this duplication cannot
# drift silently.

# --- FROZEN SEED SNAPSHOT (see module note above) ---------------------------
_ROLE_NAMES = (
    "SUPER_ADMIN",
    "ORG_ADMIN",
    "SOC_MANAGER",
    "SOC_ANALYST_L1",
    "SOC_ANALYST_L2",
    "SOC_ANALYST_L3",
    "THREAT_HUNTER",
    "DFIR_ANALYST",
    "AUDITOR",
    "READ_ONLY",
)

_PERMISSION_CATALOG = (
    ("user", "read"),
    ("user", "write"),
    ("user", "delete"),
    ("organization", "read"),
    ("organization", "write"),
    ("asset", "read"),
    ("asset", "write"),
    ("asset", "delete"),
    ("event", "read"),
    ("alert", "read"),
    ("alert", "write"),
    ("incident", "read"),
    ("incident", "write"),
    ("incident", "delete"),
    ("ioc", "read"),
    ("ioc", "write"),
    ("ioc", "delete"),
    ("rule", "read"),
    ("rule", "write"),
    ("rule", "delete"),
    ("rule", "execute"),
    ("hunt", "read"),
    ("hunt", "write"),
    ("hunt", "execute"),
    ("mitre", "read"),
    ("mitre", "write"),
    ("playbook", "read"),
    ("playbook", "write"),
    ("playbook", "execute"),
    ("playbook", "approve"),
    ("audit", "read"),
)

_ROLE_PERMISSIONS = {
    "SUPER_ADMIN": (
        ("user", "read"),
        ("user", "write"),
        ("user", "delete"),
        ("organization", "read"),
        ("organization", "write"),
        ("asset", "read"),
        ("asset", "write"),
        ("asset", "delete"),
        ("event", "read"),
        ("alert", "read"),
        ("alert", "write"),
        ("incident", "read"),
        ("incident", "write"),
        ("incident", "delete"),
        ("ioc", "read"),
        ("ioc", "write"),
        ("ioc", "delete"),
        ("rule", "read"),
        ("rule", "write"),
        ("rule", "delete"),
        ("rule", "execute"),
        ("hunt", "read"),
        ("hunt", "write"),
        ("hunt", "execute"),
        ("mitre", "read"),
        ("mitre", "write"),
        ("playbook", "read"),
        ("playbook", "write"),
        ("playbook", "execute"),
        ("playbook", "approve"),
        ("audit", "read"),
    ),
    "ORG_ADMIN": (
        ("user", "read"),
        ("user", "write"),
        ("user", "delete"),
        ("organization", "read"),
        ("organization", "write"),
        ("asset", "read"),
        ("asset", "write"),
        ("asset", "delete"),
        ("event", "read"),
        ("alert", "read"),
        ("alert", "write"),
        ("incident", "read"),
        ("incident", "write"),
        ("incident", "delete"),
        ("ioc", "read"),
        ("ioc", "write"),
        ("ioc", "delete"),
        ("rule", "read"),
        ("rule", "write"),
        ("rule", "delete"),
        ("rule", "execute"),
        ("hunt", "read"),
        ("hunt", "write"),
        ("hunt", "execute"),
        ("mitre", "read"),
        ("mitre", "write"),
        ("playbook", "read"),
        ("playbook", "write"),
        ("playbook", "execute"),
        ("playbook", "approve"),
        ("audit", "read"),
    ),
    "SOC_MANAGER": (
        ("user", "read"),
        ("user", "write"),
        ("asset", "read"),
        ("asset", "write"),
        ("asset", "delete"),
        ("alert", "read"),
        ("alert", "write"),
        ("incident", "read"),
        ("incident", "write"),
        ("incident", "delete"),
        ("ioc", "read"),
        ("ioc", "write"),
        ("ioc", "delete"),
        ("rule", "read"),
        ("rule", "write"),
        ("rule", "delete"),
        ("rule", "execute"),
        ("hunt", "read"),
        ("hunt", "write"),
        ("hunt", "execute"),
        ("mitre", "read"),
        ("mitre", "write"),
        ("playbook", "read"),
        ("playbook", "write"),
        ("playbook", "execute"),
        ("playbook", "approve"),
        ("audit", "read"),
        ("organization", "read"),
    ),
    "SOC_ANALYST_L1": (
        ("asset", "read"),
        ("alert", "read"),
        ("alert", "write"),
        ("incident", "read"),
        ("incident", "write"),
        ("ioc", "read"),
        ("event", "read"),
        ("mitre", "read"),
        ("hunt", "read"),
        ("hunt", "execute"),
    ),
    "SOC_ANALYST_L2": (
        ("asset", "read"),
        ("alert", "read"),
        ("alert", "write"),
        ("incident", "read"),
        ("incident", "write"),
        ("ioc", "read"),
        ("ioc", "write"),
        ("event", "read"),
        ("mitre", "read"),
        ("rule", "read"),
        ("rule", "execute"),
        ("hunt", "read"),
        ("hunt", "write"),
        ("hunt", "execute"),
        ("playbook", "read"),
        ("playbook", "execute"),
    ),
    "SOC_ANALYST_L3": (
        ("asset", "read"),
        ("asset", "write"),
        ("alert", "read"),
        ("alert", "write"),
        ("incident", "read"),
        ("incident", "write"),
        ("incident", "delete"),
        ("ioc", "read"),
        ("ioc", "write"),
        ("ioc", "delete"),
        ("event", "read"),
        ("mitre", "read"),
        ("rule", "read"),
        ("rule", "write"),
        ("rule", "execute"),
        ("hunt", "read"),
        ("hunt", "write"),
        ("hunt", "execute"),
        ("playbook", "read"),
        ("playbook", "write"),
        ("playbook", "execute"),
    ),
    "THREAT_HUNTER": (
        ("asset", "read"),
        ("alert", "read"),
        ("incident", "read"),
        ("ioc", "read"),
        ("ioc", "write"),
        ("event", "read"),
        ("mitre", "read"),
        ("hunt", "read"),
        ("hunt", "write"),
        ("hunt", "execute"),
    ),
    "DFIR_ANALYST": (
        ("asset", "read"),
        ("asset", "write"),
        ("alert", "read"),
        ("incident", "read"),
        ("incident", "write"),
        ("ioc", "read"),
        ("ioc", "write"),
        ("event", "read"),
        ("mitre", "read"),
        ("hunt", "read"),
        ("hunt", "execute"),
        ("playbook", "read"),
        ("playbook", "execute"),
        ("audit", "read"),
    ),
    "AUDITOR": (
        ("user", "read"),
        ("organization", "read"),
        ("asset", "read"),
        ("alert", "read"),
        ("incident", "read"),
        ("ioc", "read"),
        ("rule", "read"),
        ("playbook", "read"),
        ("audit", "read"),
        ("mitre", "read"),
    ),
    "READ_ONLY": (
        ("asset", "read"),
        ("alert", "read"),
        ("incident", "read"),
        ("ioc", "read"),
        ("event", "read"),
        ("rule", "read"),
        ("mitre", "read"),
        ("hunt", "read"),
        ("playbook", "read"),
    ),
}


# Tenant-scoped tables created by this migration — each gets a
# FORCE ROW LEVEL SECURITY policy as the second isolation layer described in
# THREAT_MODEL.md §3.2 / ARCHITECTURE.md §1 row 3. `organizations` itself IS
# the tenant (no policy needed); `roles`/`permissions`/`role_permissions`
# are global reference data.
TENANT_SCOPED_TABLES = ("users", "sessions", "api_keys", "user_roles")


def upgrade() -> None:
    # citext is used by users.email and must exist before that table is created.
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('organizations',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('slug', sa.String(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('slug')
    )
    op.create_table('permissions',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('resource', sa.String(), nullable=False),
    sa.Column('action', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('resource', 'action', name='uq_permissions_resource_action')
    )
    op.create_table('roles',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=True),
    sa.CheckConstraint("name IN ('SUPER_ADMIN', 'ORG_ADMIN', 'SOC_MANAGER', 'SOC_ANALYST_L1', 'SOC_ANALYST_L2', 'SOC_ANALYST_L3', 'THREAT_HUNTER', 'DFIR_ANALYST', 'AUDITOR', 'READ_ONLY')", name='ck_roles_name'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('role_permissions',
    sa.Column('role_id', sa.UUID(), nullable=False),
    sa.Column('permission_id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )
    op.create_table('users',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('email', postgresql.CITEXT(), nullable=False),
    sa.Column('password_hash', sa.String(), nullable=False),
    sa.Column('full_name', sa.String(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('mfa_enabled', sa.Boolean(), nullable=False),
    sa.Column('mfa_secret_enc', sa.String(), nullable=True),
    sa.Column('failed_login_attempts', sa.Integer(), nullable=False),
    sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('tenant_id', 'email', name='uq_users_tenant_email')
    )
    op.create_table('api_keys',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('key_hash', sa.String(), nullable=False),
    sa.Column('scopes', sa.ARRAY(sa.String()), nullable=False),
    sa.Column('is_collector_key', sa.Boolean(), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_by', sa.UUID(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('sessions',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.Column('refresh_token_hash', sa.String(), nullable=False),
    sa.Column('user_agent', sa.String(), nullable=True),
    sa.Column('ip_address', postgresql.INET(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_roles',
    sa.Column('user_id', sa.UUID(), nullable=False),
    sa.Column('role_id', sa.UUID(), nullable=False),
    sa.Column('tenant_id', sa.UUID(), nullable=False),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['tenant_id'], ['organizations.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    # ### end Alembic commands ###

    for table in TENANT_SCOPED_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{table} ON {table}
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            """
        )

    _seed_rbac_catalog()


def _seed_rbac_catalog() -> None:
    """Load the fixed frozen role catalog, permission catalog, and default
    role->permission matrix defined at the top of this module."""
    roles_table = sa.table(
        "roles", sa.column("id", postgresql.UUID), sa.column("name", sa.String),
        sa.column("description", sa.String),
    )
    permissions_table = sa.table(
        "permissions", sa.column("id", postgresql.UUID), sa.column("resource", sa.String),
        sa.column("action", sa.String),
    )
    role_permissions_table = sa.table(
        "role_permissions", sa.column("role_id", postgresql.UUID),
        sa.column("permission_id", postgresql.UUID),
    )

    role_ids = {name: uuid.uuid4() for name in _ROLE_NAMES}
    op.bulk_insert(
        roles_table,
        [{"id": role_ids[name], "name": name, "description": None} for name in _ROLE_NAMES],
    )

    permission_ids = {(resource, action): uuid.uuid4() for resource, action in _PERMISSION_CATALOG}
    op.bulk_insert(
        permissions_table,
        [
            {"id": permission_ids[(resource, action)], "resource": resource, "action": action}
            for resource, action in _PERMISSION_CATALOG
        ],
    )

    role_permission_rows = [
        {"role_id": role_ids[role_name], "permission_id": permission_ids[perm]}
        for role_name, perms in _ROLE_PERMISSIONS.items()
        for perm in perms
    ]
    op.bulk_insert(role_permissions_table, role_permission_rows)


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('user_roles')
    op.drop_table('sessions')
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('role_permissions')
    op.drop_table('roles')
    op.drop_table('permissions')
    op.drop_table('organizations')
    # ### end Alembic commands ###
