"""api_key permissions

Adds the `api_key` resource to the RBAC catalog so collector credentials can
be issued and revoked under normal permission control (Phase 3 — ingestion).
Granted to SUPER_ADMIN/ORG_ADMIN (full), SOC_MANAGER (full), AUDITOR (read).

Revision ID: 67705d355d3b
Revises: e9f11f3bcc93
Create Date: 2026-09-12 05:02:11.000000

"""
import uuid
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '67705d355d3b'
down_revision: str | None = 'e9f11f3bcc93'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen snapshot of what THIS migration adds (see the note in the initial
# RBAC migration: seed data is never imported from live application code).
_NEW_PERMISSIONS = (
    ("api_key", "read"),
    ("api_key", "write"),
    ("api_key", "delete"),
)

_NEW_GRANTS = {
    "SUPER_ADMIN": (("api_key", "read"), ("api_key", "write"), ("api_key", "delete")),
    "ORG_ADMIN": (("api_key", "read"), ("api_key", "write"), ("api_key", "delete")),
    "SOC_MANAGER": (("api_key", "read"), ("api_key", "write"), ("api_key", "delete")),
    "AUDITOR": (("api_key", "read"),),
}


def upgrade() -> None:
    connection = op.get_bind()

    permission_ids: dict[tuple[str, str], uuid.UUID] = {}
    for resource, action in _NEW_PERMISSIONS:
        permission_id = uuid.uuid4()
        permission_ids[(resource, action)] = permission_id
        connection.execute(
            sa.text(
                "INSERT INTO permissions (id, resource, action) VALUES (:id, :resource, :action)"
            ),
            {"id": permission_id, "resource": resource, "action": action},
        )

    for role_name, grants in _NEW_GRANTS.items():
        role_id = connection.execute(
            sa.text("SELECT id FROM roles WHERE name = :name"), {"name": role_name}
        ).scalar_one()
        for grant in grants:
            connection.execute(
                sa.text(
                    "INSERT INTO role_permissions (role_id, permission_id) "
                    "VALUES (:role_id, :permission_id)"
                ),
                {"role_id": role_id, "permission_id": permission_ids[grant]},
            )


def downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text(
            "DELETE FROM role_permissions WHERE permission_id IN "
            "(SELECT id FROM permissions WHERE resource = 'api_key')"
        )
    )
    connection.execute(sa.text("DELETE FROM permissions WHERE resource = 'api_key'"))
