import uuid
from datetime import datetime

from sqlalchemy import ARRAY, Boolean, CheckConstraint, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import INET, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

ASSET_TYPES = (
    "server",
    "endpoint",
    "laptop",
    "network_device",
    "cloud_resource",
    "application",
)
CRITICALITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class Asset(Base):
    """Lightweight CMDB entry (spec §16).

    Exists this early because asset criticality is the highest-weight input
    to the Risk Engine and the enrichment that makes an alert actionable:
    the same failed login means something different on a laptop and on a
    domain controller.
    """

    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint(f"asset_type IN {ASSET_TYPES}", name="ck_assets_type"),
        CheckConstraint(f"criticality IN {CRITICALITIES}", name="ck_assets_criticality"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    asset_type: Mapped[str] = mapped_column(String, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    os: Mapped[str | None] = mapped_column(String, nullable=True)
    owner: Mapped[str | None] = mapped_column(String, nullable=True)
    department: Mapped[str | None] = mapped_column(String, nullable=True)
    criticality: Mapped[str] = mapped_column(String, nullable=False, default="MEDIUM")
    environment: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # The SIEM's own record of network containment, set by the `isolate_host`
    # playbook action (Phase 15). This is the platform's record that
    # isolation was ordered and approved — not a live signal from a
    # firewall/EDR, which no integration in this codebase actually drives;
    # see docs/PLAYBOOKS.md for why that boundary is drawn here.
    is_isolated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    isolated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
