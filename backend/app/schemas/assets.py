"""Asset inventory schemas.

`criticality` is not an ordinary CRUD field: it is a direct multiplier on
every risk score computed for that machine (`app/risk/factors.py`), so
raising or lowering it changes what the SOC sees. That is why the write
paths are permission-gated and audit-logged, and why the API refuses
anything outside the fixed vocabulary rather than storing free text.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.assets import ASSET_TYPES, CRITICALITIES


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_type: str
    hostname: str | None = Field(default=None, max_length=253)
    ip_address: str | None = None
    mac_address: str | None = None
    os: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    department: str | None = Field(default=None, max_length=200)
    criticality: str = "MEDIUM"
    environment: str | None = Field(default=None, max_length=64)
    tags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("asset_type")
    @classmethod
    def _known_type(cls, value: str) -> str:
        if value not in ASSET_TYPES:
            raise ValueError(f"asset_type must be one of {', '.join(ASSET_TYPES)}")
        return value

    @field_validator("criticality")
    @classmethod
    def _known_criticality(cls, value: str) -> str:
        upper = value.upper()
        if upper not in CRITICALITIES:
            raise ValueError(f"criticality must be one of {', '.join(CRITICALITIES)}")
        return upper


class AssetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str | None = Field(default=None, max_length=253)
    ip_address: str | None = None
    mac_address: str | None = None
    os: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    department: str | None = Field(default=None, max_length=200)
    criticality: str | None = None
    environment: str | None = Field(default=None, max_length=64)
    tags: list[str] | None = Field(default=None, max_length=32)
    is_active: bool | None = None

    @field_validator("criticality")
    @classmethod
    def _known_criticality(cls, value: str | None) -> str | None:
        if value is None:
            return None
        upper = value.upper()
        if upper not in CRITICALITIES:
            raise ValueError(f"criticality must be one of {', '.join(CRITICALITIES)}")
        return upper


class AssetPublic(BaseModel):
    id: str
    asset_type: str
    hostname: str | None
    ip_address: str | None
    mac_address: str | None
    os: str | None
    owner: str | None
    department: str | None
    criticality: str
    environment: str | None
    tags: list[str]
    is_active: bool
    last_seen_at: datetime | None
    created_at: datetime
    updated_at: datetime
