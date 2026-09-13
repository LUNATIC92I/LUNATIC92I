from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.models.identity import ROLE_NAMES


class UserPublic(BaseModel):
    id: str
    email: str
    full_name: str
    is_active: bool
    mfa_enabled: bool
    roles: list[str]


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    full_name: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=256)
    role: str

    @field_validator("role")
    @classmethod
    def _known_role(cls, value: str) -> str:
        if value not in ROLE_NAMES:
            raise ValueError(f"role must be one of {', '.join(ROLE_NAMES)}")
        return value


class UserUpdate(BaseModel):
    """Every field is optional, but at least one must be given (enforced by
    the endpoint, not here) — an update naming nothing to change is a
    request written incorrectly, not a no-op."""

    model_config = ConfigDict(extra="forbid")

    is_active: bool | None = None
    role: str | None = None

    @field_validator("role")
    @classmethod
    def _known_role(cls, value: str | None) -> str | None:
        if value is not None and value not in ROLE_NAMES:
            raise ValueError(f"role must be one of {', '.join(ROLE_NAMES)}")
        return value


class RoleCatalogResponse(BaseModel):
    roles: list[str]
