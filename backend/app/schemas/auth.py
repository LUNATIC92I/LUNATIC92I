from pydantic import BaseModel, EmailStr, Field

_SLUG_PATTERN = r"^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])?$"


class RegisterOrganizationRequest(BaseModel):
    organization_name: str = Field(min_length=1, max_length=200)
    organization_slug: str = Field(pattern=_SLUG_PATTERN, max_length=64)
    admin_email: EmailStr
    admin_password: str = Field(min_length=12, max_length=256)
    admin_full_name: str = Field(min_length=1, max_length=200)


class RegisterOrganizationResponse(BaseModel):
    organization_id: str
    organization_slug: str
    user_id: str


class LoginRequest(BaseModel):
    organization_slug: str = Field(pattern=_SLUG_PATTERN, max_length=64)
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=6)


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105  OAuth2 token type label, not a credential
    expires_in: int
    mfa_required: bool = False


class MfaEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MeResponse(BaseModel):
    id: str
    email: str
    full_name: str
    tenant_id: str
    roles: list[str]
    permissions: list[str]
