from pydantic import BaseModel


class UserPublic(BaseModel):
    id: str
    email: str
    full_name: str
    is_active: bool
    mfa_enabled: bool
    roles: list[str]
