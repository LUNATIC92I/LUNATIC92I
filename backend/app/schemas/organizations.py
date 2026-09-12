from pydantic import BaseModel


class OrganizationPublic(BaseModel):
    id: str
    name: str
    slug: str
    is_active: bool
