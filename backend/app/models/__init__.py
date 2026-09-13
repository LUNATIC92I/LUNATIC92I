# SQLAlchemy ORM models, one module per bounded context — added from Phase 2
# onward. Import new model modules here so they register on
# app.core.db.Base.metadata before Alembic autogenerate runs.
from app.models.assets import Asset  # noqa: F401
from app.models.audit import AuditLog  # noqa: F401
from app.models.detection import (  # noqa: F401
    DetectionRuleRecord,
    DetectionRuleVersion,
    RuleExceptionRecord,
)
from app.models.identity import (  # noqa: F401
    ApiKey,
    Organization,
    Permission,
    Role,
    RolePermission,
    Session,
    User,
    UserRole,
)
from app.models.threat_intel import Ioc, IocFeed, IocHistory  # noqa: F401
