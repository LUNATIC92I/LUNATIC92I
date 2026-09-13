import os
from pathlib import Path

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://lunatic:dev-only-change-me@localhost:5432/lunatic_siem_test"
)
os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-production")
os.environ.setdefault("MFA_ENCRYPTION_KEY", "zHb3Yy0hz3z1aFq8LZ9v5jz1E7c8n5x2b3v4c5x6y7z=")
os.environ.setdefault("ENV", "test")
os.environ.setdefault("MAX_FAILED_LOGIN_ATTEMPTS", "3")
# The shipped rule pack lives at the repository root; tests exercise the real
# install path (a new tenant gets detections immediately) rather than a stub.
os.environ.setdefault(
    "DETECTION_RULES_PATH", str(Path(__file__).resolve().parents[3] / "rules")
)
os.environ.setdefault("OPENSEARCH_URL", "https://localhost:9200")
os.environ.setdefault("OPENSEARCH_USERNAME", "admin")
os.environ.setdefault("OPENSEARCH_PASSWORD", "LunaticDev-Test-1!")
# Local clusters use the self-signed demo certificates.
os.environ.setdefault("OPENSEARCH_VERIFY_CERTS", "false")
os.environ.setdefault("CORS_ALLOWED_ORIGINS", "http://localhost:5173")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from alembic.config import Config  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from alembic import command  # noqa: E402
from app.core.db import async_session_factory  # noqa: E402
from app.main import app  # noqa: E402

_BACKEND_ROOT = Path(__file__).resolve().parents[2]


def _alembic_config() -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    return cfg


@pytest.fixture(scope="session", autouse=True)
def _migrated_database():
    """Applies every migration once for the whole test session against a
    dedicated test database (never the dev database), and tears the schema
    back down at the end so repeated local runs stay reproducible."""
    cfg = _alembic_config()
    command.upgrade(cfg, "head")
    yield
    command.downgrade(cfg, "base")


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables():
    """Truncates all tenant/identity data between tests so each test starts
    from a blank slate without re-running migrations. RBAC seed data
    (roles/permissions/role_permissions) is left intact."""
    yield
    async with async_session_factory() as db:
        await db.execute(
            text(
                "TRUNCATE TABLE audit_logs, sessions, api_keys, user_roles, "
                "rule_exceptions, detection_rule_versions, detection_rules, "
                "iocs, ioc_history, ioc_feeds, "
                # The ATT&CK catalog is global rather than tenant data, but
                # it is still per-test state: a catalog left behind by an
                # earlier test would make a later one's coverage numbers
                # depend on execution order.
                "rule_mitre_map, mitre_technique_tactics, mitre_techniques, "
                "mitre_tactics, mitre_imports, "
                "users, assets, organizations CASCADE"
            )
        )
        await db.commit()


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
