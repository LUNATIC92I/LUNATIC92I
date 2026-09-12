from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized configuration, loaded from environment variables (.env in
    development). No secret ever has a non-empty default here — a missing
    required value must fail startup loudly, not silently fall back."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = "development"
    log_level: str = "INFO"

    backend_port: int = 8000

    jwt_secret_key: str = ""
    jwt_access_token_ttl_seconds: int = 900
    jwt_refresh_token_ttl_seconds: int = 1_209_600

    # Fernet key (cryptography.fernet.Fernet.generate_key()) used for
    # envelope-encrypting MFA TOTP secrets at rest — never the same value
    # across environments, never committed.
    mfa_encryption_key: str = ""

    # Brute-force lockout (THREAT_MODEL.md §3.3).
    max_failed_login_attempts: int = 5
    lockout_duration_minutes: int = 15

    database_url: str = "postgresql+asyncpg://lunatic:lunatic@localhost:5432/lunatic_siem"
    redis_url: str = "redis://localhost:6379/0"
    opensearch_url: str = "http://localhost:9200"

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
