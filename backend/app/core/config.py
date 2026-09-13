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

    opensearch_url: str = "https://localhost:9200"
    opensearch_username: str = ""
    opensearch_password: str = ""
    # Must be true in production. False is only for local clusters using the
    # self-signed demo certificates (see app/core/opensearch.py).
    opensearch_verify_certs: bool = True
    # Retention, in days, per index family. Configurable per deployment
    # because retention is a compliance decision, not an engineering one.
    opensearch_raw_retention_days: int = 90
    opensearch_normalized_retention_days: int = 180
    opensearch_deadletter_retention_days: int = 90

    # --- Ingestion (Phase 3) ---
    ingest_max_payload_bytes: int = 1024 * 1024
    ingest_rate_limit_per_minute: int = 60_000
    ingest_dedup_ttl_seconds: int = 3600

    # Syslog collector worker. Both are required to start that worker: an
    # unauthenticated transport must be pinned to one tenant and an explicit
    # source allowlist (THREAT_MODEL.md §3.1).
    syslog_tenant_id: str = ""
    syslog_allowed_source_cidrs: str = ""
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5515

    # --- Detection engine (Phase 6) ---
    # Where the default rule pack lives. Rules are installed from here into
    # a tenant once; after that the database is authoritative, so editing a
    # file never silently overwrites a tenant's tuning.
    detection_rules_path: str = "/app/rules"
    detection_rule_refresh_seconds: int = 60
    # How often windowed (threshold) rules are evaluated. Shorter than the
    # shortest rule window on purpose: runs overlap so an attack straddling
    # two runs still lands whole inside one window (see detection/windowed.py).
    detection_window_interval_seconds: int = 60

    # --- Correlation engine (Phase 7) ---
    # How far a source's own timestamp may sit from its ingestion time
    # before the correlation engine stops believing it and uses ingestion
    # time instead (Technical Risk #5: timestamp-manipulation evasion).
    correlation_max_clock_skew_seconds: int = 900

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
