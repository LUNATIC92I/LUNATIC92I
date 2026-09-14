from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized configuration, loaded from environment variables (.env in
    development). No secret ever has a non-empty default here — a missing
    required value must fail startup loudly, not silently fall back."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = "development"
    log_level: str = "INFO"

    # The frontend authenticates with an httpOnly refresh cookie
    # (app/api/auth.py), so its origin must be named explicitly — a
    # wildcard (`*`) is rejected by browsers for credentialed requests
    # anyway, and would be a much wider CORS hole than this API needs.
    # Comma-separated; empty means no browser origin is allowed (fail
    # closed, like the egress guard).
    cors_allowed_origins: str = ""

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
    opensearch_detection_retention_days: int = 365

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

    # --- Outbound egress guard (Phase 9, THREAT_MODEL.md §3.8) ---
    # Comma-separated hosts the platform may fetch from. EMPTY MEANS
    # NOTHING IS REACHABLE — the guard fails closed, so a deployment that
    # wants feeds must name their hosts. A leading dot matches subdomains
    # (".example.com"); anything else must match exactly.
    egress_allowed_hosts: str = ""
    # Local development only. Plain HTTP means an on-path attacker chooses
    # what your threat intelligence says.
    egress_allow_http: bool = False
    # Local development only. Disables the check that refuses hosts
    # resolving to loopback, private, link-local (169.254.169.254) or
    # reserved addresses — i.e. it disables the SSRF protection itself.
    egress_allow_private_destinations: bool = False

    # --- Threat intelligence (Phase 9) ---
    threat_intel_feed_interval_seconds: int = 3600
    threat_intel_default_ttl_days: int = 30
    # Where file-drop feeds are read from. Filenames from feed config are
    # confined to this directory (path traversal, THREAT_MODEL.md §3.8).
    threat_intel_drop_dir: str = "/app/intel-drop"

    # --- MITRE ATT&CK (Phase 10) ---
    # Where the ATT&CK STIX bundle is imported from: an HTTPS URL (subject
    # to the egress allow-list) or a filename in the drop directory. The
    # catalog is data, never hardcoded — see docs/MITRE_MAPPING.md.
    mitre_attack_source: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    )
    mitre_catalog_max_age_days: int = 90

    # --- Alerts (Phase 11) ---
    # How long a repeat of the same thing folds into the open alert instead
    # of raising a new one.
    alert_dedup_window_minutes: int = 60
    # Detections below this risk score are recorded and searchable but do
    # not become an analyst's task. Where that line sits is a SOC staffing
    # decision, so it is configuration, not a constant.
    alert_min_risk_score: int = 0

    # --- Threat hunting (Phase 13) ---
    # A hunt search/pivot result set an analyst can page through is one
    # thing; a bulk export is a different risk (THREAT_MODEL.md §3.7: data
    # exfiltration via a legitimate feature). Both are capped, and exports
    # are additionally rate-limited and audit-logged (EXPORT_DATA).
    hunt_search_max_results: int = 1000
    hunt_export_max_rows: int = 10_000
    hunt_export_rate_limit_per_hour: int = 20

    # --- SOAR playbooks (Phase 15) ---
    # Where the shipped playbook pack lives, mirroring
    # DETECTION_RULES_PATH: installed into a tenant once at registration,
    # after that the database is authoritative.
    playbooks_path: str = "/app/playbooks"

    # --- Observability (Phase 16) ---
    # `/health`, `/ready` and `/metrics` for every worker process are served
    # on this port, deliberately never published in docker-compose's `ports:`
    # (only reachable from Prometheus over the internal `app` network) —
    # unlike the API's own request/response routes, metrics are operational
    # detail (event/alert/detection volume) that a caller outside the
    # deployment has no business seeing (this phase's own review criterion).
    # The API backend runs the same server on the same default port
    # alongside its public one for exactly that reason: `/metrics` moves
    # off the publicly published port even though `/health`/`/ready` stay on
    # it too (those carry no more than a boolean, and container
    # orchestrators expect to reach them on a pod's primary port).
    metrics_port: int = 9100

    # OTLP/HTTP endpoint traces are exported to (e.g. a local Jaeger/Tempo
    # collector's "http://otel-collector:4318/v1/traces"). Empty by
    # default: spans are still created (propagation across the pipeline
    # works and is testable either way) but nothing leaves the process —
    # the same fail-closed-until-configured shape as EGRESS_ALLOWED_HOSTS.
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "lunatic-siem-backend"

    @property
    def is_production(self) -> bool:
        return self.env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
