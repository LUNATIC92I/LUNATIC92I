-- LUNATIC-IT SIEM — PostgreSQL schema (Phase 0 draft)
--
-- Scope: system-of-record entities (identity/RBAC, multi-tenancy, assets,
-- alerts, incidents, detection rules, IOCs, playbooks, audit log, MITRE
-- reference data). Event/log data lives in OpenSearch (see
-- docs/database/opensearch_indices.md), not here.
--
-- Conventions:
--   - UUID primary keys everywhere (no sequential/guessable IDs -> IDOR mitigation).
--   - Every tenant-scoped table carries tenant_id and has an RLS policy.
--   - created_at/updated_at on every mutable table.
--   - Enums modeled as CHECK-constrained text (portable, easy Alembic migration diffs)
--     rather than native PG ENUM (avoids painful enum-alter migrations).
--   - This file is a Phase 0 design artifact; actual schema will be created via
--     Alembic migrations in Phase 1/2, not applied directly from this file.

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- gen_random_uuid()

-- =========================================================================
-- 1. IDENTITY / MULTI-TENANCY / RBAC
-- =========================================================================

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- organizations ARE tenants (1:1). tenant_id everywhere below = organizations.id.

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES organizations(id),
    email               CITEXT NOT NULL,
    password_hash       TEXT NOT NULL,           -- Argon2id
    full_name           TEXT NOT NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_enc      TEXT,                     -- encrypted at rest via app-level envelope encryption
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE CHECK (name IN (
                    'SUPER_ADMIN','ORG_ADMIN','SOC_MANAGER','SOC_ANALYST_L1',
                    'SOC_ANALYST_L2','SOC_ANALYST_L3','THREAT_HUNTER',
                    'DFIR_ANALYST','AUDITOR','READ_ONLY')),
    description TEXT
);

CREATE TABLE permissions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource    TEXT NOT NULL,      -- e.g. 'incident', 'rule', 'ioc', 'playbook'
    action      TEXT NOT NULL,      -- e.g. 'read', 'write', 'delete', 'execute', 'approve'
    UNIQUE (resource, action)
);

CREATE TABLE role_permissions (
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id   UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL REFERENCES organizations(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL REFERENCES organizations(id),
    refresh_token_hash  TEXT NOT NULL,
    user_agent          TEXT,
    ip_address          INET,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organizations(id),
    name            TEXT NOT NULL,
    key_hash        TEXT NOT NULL,           -- never store raw key
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    is_collector_key BOOLEAN NOT NULL DEFAULT FALSE, -- used by ingestion collectors
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 2. ASSETS (lightweight CMDB)
-- =========================================================================

CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organizations(id),
    asset_type      TEXT NOT NULL CHECK (asset_type IN (
                        'server','endpoint','laptop','network_device',
                        'cloud_resource','application')),
    hostname        TEXT,
    ip_address      INET,
    mac_address     MACADDR,
    os              TEXT,
    owner           TEXT,
    department      TEXT,
    criticality     TEXT NOT NULL DEFAULT 'MEDIUM' CHECK (criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    environment     TEXT,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_assets_ip ON assets(tenant_id, ip_address);

-- =========================================================================
-- 3. MITRE ATT&CK REFERENCE DATA (imported/updated, not hardcoded logic)
-- =========================================================================

CREATE TABLE mitre_tactics (
    id          TEXT PRIMARY KEY,       -- e.g. 'TA0001'
    name        TEXT NOT NULL,
    version     TEXT NOT NULL           -- ATT&CK content version imported
);

CREATE TABLE mitre_techniques (
    id              TEXT PRIMARY KEY,   -- e.g. 'T1110' or 'T1110.001'
    name            TEXT NOT NULL,
    tactic_id       TEXT REFERENCES mitre_tactics(id),
    is_subtechnique BOOLEAN NOT NULL DEFAULT FALSE,
    parent_id       TEXT REFERENCES mitre_techniques(id),
    version         TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 4. DETECTION RULES
-- =========================================================================

CREATE TABLE detection_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES organizations(id), -- NULL = global/shared rule
    rule_key        TEXT NOT NULL,       -- e.g. 'AUTH-001' (stable across versions)
    name            TEXT NOT NULL,
    description     TEXT,
    severity        TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    confidence      SMALLINT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    status          TEXT NOT NULL DEFAULT 'disabled' CHECK (status IN ('enabled','disabled','testing')),
    rule_type       TEXT NOT NULL CHECK (rule_type IN ('streaming','windowed')),
    definition_yaml TEXT NOT NULL,       -- source of truth authored form
    risk_score      SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    false_positive_notes TEXT,
    investigation_steps  TEXT,
    references_urls TEXT[] NOT NULL DEFAULT '{}',
    author          UUID REFERENCES users(id),
    current_version INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, rule_key)
);

CREATE TABLE detection_rule_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    definition_yaml TEXT NOT NULL,
    changed_by      UUID REFERENCES users(id),
    change_summary  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_id, version)
);

CREATE TABLE rule_mitre_map (
    rule_id         UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    technique_id    TEXT NOT NULL REFERENCES mitre_techniques(id),
    PRIMARY KEY (rule_id, technique_id)
);

CREATE TABLE rule_exceptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES organizations(id),
    match_criteria  JSONB NOT NULL,     -- e.g. {"user": "svc-backup", "source_ip": "10.0.0.5"}
    reason          TEXT NOT NULL,
    created_by      UUID REFERENCES users(id),
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 5. CORRELATION RULES
-- =========================================================================

CREATE TABLE correlation_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES organizations(id),
    name            TEXT NOT NULL,
    description     TEXT,
    definition_yaml TEXT NOT NULL,   -- required events, order, window, entities, score
    status          TEXT NOT NULL DEFAULT 'disabled' CHECK (status IN ('enabled','disabled','testing')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 6. THREAT INTELLIGENCE / IOC
-- =========================================================================

CREATE TABLE iocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES organizations(id),  -- NULL = shared/global feed IOC
    ioc_type        TEXT NOT NULL CHECK (ioc_type IN (
                        'ipv4','ipv6','domain','url','md5','sha1','sha256',
                        'email','asn','certificate')),
    value           TEXT NOT NULL,
    classification  TEXT NOT NULL DEFAULT 'unknown' CHECK (classification IN ('malicious','suspicious','benign','unknown')),
    confidence      SMALLINT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    source          TEXT NOT NULL,           -- feed name or 'manual'
    tags            TEXT[] NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, ioc_type, value, source)
);
CREATE INDEX idx_iocs_value ON iocs(ioc_type, value);

CREATE TABLE ioc_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_id          UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    changed_field   TEXT NOT NULL,
    old_value       TEXT,
    new_value       TEXT,
    changed_by      UUID REFERENCES users(id),
    changed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ioc_feeds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    connector_type  TEXT NOT NULL,      -- e.g. 'misp', 'otx', 'csv_url'
    config          JSONB NOT NULL DEFAULT '{}', -- non-secret config; credentials via secrets manager reference
    is_enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 7. ALERTS
-- =========================================================================

CREATE TABLE alerts (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES organizations(id),
    rule_id             UUID REFERENCES detection_rules(id),
    correlation_rule_id UUID REFERENCES correlation_rules(id),
    event_ids           TEXT[] NOT NULL DEFAULT '{}',  -- OpenSearch event _id references (evidence lineage)
    severity            TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    risk_score          SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_explanation    JSONB NOT NULL DEFAULT '{}',   -- per-factor breakdown, see risk engine
    confidence          SMALLINT NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    source              TEXT,
    affected_user       TEXT,
    affected_host       TEXT,
    affected_asset_id   UUID REFERENCES assets(id),
    source_ip           INET,
    destination_ip      INET,
    mitre_techniques    TEXT[] NOT NULL DEFAULT '{}',
    description         TEXT NOT NULL,
    evidence            JSONB NOT NULL DEFAULT '{}',
    status              TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN (
                            'NEW','IN_PROGRESS','ESCALATED','FALSE_POSITIVE','RESOLVED','CLOSED')),
    analyst_id          UUID REFERENCES users(id),
    dedup_key           TEXT,             -- for suppression/dedup window
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_alerts_tenant_status ON alerts(tenant_id, status);
CREATE INDEX idx_alerts_dedup ON alerts(tenant_id, dedup_key, created_at);

-- =========================================================================
-- 8. INCIDENTS
-- =========================================================================

CREATE TABLE incidents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES organizations(id),
    display_id          TEXT NOT NULL,     -- e.g. 'INC-2026-000001', generated per-tenant sequence
    title               TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    priority            TEXT NOT NULL DEFAULT 'P3' CHECK (priority IN ('P1','P2','P3','P4')),
    status              TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN (
                            'NEW','TRIAGE','INVESTIGATION','CONTAINMENT',
                            'ERADICATION','RECOVERY','CLOSED')),
    analyst_id          UUID REFERENCES users(id),
    resolution          TEXT,
    lessons_learned     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at           TIMESTAMPTZ,
    UNIQUE (tenant_id, display_id)
);

CREATE TABLE incident_alerts (
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id    UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE incident_assets (
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    asset_id    UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, asset_id)
);

CREATE TABLE incident_iocs (
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    ioc_id      UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, ioc_id)
);

CREATE TABLE incident_notes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id       UUID REFERENCES users(id),
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE incident_tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    assignee_id     UUID REFERENCES users(id),
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','done')),
    due_at          TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE incident_timeline (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    occurred_at     TIMESTAMPTZ NOT NULL,
    event_type      TEXT NOT NULL,      -- e.g. 'status_change', 'note_added', 'alert_linked'
    payload         JSONB NOT NULL DEFAULT '{}',
    actor_id        UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 9. THREAT HUNTING (saved queries)
-- =========================================================================

CREATE TABLE saved_hunts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES organizations(id),
    name            TEXT NOT NULL,
    description     TEXT,
    query_dsl       JSONB NOT NULL,       -- OpenSearch query representation
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- =========================================================================
-- 10. PLAYBOOKS / SOAR
-- =========================================================================

CREATE TABLE playbooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES organizations(id),
    name            TEXT NOT NULL,
    trigger_rule_id UUID REFERENCES detection_rules(id),
    definition_yaml TEXT NOT NULL,        -- ordered actions
    is_enabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE playbook_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id     UUID NOT NULL REFERENCES playbooks(id),
    alert_id        UUID REFERENCES alerts(id),
    incident_id     UUID REFERENCES incidents(id),
    status          TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN (
                        'PENDING','RUNNING','COMPLETED','FAILED','PARTIALLY_COMPLETED')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

CREATE TABLE playbook_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id          UUID NOT NULL REFERENCES playbook_runs(id) ON DELETE CASCADE,
    action_name     TEXT NOT NULL,       -- e.g. 'enrich_ip', 'isolate_host'
    is_destructive  BOOLEAN NOT NULL DEFAULT FALSE,
    dry_run_result  JSONB,
    status          TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN (
                        'PENDING','PENDING_APPROVAL','APPROVED','REJECTED',
                        'EXECUTED','FAILED','SKIPPED')),
    result          JSONB,
    executed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE playbook_action_approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id       UUID NOT NULL REFERENCES playbook_actions(id) ON DELETE CASCADE,
    requested_by    UUID REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    decision        TEXT CHECK (decision IN ('APPROVED','REJECTED')),
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (requested_by IS DISTINCT FROM approved_by)  -- dual control: requester cannot approve their own action
);

-- =========================================================================
-- 11. AUDIT LOG (append-only)
-- =========================================================================

CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES organizations(id),
    actor_id        UUID REFERENCES users(id),
    actor_ip        INET,
    user_agent      TEXT,
    action          TEXT NOT NULL,        -- e.g. 'CREATE_RULE','CHANGE_ROLE','IOC_CHANGE'
    object_type     TEXT NOT NULL,
    object_id       TEXT,
    before_state    JSONB,
    after_state     JSONB,
    result          TEXT NOT NULL CHECK (result IN ('success','failure')),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_tenant_time ON audit_logs(tenant_id, occurred_at DESC);
-- Application DB role for the audit module is granted INSERT + SELECT only
-- (no UPDATE/DELETE) — see THREAT_MODEL.md §3.7.

-- =========================================================================
-- 12. ROW-LEVEL SECURITY (representative pattern, applied to every
--     tenant-scoped table above)
-- =========================================================================

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_alerts ON alerts
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
-- The app sets `app.current_tenant_id` (a session-local GUC) from the
-- authenticated principal at the start of every request/transaction, never
-- from client-supplied input. Repeat this ENABLE + POLICY pair for:
-- users, assets, detection_rules, correlation_rules, iocs, incidents,
-- incident_notes/tasks/timeline, saved_hunts, playbooks, playbook_runs,
-- audit_logs (tenant-scoped rows only; NULL tenant_id = global/shared rows
-- readable per a separate "is_global" policy branch).
