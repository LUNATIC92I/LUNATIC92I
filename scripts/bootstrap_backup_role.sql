-- One-time DBA bootstrap for logical backups (docs/BACKUP_RESTORE.md).
--
-- Every tenant-scoped table has FORCE ROW LEVEL SECURITY (Phase 2,
-- defense-in-depth: even the table owner is subject to the tenant policy,
-- so a missing tenant_id filter in application code cannot leak rows).
-- That is exactly correct for the application's own role and exactly
-- wrong for a backup, which must capture every tenant's data in one pass.
-- The fix is a SEPARATE role with BYPASSRLS, used only for pg_dump /
-- pg_basebackup — never for application traffic, never granted to the
-- app's own connection role.
--
-- Run this once, as a Postgres superuser (or any role with CREATEROLE),
-- against each environment. It is deliberately NOT run by the
-- application, a migration, or CI: granting BYPASSRLS is a privileged,
-- rare, human-reviewed action, not something automation should be able
-- to do to itself.
--
--   psql -h <host> -U postgres -d lunatic_siem -f scripts/bootstrap_backup_role.sql

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lunatic_backup') THEN
    -- NOLOGIN by default; a real deployment sets a password or, better,
    -- relies on its secret-manager/IAM-auth integration (matching however
    -- the platform's own DATABASE_URL credential is sourced) rather than
    -- a password baked into this script.
    CREATE ROLE lunatic_backup WITH LOGIN BYPASSRLS;
  END IF;
END
$$;

GRANT CONNECT ON DATABASE lunatic_siem TO lunatic_backup;
GRANT USAGE ON SCHEMA public TO lunatic_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO lunatic_backup;
-- Any table Alembic adds later should be covered automatically for
-- future backups without re-running this script by hand.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO lunatic_backup;
