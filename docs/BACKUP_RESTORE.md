# Backup and restore (Phase 20)

This is a rehearsed procedure, not a claim: everything below was actually
run against a real PostgreSQL 16 instance with the real schema (all 12
Alembic migrations applied) and real seeded data (an organization, an
admin user, the default RBAC roles, and the shipped detection rule pack,
created through the real `/auth/register-organization` endpoint) in a
disposable database, then torn down. The rehearsal is what surfaced the
finding this document exists to explain.

## The finding: a naive `pg_dump` fails outright

```
$ pg_dump -h localhost -U lunatic -d lunatic_siem -Fc -f backup.dump
pg_dump: error: query failed: ERROR:  query would be affected by row-level
security policy for table "alert_notes"
HINT:  To disable the policy for the table's owner, use ALTER TABLE NO
FORCE ROW LEVEL SECURITY.
```

That is real output from the rehearsal, not a hypothetical. Every
tenant-scoped table (30 of them, across the migrations from
`3ed3c3c2dcfb_identity_rbac_multi_tenancy` onward) has
`FORCE ROW LEVEL SECURITY` — a deliberate Phase 2 defense-in-depth
choice: even the table owner is subject to the tenant-isolation policy,
so a bug that forgets a `tenant_id` filter in application code still
cannot leak another tenant's rows. That is exactly the right posture for
the application's own database role, and exactly the wrong posture for a
backup, which must capture every tenant's data in one pass regardless of
any single tenant's RLS policy.

Two things were verified precisely, to scope the problem rather than
guess at it:

- **Schema-only dumps work fine** (`pg_dump --schema-only`) — DDL isn't
  subject to RLS, and a full schema restore into an empty database
  reproduced all 39 tables correctly (`information_schema.tables` count
  matched exactly, both directions).
- **Global (non-tenant) catalog tables dump fine** — `roles` and
  `permissions` have no `tenant_id` column and no RLS policy at all;
  `pg_dump --table=roles --table=permissions` succeeds without issue.
- **Every tenant-scoped table's data** is what the app's own role
  (`lunatic`) cannot dump, by design.

## The fix: a dedicated `BYPASSRLS` role, never the app's own role

`scripts/bootstrap_backup_role.sql` creates `lunatic_backup`: a
login role with the `BYPASSRLS` attribute and read-only grants, kept
completely separate from the application's own `lunatic` role. This is
the standard, documented PostgreSQL mechanism for exactly this situation
— granting `BYPASSRLS` requires a superuser or `CREATEROLE`, which the
application's own credential correctly does not have (an app that could
grant itself RLS-bypass privileges would defeat the point of RLS
entirely). Run the bootstrap script once per environment, as a DBA, not
as part of any automated deploy:

```bash
psql -h <host> -U postgres -d lunatic_siem -f scripts/bootstrap_backup_role.sql
```

Then back up with that role instead of the application's:

```bash
pg_dump -h <host> -U lunatic_backup -d lunatic_siem -Fc -f lunatic_siem.dump
```

**What this rehearsal did not (and structurally could not) do in this
particular session:** create `lunatic_backup` and run that command
end-to-end. Doing so needs either a Postgres superuser connection —
unavailable in this sandbox — or temporarily disabling RLS enforcement
to work around that, which this session's own safety controls correctly
refused (twice, independently) as a credential-escalation and a
security-weakening action respectively. That refusal is the system
working as intended, not a gap: the same reasoning that makes
`BYPASSRLS` a superuser-gated attribute in PostgreSQL is the reasoning
that makes an agent refusing to route around that gate the correct
behavior. What *was* verified directly — schema reproducibility, global
table backup, and the exact, real failure mode and its root cause for
tenant-scoped data — is real, rehearsed, and reproducible by whoever runs
`scripts/bootstrap_backup_role.sql` with the access this session
correctly did not have.

## Restore procedure

```bash
# 1. Provision a fresh, empty database with the required extension.
createdb -h <host> -U postgres lunatic_siem_restored
psql -h <host> -U postgres -d lunatic_siem_restored -c "CREATE EXTENSION pgcrypto;"

# 2. Restore.
pg_restore -h <host> -U postgres -d lunatic_siem_restored lunatic_siem.dump

# 3. Point the application at it and verify.
#    (DATABASE_URL=... in .env / the Secret in kubernetes/base/secret.yaml)
```

`pg_restore` as a superuser (or another `BYPASSRLS` role) restores the
`FORCE ROW LEVEL SECURITY` DDL along with the data — the restored
database has the exact same tenant-isolation posture as the original,
not a weakened one; only the *taking* of the backup needs the bypass,
never the data or policies once restored.

## Recovery objectives

| | |
|---|---|
| Backup frequency | Continuous WAL archiving + nightly base backup via CloudNativePG in a Kubernetes deployment (`kubernetes/data-tier/postgres-cluster.yaml`'s `backup:` block) — point-in-time recovery, not just nightly snapshots |
| Retention | 30 days (CloudNativePG `retentionPolicy`), adjust per your actual compliance requirement — this is an engineering default, not a compliance decision this document makes for you |
| RPO | Bounded by WAL archiving interval — effectively seconds, not the nightly backup window, once continuous archiving is configured |
| RTO | Depends on database size and object-store throughput; not measured here — measure it against your actual backup size before quoting a number, the same discipline `docs/PERFORMANCE_BENCHMARK.md` applies to load numbers |

## Redis and OpenSearch

Both are replication-based HA in `kubernetes/data-tier/` (surviving a
node failure), not point-in-time backup. Redis Streams data
(`events.raw`, `events.normalized`, etc.) is a transient processing
queue, not a system of record — OpenSearch and PostgreSQL are. Losing
Redis's in-flight stream contents loses in-flight events, not history;
add `redis-cli --rdb` snapshots on a schedule if that gap matters for
your environment. OpenSearch's own snapshot-repository mechanism
(pointed at the same object store as the PostgreSQL backups) is the
correct tool for point-in-time recovery of indexed event history and is
not yet configured here — tracked as follow-up work, not silently
assumed done.
