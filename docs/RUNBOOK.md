# Operational runbook

This is for "the platform itself is broken" — a pod crash-looping, a
database failover, an alert storm from a misbehaving rule. For "a
security incident happened in the environment this SIEM watches," see
`docs/INCIDENT_RESPONSE.md` instead: that is the analyst-facing case
workflow (`NEW → ... → CLOSED`) for what the platform *detects*, not for
recovering the platform *itself*. The two are easy to conflate by name
and are deliberately separate documents.

## First move, always: check `/ready`

Every service answers the same question the same way
(`docs/OBSERVABILITY.md`). Before doing anything else:

```bash
# API
curl -s http://<api-host>:8000/ready
# Every worker, on its internal metrics port
kubectl exec -n lunatic-siem deploy/parser -- curl -s http://localhost:9100/ready
```

`{"status": "ready"}` vs a 503 naming which dependency (`database`,
`redis`, `opensearch`) is unreachable tells you which failure class
you're in before you touch anything. Grafana's pipeline-overview
dashboard (`docker/grafana/dashboards/pipeline-overview.json`) is the
faster way to see this across every service at once if it's already
open.

## API or a worker is crash-looping

1. `kubectl logs -n lunatic-siem <pod> --previous` — the previous
   container's last output, since a crash-looping pod's *current* logs
   are often empty (it just restarted).
2. Structured JSON logs (`app/core/logging.py`) — grep for
   `"level": "ERROR"` or `"level": "CRITICAL"` rather than reading
   line-by-line.
3. If it's a worker and the error is
   `redis.exceptions.TimeoutError` / `ResponseError`: confirm Redis
   itself is actually reachable (`redis-cli -h <redis-host> ping`)
   before assuming it's a repeat of the Phase 18 socket-timeout class of
   bug — that one is fixed (`app/core/eventbus.py`), so a recurrence
   here points at the Redis side, not the client.
4. If it's the API and the error is a migration/schema mismatch: check
   `alembic_version` in the database matches what the deployed image
   expects (`alembic current` from a pod, or `SELECT version_num FROM
   alembic_version`) — a deploy that shipped code ahead of its migration
   is the usual cause, never fixed by restarting the pod.

## A worker's consumer lag is climbing

`XINFO GROUPS <topic>` on the relevant Redis Streams topic (from any pod
or `redis-cli`) shows `lag` per consumer group directly. Three causes,
in the order to check them:

1. **Not enough replicas for the load** — scale the Deployment (or let
   the HPA in `kubernetes/base/deployment-*.yaml` do it; check
   `kubectl get hpa -n lunatic-siem` for why it hasn't already, if it
   hasn't).
2. **A downstream dependency is slow** — OpenSearch indexing latency
   backs up the indexer worker specifically; check OpenSearch cluster
   health before assuming the worker itself is the problem.
3. **A poison message** — one event repeatedly failing to process
   without being dead-lettered would stall a consumer; this should not
   happen (every worker's `handle()` either publishes-and-acks or
   dead-letters-and-acks, never neither — see
   `app/core/eventbus.py`'s own module docstring), so if it does, that's
   a real bug worth a regression test, not something to work around by
   manually acking the stuck message and moving on.

## PostgreSQL primary failure

In the `kubernetes/data-tier/` deployment (CloudNativePG), this is
**automatic**: the operator promotes a synchronous replica and updates
the `postgres-rw` Service to point at it — the application's
`DATABASE_URL` never changes. Confirm it happened rather than assume it:

```bash
kubectl get cluster postgres -n lunatic-data -o jsonpath='{.status.currentPrimary}'
```

If the primary does not fail back over automatically, that is itself the
incident — escalate to the CloudNativePG operator's own troubleshooting
(`kubectl describe cluster postgres -n lunatic-data`) rather than
hand-editing the Service.

## Redis Sentinel failover

Automatic at both layers. Sentinel promotes a replica at the *data*
layer, and every backend Redis client — `RedisStreamsEventBus` included —
follows that promotion on its own, with no worker restart: set
`REDIS_SENTINEL_HOSTS` (comma-separated `host:port` Sentinel addresses)
and `REDIS_SENTINEL_SERVICE_NAME` (the `masterSet` name, `mymaster` for
the shipped `values-redis-ha.yaml`), and `app/core/redis.py::build_redis_client()`
builds every client through redis-py's own `Sentinel` class instead of a
static `redis://` connection — it re-resolves the current master on each
command rather than remembering whichever pod was master at process
start. Verified directly against a real local Redis+Sentinel cluster:
the actual master container was killed mid-run and the same client
continued serving requests against the promoted replica once Sentinel's
own detection window elapsed, with no data lost.

Nothing to do manually — confirm it happened rather than assume it:

```bash
# Confirm the new master
redis-cli -h <sentinel-host> -p 26379 sentinel get-master-addr-by-name mymaster
```

If a worker's logs show sustained connection errors past Sentinel's own
detection window (`down-after-milliseconds`), that is itself the
incident — check `REDIS_SENTINEL_HOSTS` is actually set for that
workload before assuming the client isn't following the failover.

## OpenSearch node loss

3-node cluster (`kubernetes/data-tier/values-opensearch-ha.yaml`)
tolerates one node down without losing quorum. Check
`GET /_cluster/health` — `status: yellow` (replicas unavailable, no data
lost) is expected and self-heals as Kubernetes reschedules the pod;
`status: red` (a primary shard is unavailable) means data loss risk and
needs immediate attention: check `GET /_cat/shards?h=index,shard,prirep,state`
for which shard and why, before doing anything else.

## Alert storm from a misbehaving detection rule

Rules refresh from PostgreSQL every `DETECTION_RULE_REFRESH_SECONDS`
(default 60s) with no worker restart required
(`app/workers/detection_worker.py`'s `RuleRegistry`). To silence a
misfiring rule immediately:

```sql
-- The DSL's rule_id (e.g. AUTH-003) is stored as rule_key here — see
-- app/models/detection.py's own comment on why the column is named
-- differently from the YAML field.
UPDATE detection_rules SET status = 'disabled' WHERE rule_key = 'AUTH-003' AND tenant_id = '<tenant>';
```

or via the API (`POST /rules/{rule_key}/status`, audited — see
`app/api/rules.py`) if the operator has API access rather than direct
database access. Takes effect within one refresh interval, not
instantly — that interval is the deliberate cost of not needing a
restart for routine rule tuning.

## Rolling back a bad deploy

```bash
kubectl rollout undo deployment/api -n lunatic-siem
kubectl rollout status deployment/api -n lunatic-siem
```

Every Deployment in `kubernetes/base/` uses `RollingUpdate` with
`maxUnavailable: 0` (api, frontend) or `1` (workers) — a rollback is the
same zero/low-disruption rolling update in reverse, not a special case.
If the bad deploy included a migration, **do not roll back the database
migration automatically**: check whether the previous application
version can run against the new schema before deciding whether a schema
rollback is even needed (most additive migrations are safely
forward-compatible; a rollback that also reverts a migration needs a
human decision, not a scripted one).

## Full database loss

`docs/BACKUP_RESTORE.md` — the rehearsed procedure, including the real
`FORCE ROW LEVEL SECURITY` gotcha it found and the exact commands to
work around it correctly (a dedicated `BYPASSRLS` backup role, never the
application's own credential).

## Secret rotation

1. Update the value in whatever externalizes it in your environment
   (`kubernetes/base/secret.yaml` is an example/dev template — see that
   file's own comment: production should source this from External
   Secrets Operator, Sealed Secrets, or a cloud secret manager, never a
   plain committed Secret manifest).
2. `kubectl rollout restart deployment -n lunatic-siem <affected services>`
   — nothing in this codebase hot-reloads `JWT_SECRET_KEY`,
   `MFA_ENCRYPTION_KEY`, `DATABASE_URL`, `REDIS_URL`, or
   `OPENSEARCH_PASSWORD`; all are read once at process startup
   (`app/core/config.py`'s `Settings`, cached via `lru_cache`).
3. Rotating `JWT_SECRET_KEY` invalidates every outstanding access and
   refresh token immediately — every logged-in user is signed out. This
   is correct behavior for a compromised-secret rotation, not a bug to
   route around; plan the rotation window accordingly.
4. Rotating `MFA_ENCRYPTION_KEY` breaks decryption of already-stored MFA
   TOTP secrets (Fernet has no key-rotation-with-re-encryption built in
   here) — every user with MFA enabled needs to re-enroll. Not something
   to rotate casually; treat it the same as a credential compromise
   response, not routine hygiene.
