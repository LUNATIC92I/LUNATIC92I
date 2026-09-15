# Data tier (PostgreSQL / Redis / OpenSearch HA)

Everything here lives in its own `lunatic-data` namespace, never
colocated with the app tier in `lunatic-siem` — see
`kubernetes/base/networkpolicy.yaml` and `networkpolicy.yaml` in this
directory for the NetworkPolicy pair that makes that boundary real
(THREAT_MODEL.md §1), not just a folder convention.

Each store uses a well-established, real operator or Helm chart rather
than hand-rolled failover logic — the same reasoning as using CloudNativePG
instead of writing Postgres replication management from scratch:

| Store | Mechanism | Install |
|---|---|---|
| PostgreSQL | [CloudNativePG](https://cloudnative-pg.io) operator, `Cluster` CR (`postgres-cluster.yaml`) | Operator once, then `kubectl apply -f postgres-cluster.yaml` |
| Redis | [Bitnami redis chart](https://github.com/bitnami/charts/tree/main/bitnami/redis), Sentinel mode (`values-redis-ha.yaml`) | `helm install redis bitnami/redis -n lunatic-data -f values-redis-ha.yaml` |
| OpenSearch | [Official opensearch chart](https://github.com/opensearch-project/helm-charts), 3-node cluster (`values-opensearch-ha.yaml`) | `helm install opensearch opensearch/opensearch -n lunatic-data -f values-opensearch-ha.yaml` |

## Setup order

```bash
kubectl apply -f namespace.yaml
kubectl apply -f networkpolicy.yaml

# PostgreSQL
kubectl apply --server-side -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.24/releases/cnpg-1.24.1.yaml
# fill in postgres-app-credentials / postgres-backup-credentials secrets
# in postgres-cluster.yaml with real values first
kubectl apply -f postgres-cluster.yaml

# Redis
helm repo add bitnami https://charts.bitnami.com/bitnami
kubectl create secret generic redis-auth -n lunatic-data --from-literal=password='REPLACE-ME'
helm install redis bitnami/redis -n lunatic-data -f values-redis-ha.yaml

# OpenSearch
helm repo add opensearch https://opensearch-project.github.io/helm-charts
helm install opensearch opensearch/opensearch -n lunatic-data -f values-opensearch-ha.yaml
```

Then deploy the app tier (`kubernetes/base/`) — its ConfigMap/Secret
already reference the exact Service names these three produce
(`postgres-rw`, `redis-master`, `opensearch-cluster-master`).

## Redis failover is transparent to the app

Sentinel mode here delivers real automatic master promotion, and the
application follows it automatically too: set `REDIS_SENTINEL_HOSTS`
(comma-separated `host:port` Sentinel addresses — the `redis-sentinel`
Service this chart creates) and `REDIS_SENTINEL_SERVICE_NAME` (the
`masterSet` value below, `mymaster`) on every backend deployment.
`app/core/redis.py::build_redis_client()` then builds every Redis
client — `RedisStreamsEventBus` (`backend/app/core/eventbus.py`)
included — through redis-py's own `Sentinel` class instead of a bare
`redis.asyncio.from_url()`, which re-resolves the current master on
every command rather than remembering whichever pod was master when the
process started. Verified directly, not just by reading redis-py's
source: a real local Redis+Sentinel cluster, the actual master container
killed mid-run, the same client continuing to serve requests against the
promoted replica once Sentinel's own detection window elapsed, with data
written both before and after the kill confirmed present. See
`values-redis-ha.yaml`'s own header comment for the full detail.

## Backups

CloudNativePG's own `backup:` block in `postgres-cluster.yaml` handles
continuous WAL archiving and base backups to object storage — point
`destinationPath` at a real bucket before relying on it. Redis and
OpenSearch persistence here is replication-based (surviving node loss),
not point-in-time backup; add scheduled snapshots (`redis-cli --rdb` /
OpenSearch snapshot repository) per your environment's actual recovery
objectives before calling this production-ready (Phase 20's own
acceptance criteria cover exactly this).
