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

## Known gap: Redis failover is not yet fully transparent to the app

Sentinel mode here delivers real automatic master promotion. What it does
NOT yet deliver on its own is the application noticing a promotion
happened: `RedisStreamsEventBus` (`backend/app/core/eventbus.py`) opens a
single `redis://` connection via `redis.asyncio.from_url()`, which has no
Sentinel-awareness — after a failover it keeps addressing the pod that
used to be master. This is called out in detail at the top of
`values-redis-ha.yaml` along with the two ways to close it (a
failover-aware proxy in front of Redis, or making `RedisStreamsEventBus`
build its client through redis-py's `Sentinel` class instead of a bare
URL). Recorded here rather than glossed over, because "Redis HA" as
shipped in this phase means the store recovers on its own — it does not
yet mean the app reconnects to the new master without a restart.

## Backups

CloudNativePG's own `backup:` block in `postgres-cluster.yaml` handles
continuous WAL archiving and base backups to object storage — point
`destinationPath` at a real bucket before relying on it. Redis and
OpenSearch persistence here is replication-based (surviving node loss),
not point-in-time backup; add scheduled snapshots (`redis-cli --rdb` /
OpenSearch snapshot repository) per your environment's actual recovery
objectives before calling this production-ready (Phase 20's own
acceptance criteria cover exactly this).
