# Kubernetes / High Availability (Phase 19)

Manifests live in `kubernetes/`:

- `kubernetes/base/` — the app tier (API, 6 pipeline workers, frontend),
  as a Kustomize base. Deploy with:
  ```bash
  kubectl kustomize --load-restrictor=LoadRestrictionsNone kubernetes/base | kubectl apply -f -
  ```
  The `--load-restrictor` flag is required because the rule pack and
  playbook pack are generated from `rules/` and `playbooks/` at the repo
  root — siblings of `kubernetes/`, not descendants — and Kustomize's
  default sandboxing refuses to read files outside the kustomization's own
  directory tree. This is Kustomize's documented, standard escape hatch
  for exactly this layout, not a workaround for a mistake.
- `kubernetes/data-tier/` — PostgreSQL (CloudNativePG), Redis (Bitnami
  chart, Sentinel mode) and OpenSearch (official chart, 3-node cluster),
  each in their own `lunatic-data` namespace. See that directory's own
  `README.md` for install order. A Sentinel-promoted master is followed
  transparently by every backend Redis client (`REDIS_SENTINEL_HOSTS`,
  `app/core/redis.py::build_redis_client()`) — no manual worker restart
  needed after a failover.

Before applying either, fill in the real values in
`kubernetes/base/secret.yaml` and `kubernetes/data-tier/postgres-cluster.yaml`
— every `REPLACE-ME` in those two files is a placeholder, the same
convention as `.env.example`. Point `images:` in
`kubernetes/base/kustomization.yaml` at your actual registry and tag.

All 38 app-tier resources validate cleanly against the real Kubernetes
1.32 API schemas offline (`kubeconform -kubernetes-version 1.32.0
-strict`, no live cluster needed) — checked as part of this phase's
validation gate, not just asserted.

## What "all services" means here

| Workload | Replicas | Why |
|---|---|---|
| `api` | 2, HPA 2–6 | Public-facing; zero-downtime rollout (`maxUnavailable: 0`) |
| `parser`, `indexer`, `detection`, `correlation`, `alerting` | 2, HPA 2–6/8 | Each scales via its own Redis Streams consumer group — see "Horizontal scaling correctness" below |
| `feeds` | 1, fixed | Timer-driven, not consumer-group-driven; see the comment in `deployment-feeds.yaml` for why >1 replica would just duplicate outbound fetches, not add capacity |
| `frontend` | 2 | Static nginx, trivially horizontal |

## Horizontal scaling correctness

Parser/indexer/detection/correlation/alerting all consume from Redis
Streams consumer groups (`app/core/eventbus.py`), so N replicas is
"N members of one group" — each message still goes to exactly one
replica, by construction, not by convention.

The detection worker's **windowed** (threshold) rule path is not
consumer-group-driven — every replica independently evaluates every
active tenant's windowed rules on its own timer
(`app/workers/detection_worker.py`'s `WindowedScheduler`). This is still
safe to scale because every windowed rule in the shipped pack sets
`suppression_seconds > 0`; when two replicas compute the same match in
the same instant, only the one that wins the atomic Redis suppression
claim (`app/detection/windowed.py`) publishes it. This is asserted, not
assumed — see the comment block at the top of
`kubernetes/base/deployment-detection.yaml`. A future windowed rule
authored with `suppression_seconds == 0` would double-fire under >1
replica; the rule schema doesn't currently forbid that combination, which
is worth tightening if custom windowed rules become common.

**Resolved.** Every worker's consumer name used to default to a
hardcoded literal (`"parser-1"`, `"detection-1"`, etc.), so two replicas
of the same worker shared one logical Redis Streams consumer name. This
never broke the no-data-loss guarantee — `claim_stale()`'s reclaim is
keyed by idle-time, not by which physical process a name used to belong
to, so a crashed replica's orphaned pending entries were always recovered
by the survivor(s) regardless (confirmed directly, see "Chaos test"
below) — but it did mean `XINFO CONSUMERS` couldn't distinguish which pod
was doing the work. Fixed: `app/core/eventbus.py::consumer_identity()`
derives the name from `HOSTNAME` (which Kubernetes sets to the pod name
for every pod, no extra wiring), falling back to the old literal only
when `HOSTNAME` is unset. Every worker's `run()`/`build()` now passes
this explicitly (`app/tests/test_eventbus.py` covers both branches).

## Health checks and graceful shutdown

Every container's `livenessProbe`/`readinessProbe` targets the same
`/health` and `/ready` endpoints Phase 16 built
(`docs/OBSERVABILITY.md`) — on the API's public port for `api`, on the
internal metrics port for every worker. `readinessProbe` failing pulls a
pod out of its Service/consumer rotation without killing it;
`livenessProbe` failing restarts it. Nothing new was built for
Kubernetes here — Phase 16's health model was already the right shape
for a cluster and this phase just wires it into probes.

Graceful shutdown is likewise already real, not added for this phase:
every worker's `run()` installs `SIGTERM`/`SIGINT` handlers that set a
`stop` `asyncio.Event`, finishing the message currently in flight before
exiting cleanly (`app/workers/*.py`). `terminationGracePeriodSeconds: 30`
in every Deployment gives that loop real time to land before Kubernetes
escalates to `SIGKILL`. Anything still unacked at that point — a
harder crash, not a graceful one — is exactly what the reclaim sweep
below exists for.

## Retry / circuit-breaker policies

| Layer | Mechanism | Where |
|---|---|---|
| Redis Streams delivery | At-least-once: unacked messages are reclaimed by `claim_stale()` (`XAUTOCLAIM`), never silently dropped | `app/core/eventbus.py`, every worker's periodic reclaim loop |
| Redis client transport | Explicit `socket_timeout` wider than the subscribe block window — the Phase 18 fix that stopped workers crashing on any 5+s quiet period | `app/core/eventbus.py::RedisStreamsEventBus.__init__` |
| Malformed/unprocessable events | Dead-lettered (`dead_letter()`) rather than retried forever — a retry loop on a message that can never succeed is not resilience, it's a stuck pipeline | `app/core/eventbus.py`, every worker's `_reject`/`dead_letter` path |
| OpenSearch writes | `opensearch-py`'s built-in connection-level retry (`max_retries`, `retry_on_timeout`) on the client used by indexer/detection | `app/core/opensearch.py` |
| Outbound feed/webhook calls | Egress guard fails closed on an unconfigured/disallowed host (THREAT_MODEL.md §3.8) — the correct "circuit breaker" for calls to hosts we don't control is refusing them by default, not retrying a call that should never have been attempted | `app/core/egress.py` |
| Kubernetes-level | `restartPolicy: Always` (Deployment default) + liveness probes restart a wedged process; readiness probes remove an unhealthy replica from rotation without an actual restart, the cheaper first line of defense | every Deployment in `kubernetes/base/` |
| Database writes | No custom retry: a failed transaction surfaces as a 5xx / dead-lettered event rather than silently retrying with partial state — correct for a system where "definitely happened once" matters more than "eventually happened" | SQLAlchemy sessions, `app/core/db.py` |

Nothing here is a generic "wrap every call in exponential backoff"
policy — retrying is the right answer exactly where a failure is
transient (a network blip, an idle Redis connection reaped by a
timeout) and the wrong answer everywhere a failure means the input
itself cannot succeed (malformed event, disallowed egress host).

## NetworkPolicies (security review)

`kubernetes/base/networkpolicy.yaml` and
`kubernetes/data-tier/networkpolicy.yaml` together enforce
THREAT_MODEL.md §1's trust boundary as two namespaces rather than a
label convention within one:

- `lunatic-siem` (app tier) and `lunatic-data` (data tier) both
  default-deny everything, then allow only the specific paths the
  platform actually uses.
- The data tier accepts ingress **only** from pods carrying
  `app.kubernetes.io/part-of: lunatic-siem` inside the `lunatic-siem`
  namespace specifically — not "anything in any namespace," not "anything
  with a matching label regardless of namespace." A compromised pod in
  an unrelated namespace, even one that somehow acquired the same label,
  cannot reach Postgres/Redis/OpenSearch: the `namespaceSelector` and
  `podSelector` in `allow-ingress-from-app-tier` are both required to
  match (`NetworkPolicy` ANDs multiple selectors within one `from` entry).
- The data tier has no path to the public internet at all — not even
  DNS beyond what its own service discovery needs — and never initiates
  connections to the app tier.
- Outbound internet access (threat-intel feeds, MITRE bundle, playbook
  webhooks) is scoped to exactly the two workloads that need it (`api`,
  `feeds`) and to public IP space only (an `ipBlock` excluding RFC1918
  ranges), never to another pod in the cluster. The specific *hosts*
  reachable within that are enforced at the application layer
  (`app/core/egress.py`'s allow-list, fail-closed) since that's
  per-tenant runtime configuration a static NetworkPolicy cannot express
  — this NetworkPolicy is the outer perimeter, the egress guard is the
  actual allow-list.

## Chaos / failure-injection test

The spec calls for killing a backend pod, an OpenSearch node, and a
Redis node under real Kubernetes and observing graceful degradation with
no data loss. That could not be run as literally specified in this
sandboxed session: `kind` (the standard way to get a throwaway real
Kubernetes cluster for exactly this kind of test) requires nesting a
second container runtime inside this session's own container, and that
failed at the innermost layer —
`runc create failed: unable to start container process: can't get final
child's PID from pipe: EOF` — a sandbox restriction on nested container
runtimes, not anything about these manifests. `kubeconform` and
`kubectl kustomize` (both used above) don't need a live cluster and were
run for exactly that reason; a true multi-node pod-eviction test still
needs a real cluster (or a less nested CI runner) before this can be
called verified end-to-end.

What **was** run, for real, against the actual running system rather
than skipped: the specific mechanism a Kubernetes Deployment's pod
restart relies on for "no data loss" — the EventBus's own crash-recovery
guarantee (`app/core/eventbus.py`'s `claim_stale`/reclaim sweep,
Phase 3's DLQ design) — exercised with the real Docker images, the real
`app.workers.parser_worker` code, and a real `docker compose kill -s
SIGKILL` against a live container, no mocks:

1. Published 500, then a further 50,000, raw events onto the real
   `events.raw` Redis Stream (50,500 total) via the real `EventBus`
   publish path.
2. Started one parser worker container, polled it until it was
   provably mid-batch (500 of 50,000 processed), then `SIGKILL`ed it —
   no graceful shutdown, the worst case the reclaim mechanism exists for.
   Result: **6 messages left claimed-but-unacked** (`XPENDING` confirmed
   this precisely).
3. Started a second, independent parser worker container (standing in
   for "Kubernetes scheduled a replacement pod" — no state shared with
   the first beyond what's in Redis).
4. That second worker drained all newly-undelivered messages within
   ~30 seconds on its own, with the 6 orphaned ones sitting untouched
   (correctly — they're below the reclaim's `min_idle_ms` threshold and
   still technically "owned" by the dead worker's consumer identity).
5. At the 120-second idle mark, the survivor's own periodic reclaim
   sweep (`RECLAIM_INTERVAL_SECONDS = 60`, `RECLAIM_MIN_IDLE_MS =
   120_000` in `app/workers/parser_worker.py`) fired automatically —
   no manual intervention, no restart — and reclaimed and reprocessed
   all 6.
6. **Final state: `events.raw.deadletter` = 0, pending = 0,
   `events.normalized` = 50,501** — one more than the 50,500 published.
   That +1 is the documented at-least-once tradeoff this codebase already
   states elsewhere (`app/workers/detection_worker.py`'s own docstring:
   "A crash between publishing and acking replays the event, which can
   duplicate... deliberately preferred over the alternative"): one of
   the 6 orphaned messages had already been published to
   `events.normalized` by the dying worker moments before the
   `SIGKILL`, just not yet acked, so the reclaiming worker reprocessed
   and republished it too. **Zero events were lost. Zero were
   dead-lettered. One was duplicated, exactly as designed, at a rate of
   1-in-50,500 under a hard kill mid-batch.**

This is the actual guarantee "kill a pod, no data loss" cashes out to at
the code level, verified directly rather than assumed because the
manifests say `replicas: 2`. The one item this test surfaced — the
shared hardcoded consumer name across replicas — is called out above
under "Horizontal scaling correctness" and has since been fixed
(`consumer_identity()`), not left as a standing gap.

## Load balancer

`kubernetes/base/ingress.yaml` fronts `api` and `frontend` (any
conformant Ingress controller; annotations shown are ingress-nginx's).
TLS termination and real hostnames are deployment-specific and left for
an overlay — this base intentionally ships no certificates.
