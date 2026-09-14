# Kubernetes manifests

Kubernetes manifests for production deployment (Phase 19):

- `base/` — the app tier as a Kustomize base: Deployments, Services,
  HorizontalPodAutoscalers, PodDisruptionBudgets, NetworkPolicies
  (enforcing the trust boundaries in `THREAT_MODEL.md` §1), and an
  Ingress for the API and frontend.
- `data-tier/` — HA PostgreSQL (CloudNativePG), Redis (Sentinel), and
  OpenSearch (3-node cluster), each with its own README covering install
  order and known gaps.

See `docs/KUBERNETES.md` for the full picture: deployment instructions,
horizontal-scaling correctness per workload, health checks and graceful
shutdown, retry/circuit-breaker policies, the NetworkPolicy security
review, and a real chaos/failure-injection test run against the live
system (not simulated) with its exact numbers.
