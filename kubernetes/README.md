# Kubernetes manifests

Kubernetes manifests / Helm chart for production deployment: Deployments,
Services, HorizontalPodAutoscalers, NetworkPolicies (enforcing the trust
boundaries in `THREAT_MODEL.md` §1), and StatefulSet/operator configuration
for PostgreSQL, Redis, and OpenSearch HA.

Populated in Phase 19 (HA / Kubernetes) once the Docker Compose stack
(Phase 1) and the application itself (Phases 2–18) are complete — see
`docs/DEVELOPMENT_PLAN.md` (Phase 19) for acceptance criteria. Building this
out earlier would be premature: there is no HA behavior to encode yet.
