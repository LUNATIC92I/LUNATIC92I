"""Load test harness (Phase 18, spec §24): ingestion throughput, API
latency, and query latency, driven against the real running stack — no
mocks, no in-process shortcuts. Every simulated user registers its own
throwaway tenant in `on_start`, so runs are safe to repeat and never touch
shared or production data.

Run with:  locust -f perf/locustfile.py --host http://localhost:8000

See perf/README.md for the full set of scenarios (this file covers
IngestionUser and ApiReadUser; `perf/measure_alert_latency.py` is a
separate, non-Locust script for end-to-end alert-generation latency, which
is a single measured value per trial rather than a load pattern).
"""

import random
import uuid

from locust import HttpUser, between, task

_PASSWORD = "Correct-Horse-Battery-Staple-1"  # noqa: S105 - synthetic load-test credential, not a secret


def _register(client, *, slug: str) -> None:
    resp = client.post(
        "/auth/register-organization",
        json={
            "organization_name": f"Perf {slug}",
            "organization_slug": slug,
            "admin_email": "admin@example.com",
            "admin_password": _PASSWORD,
            "admin_full_name": "Perf Admin",
        },
        name="/auth/register-organization",
    )
    resp.raise_for_status()


def _login(client, *, slug: str) -> dict[str, str]:
    resp = client.post(
        "/auth/login",
        json={"organization_slug": slug, "email": "admin@example.com", "password": _PASSWORD},
        name="/auth/login",
    )
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class IngestionUser(HttpUser):
    """Measures ingestion throughput: each request is a unique raw event
    through the real `/ingest/events` path (API-key auth, rate limiting,
    idempotency claim, event-bus publish) — the same code path a real
    collector uses, not a shortcut into the service layer."""

    weight = 3
    wait_time = between(0, 0.05)

    def on_start(self) -> None:
        slug = f"perfingest{uuid.uuid4().hex[:12]}"
        _register(self.client, slug=slug)
        headers = _login(self.client, slug=slug)
        key_resp = self.client.post(
            "/api-keys", headers=headers, json={"name": "perf-collector"}
        )
        key_resp.raise_for_status()
        self.api_key = key_resp.json()["api_key"]
        self._sequence = 0

    @task
    def ingest_one_event(self) -> None:
        self._sequence += 1
        payload = (
            f"<34>Oct 11 22:14:15 web{self._sequence % 50:03d} sshd[{self._sequence}]: "
            f"Failed password for user{self._sequence % 200} from "
            f"10.{self._sequence % 250}.{(self._sequence // 250) % 250}.1"
        ).encode()
        self.client.post(
            "/ingest/events",
            headers={"X-API-Key": self.api_key},
            data=payload,
            name="/ingest/events",
        )


class ApiReadUser(HttpUser):
    """Measures API and query latency across the read paths an analyst's
    dashboard actually calls, under concurrent load."""

    weight = 1
    wait_time = between(0.1, 0.5)

    def on_start(self) -> None:
        slug = f"perfread{uuid.uuid4().hex[:12]}"
        _register(self.client, slug=slug)
        self.headers = _login(self.client, slug=slug)
        # A handful of incidents so list/detail/search have something real
        # to return rather than measuring the latency of an empty table.
        for i in range(5):
            self.client.post(
                "/incidents",
                headers=self.headers,
                json={
                    "title": f"perf incident {i}",
                    "description": "synthetic load-test data",
                    "severity": random.choice(["low", "medium", "high"]),  # noqa: S311 - synthetic data, not crypto
                },
                name="/incidents [seed]",
            )

    @task(3)
    def list_incidents(self) -> None:
        self.client.get("/incidents", headers=self.headers, name="/incidents")

    @task(3)
    def list_alerts(self) -> None:
        self.client.get("/alerts", headers=self.headers, name="/alerts")

    @task(2)
    def hunt_search(self) -> None:
        self.client.post(
            "/hunting/search",
            headers=self.headers,
            json={"free_text": "perf"},
            name="/hunting/search",
        )

    @task(1)
    def me(self) -> None:
        self.client.get("/users/me", headers=self.headers, name="/users/me")
