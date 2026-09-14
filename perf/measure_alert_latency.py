"""End-to-end alert-generation latency (Phase 18, spec §24): wall-clock
time from "a raw event is submitted" to "an alert for it is visible
through the API" — the number that actually matters to an analyst,
covering the whole ingestion -> parsing -> normalization -> detection ->
alerting path in one measurement rather than summing per-stage histograms.

Uses AUTH-003 ("privileged account authenticated from a non-internal
address", `rules/authentication/privileged_login_external.yml`) because it
is a single-event streaming rule with no window — a match fires on the
event that caused it, not on a scheduled aggregation a minute later, so the
number measured is pipeline latency, not polling-interval artifact.

Run with:  python perf/measure_alert_latency.py [--trials 20] [--host http://localhost:8000]

Requires the full stack running: API, parser worker, indexer worker,
detection worker, alert worker, plus Postgres/Redis/OpenSearch.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
import uuid

import httpx

_PASSWORD = "Correct-Horse-Battery-Staple-1"  # noqa: S105 - synthetic load-test credential, not a secret


async def _register_and_login(client: httpx.AsyncClient, slug: str) -> dict[str, str]:
    resp = await client.post(
        "/auth/register-organization",
        json={
            "organization_name": f"Latency {slug}",
            "organization_slug": slug,
            "admin_email": "admin@example.com",
            "admin_password": _PASSWORD,
            "admin_full_name": "Latency Admin",
        },
    )
    resp.raise_for_status()
    resp = await client.post(
        "/auth/login",
        json={"organization_slug": slug, "email": "admin@example.com", "password": _PASSWORD},
    )
    resp.raise_for_status()
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


async def _create_api_key(client: httpx.AsyncClient, headers: dict[str, str]) -> str:
    resp = await client.post("/api-keys", headers=headers, json={"name": "latency-collector"})
    resp.raise_for_status()
    return str(resp.json()["api_key"])


async def _one_trial(
    client: httpx.AsyncClient, *, api_key: str, headers: dict[str, str], marker: str
) -> float | None:
    """Ingests one AUTH-003-matching event, then polls /alerts until an
    alert carrying `marker` (encoded in the source address's last octet,
    the only part of the payload an analyst-facing field actually
    surfaces) appears. Returns the elapsed seconds, or None on timeout."""
    octets = marker  # a 1-3 digit string, unique per trial within a run
    payload = (
        f"<34>Oct 11 22:14:15 web01 sshd[9999]: Accepted password for admin "
        f"from 203.0.113.{octets} port 4242 ssh2"
    ).encode()

    started = time.perf_counter()
    resp = await client.post(
        "/ingest/events", headers={"X-API-Key": api_key}, content=payload
    )
    resp.raise_for_status()

    deadline = started + 30
    while time.perf_counter() < deadline:
        alerts_resp = await client.get("/alerts", headers=headers)
        alerts_resp.raise_for_status()
        for alert in alerts_resp.json():
            if alert.get("source_ip", "").endswith(f".{octets}"):
                return time.perf_counter() - started
        await asyncio.sleep(0.05)
    return None


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--host", default="http://localhost:8000")
    parser.add_argument("--out", default="perf/results/alert_latency.json")
    args = parser.parse_args()

    async with httpx.AsyncClient(base_url=args.host, timeout=35) as client:
        slug = f"latency{uuid.uuid4().hex[:12]}"
        headers = await _register_and_login(client, slug)
        api_key = await _create_api_key(client, headers)

        latencies: list[float] = []
        timeouts = 0
        for i in range(args.trials):
            marker = str(100 + i)  # 3-digit, unique per trial, valid octet
            elapsed = await _one_trial(client, api_key=api_key, headers=headers, marker=marker)
            if elapsed is None:
                timeouts += 1
                print(f"trial {i}: TIMED OUT (no alert within 30s)")
            else:
                latencies.append(elapsed)
                print(f"trial {i}: {elapsed:.3f}s")

    result = {
        "trials": args.trials,
        "succeeded": len(latencies),
        "timed_out": timeouts,
        "seconds": {
            "min": min(latencies) if latencies else None,
            "p50": statistics.median(latencies) if latencies else None,
            "p95": (
                statistics.quantiles(latencies, n=20)[18]
                if len(latencies) >= 20
                else max(latencies)
                if latencies
                else None
            ),
            "max": max(latencies) if latencies else None,
            "mean": statistics.mean(latencies) if latencies else None,
        },
    }
    print(json.dumps(result, indent=2))

    import pathlib

    out_path = pathlib.Path(args.out)
    await asyncio.to_thread(out_path.parent.mkdir, parents=True, exist_ok=True)
    await asyncio.to_thread(out_path.write_text, json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
