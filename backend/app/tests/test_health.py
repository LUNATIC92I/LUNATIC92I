from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_metrics_exposes_prometheus_format() -> None:
    client.get("/health")  # ensure at least one sample exists before scraping
    response = client.get("/metrics")
    assert response.status_code == 200
    assert "api_requests_total" in response.text
