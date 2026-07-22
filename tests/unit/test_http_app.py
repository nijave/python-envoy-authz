from fastapi.testclient import TestClient

from envoy_authz.http_app import create_app


def test_healthz_returns_ok():
    client = TestClient(create_app())
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_create_app_returns_distinct_instances():
    assert create_app() is not create_app()
