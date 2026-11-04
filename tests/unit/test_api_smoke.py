"""Application stack smoke test: the API factory starts and answers liveness."""

from fastapi.testclient import TestClient

from policyops.api.app import create_app


def test_liveness_reports_ok_without_configuration_details() -> None:
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_routes_are_served_only_under_the_versioned_prefix() -> None:
    with TestClient(create_app()) as client:
        assert client.get("/health/live").status_code == 404
