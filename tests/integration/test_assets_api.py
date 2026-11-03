
import pytest

from fastapi.testclient import TestClient

from vulnx.api.main import app


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def asset_payload():
    return {
        "asset_name": "VulnX-Test-Machine",
        "software_name": "TestSoftware",
        "software_version": "1.0",
        "vendor": "TestVendor",
        "operating_system": "Pop!_OS",
        "asset_type": "software",
        "description": "Automated API testing"
    }


def test_create_asset(client, asset_payload):
    response = client.post(
        "/api/v1/assets/",
        json=asset_payload
    )

    assert response.status_code == 201
    assert response.json()["software_name"] == "TestSoftware"


def test_get_assets(client):
    response = client.get("/api/v1/assets/")

    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_nonexistent_asset(client):
    response = client.get("/api/v1/assets/999999")

    assert response.status_code == 404


def test_update_asset(client, asset_payload):
    create_response = client.post(
        "/api/v1/assets/",
        json=asset_payload
    )

    asset_id = create_response.json()["id"]

    update_response = client.put(
        f"/api/v1/assets/{asset_id}",
        json={"software_version": "2.0"}
    )

    assert update_response.status_code == 200
    assert update_response.json()["software_version"] == "2.0"


def test_delete_asset(client, asset_payload):
    create_response = client.post(
        "/api/v1/assets/",
        json=asset_payload
    )

    asset_id = create_response.json()["id"]

    delete_response = client.delete(
        f"/api/v1/assets/{asset_id}"
    )

    assert delete_response.status_code == 204

    verify_response = client.get(
        f"/api/v1/assets/{asset_id}"
    )

    assert verify_response.status_code == 404


def test_invalid_asset(client):
    response = client.post(
        "/api/v1/assets/",
        json={
            "asset_name": "",
            "software_name": "",
            "software_version": ""
        }
    )

    assert response.status_code == 422
