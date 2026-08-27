from datetime import UTC, datetime
from uuid import UUID

from app.main import app
from app.routes.deps import get_current_user_id


def test_assets_list_route_returns_filtered_assets(client, monkeypatch):
    app_user_id = "33333333-3333-3333-3333-333333333333"
    app_created = datetime(2026, 4, 20, tzinfo=UTC)
    app.dependency_overrides[get_current_user_id] = lambda: app_user_id

    def fake_list_assets(**kwargs):
        assert kwargs["owner_id"] == app_user_id
        assert kwargs["search"] == "api"
        return {
            "items": [
                {
                    "id": UUID("44444444-4444-4444-4444-444444444444"),
                    "name": "Public API",
                    "target": "api.example.com",
                    "ip_address": "10.0.0.10",
                    "hostname": "api.example.com",
                    "mac_address": None,
                    "asset_type": "api",
                    "status": "active",
                    "criticality": "high",
                    "discovery_status": "up",
                    "last_scan_status": "completed",
                    "last_scan_progress": 100,
                    "last_scanned_at": app_created,
                    "updated_at": app_created,
                }
            ],
            "total": 1,
            "limit": 25,
            "offset": 0,
        }

    monkeypatch.setattr("app.routes.assets.list_assets", fake_list_assets)

    response = client.get("/api/assets?search=api&asset_type=api")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["asset_type"] == "api"
    assert payload["items"][0]["last_scan_status"] == "completed"


def test_discover_route_returns_devices(client, monkeypatch):
    app.dependency_overrides[get_current_user_id] = lambda: "33333333-3333-3333-3333-333333333333"

    def fake_discover_assets(**kwargs):
        assert kwargs["cidr"] == "10.0.0.0/24"
        return [
            {"ip": "10.0.0.10", "hostname": "host-one", "mac": "aa:bb:cc:dd:ee:ff", "status": "up"},
        ]

    monkeypatch.setattr("app.routes.assets.discover_assets", fake_discover_assets)

    response = client.post("/api/assets/discover", json={"cidr": "10.0.0.0/24"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["discovered_count"] == 1
    assert payload["devices"][0]["ip"] == "10.0.0.10"
