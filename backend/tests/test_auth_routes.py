from datetime import UTC, datetime
from uuid import UUID

from app.main import app
from app.routes.deps import get_current_user_id


def test_register_route_returns_auth_payload(client, monkeypatch):
    created_at = datetime(2026, 4, 20, tzinfo=UTC)

    def fake_register_user(**kwargs):
        assert kwargs["email"] == "alice@example.com"
        assert kwargs["full_name"] == "Alice Example"
        assert kwargs["password"] == "StrongPass123!"
        assert kwargs["role"] == "user"
        return {
            "user": {
                "id": "11111111-1111-1111-1111-111111111111",
                "email": "alice@example.com",
                "full_name": "Alice Example",
                "role": "user",
                "is_active": True,
                "created_at": created_at,
            },
            "tokens": {
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "token_type": "bearer",
            },
        }

    monkeypatch.setattr("app.routes.auth.register_user", fake_register_user)

    response = client.post(
        "/api/auth/register",
        json={
            "email": "alice@example.com",
            "full_name": "Alice Example",
            "password": "StrongPass123!",
            "role": "user",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["user"]["email"] == "alice@example.com"
    assert payload["tokens"]["access_token"] == "access-token"


def test_login_route_returns_unauthorized_on_service_error(client, monkeypatch):
    class FakeAuthError(Exception):
        pass

    def fake_login_user(**kwargs):
        raise FakeAuthError("Invalid credentials")

    monkeypatch.setattr("app.routes.auth.login_user", fake_login_user)
    monkeypatch.setattr("app.routes.auth.AuthError", FakeAuthError)

    response = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_me_route_returns_profile(client, monkeypatch):
    created_at = datetime(2026, 4, 20, tzinfo=UTC)

    app.dependency_overrides[get_current_user_id] = lambda: "22222222-2222-2222-2222-222222222222"

    def fake_profile(**kwargs):
        assert kwargs["user_id"] == "22222222-2222-2222-2222-222222222222"
        return {
            "id": "22222222-2222-2222-2222-222222222222",
            "email": "ops@example.com",
            "full_name": "Ops Lead",
            "role": "admin",
            "is_active": True,
            "created_at": created_at,
        }

    monkeypatch.setattr("app.routes.auth.get_current_user_profile", fake_profile)

    response = client.get("/api/auth/me")

    assert response.status_code == 200
    payload = response.json()
    assert payload["email"] == "ops@example.com"
    assert payload["role"] == "admin"
