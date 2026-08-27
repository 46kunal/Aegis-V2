from datetime import UTC, datetime
from uuid import UUID

from app.core.database import get_db
from app.main import app
from app.routes.deps import get_current_user_id


class FakeScan:
    def __init__(self):
        self.id = UUID("55555555-5555-5555-5555-555555555555")
        self.asset_id = UUID("66666666-6666-6666-6666-666666666666")
        self.mode = type("Mode", (), {"value": "fast"})()
        self.status = type("Status", (), {"value": "queued"})()
        self.created_at = datetime(2026, 4, 20, tzinfo=UTC)


class FakeTask:
    id = "task-123"


class FakeDatabase:
    def commit(self):
        return None

    def refresh(self, instance):
        return None


def override_db():
    return FakeDatabase()


def test_scan_start_route_queues_job(client, monkeypatch):
    app_user_id = "77777777-7777-7777-7777-777777777777"
    app.dependency_overrides[get_current_user_id] = lambda: app_user_id
    app.dependency_overrides[get_db] = override_db

    fake_scan = FakeScan()

    def fake_create_scan_job(**kwargs):
        assert kwargs["owner_id"] == app_user_id
        assert kwargs["mode"] == "fast"
        return fake_scan

    monkeypatch.setattr("app.routes.scans.create_scan_job", fake_create_scan_job)
    monkeypatch.setattr("app.routes.scans.execute_scan.delay", lambda scan_id: FakeTask())

    response = client.post(
        "/api/scans/start",
        json={"asset_id": str(fake_scan.asset_id), "mode": "fast"},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["scan_id"] == str(fake_scan.id)
    assert payload["task_id"] == "task-123"


def test_scan_start_route_returns_503_when_queue_unavailable(client, monkeypatch):
    app_user_id = "77777777-7777-7777-7777-777777777777"
    app.dependency_overrides[get_current_user_id] = lambda: app_user_id
    app.dependency_overrides[get_db] = override_db

    fake_scan = FakeScan()
    mark_failed_calls: dict[str, str] = {}

    def fake_create_scan_job(**kwargs):
        return fake_scan

    def fake_mark_scan_failed(**kwargs):
        mark_failed_calls["error_message"] = kwargs["error_message"]

    def fake_delay(_scan_id: str):
        raise RuntimeError("redis unavailable")

    monkeypatch.setattr("app.routes.scans.create_scan_job", fake_create_scan_job)
    monkeypatch.setattr("app.routes.scans.mark_scan_failed", fake_mark_scan_failed)
    monkeypatch.setattr("app.routes.scans.execute_scan.delay", fake_delay)

    response = client.post(
        "/api/scans/start",
        json={"asset_id": str(fake_scan.asset_id), "mode": "fast"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "Scan queue is unavailable"
    assert mark_failed_calls["error_message"] == "Scan queue is unavailable"


def test_scan_list_route_returns_items(client, monkeypatch):
    app.dependency_overrides[get_current_user_id] = lambda: "77777777-7777-7777-7777-777777777777"
    app.dependency_overrides[get_db] = override_db

    def fake_list_scan_jobs(**kwargs):
        return {
            "items": [
                {
                    "scan_id": UUID("88888888-8888-8888-8888-888888888888"),
                    "asset_id": UUID("99999999-9999-9999-9999-999999999999"),
                    "asset_name": "Edge Router",
                    "asset_target": "10.0.0.1",
                    "mode": "full",
                    "status": "running",
                    "progress": 55,
                    "summary": "Scanning ports",
                    "error_message": None,
                    "finding_count": 4,
                    "critical_finding_count": 1,
                    "latest_report_id": None,
                    "created_at": datetime(2026, 4, 20, tzinfo=UTC),
                    "started_at": datetime(2026, 4, 20, tzinfo=UTC),
                    "completed_at": None,
                }
            ],
            "total": 1,
            "limit": 50,
            "offset": 0,
        }

    monkeypatch.setattr("app.routes.scans.list_scan_jobs", fake_list_scan_jobs)

    response = client.get("/api/scans")

    assert response.status_code == 200
    payload = response.json()
    assert payload["items"][0]["status"] == "running"
    assert payload["items"][0]["finding_count"] == 4


def test_scan_detail_route_returns_findings(client, monkeypatch):
    app.dependency_overrides[get_current_user_id] = lambda: "77777777-7777-7777-7777-777777777777"
    app.dependency_overrides[get_db] = override_db

    def fake_get_scan_job_detail(**kwargs):
        return {
            "scan_id": UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            "asset_id": UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            "asset_name": "Database",
            "asset_target": "10.0.0.20",
            "mode": "medium",
            "status": "completed",
            "progress": 100,
            "summary": "Completed successfully",
            "error_message": None,
            "finding_count": 2,
            "critical_finding_count": 1,
            "latest_report_id": UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            "created_at": datetime(2026, 4, 20, tzinfo=UTC),
            "started_at": datetime(2026, 4, 20, tzinfo=UTC),
            "completed_at": datetime(2026, 4, 20, tzinfo=UTC),
            "findings": [
                {
                    "id": UUID("dddddddd-dddd-dddd-dddd-dddddddddddd"),
                    "title": "Open SSH",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "created_at": datetime(2026, 4, 20, tzinfo=UTC),
                }
            ],
        }

    monkeypatch.setattr("app.routes.scans.get_scan_job_detail", fake_get_scan_job_detail)

    response = client.get("/api/scans/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["findings"][0]["title"] == "Open SSH"


def test_scan_retry_route_requeues_failed_scan(client, monkeypatch):
    app_user_id = "77777777-7777-7777-7777-777777777777"
    app.dependency_overrides[get_current_user_id] = lambda: app_user_id
    app.dependency_overrides[get_db] = override_db

    fake_scan = FakeScan()
    fake_scan.status = type("Status", (), {"value": "queued"})()

    def fake_retry_scan_job(**kwargs):
        assert kwargs["owner_id"] == app_user_id
        return fake_scan

    monkeypatch.setattr("app.routes.scans.retry_scan_job", fake_retry_scan_job)
    monkeypatch.setattr("app.routes.scans.execute_scan.delay", lambda scan_id: FakeTask())

    response = client.post("/api/scans/55555555-5555-5555-5555-555555555555/retry")

    assert response.status_code == 202
    payload = response.json()
    assert payload["task_id"] == "task-123"
