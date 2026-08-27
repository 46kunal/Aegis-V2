from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.core.database import Base
from app.main import app


@pytest.fixture(autouse=True)
def clear_dependency_overrides() -> Generator[None, None, None]:
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)
