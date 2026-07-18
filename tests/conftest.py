from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.settings import Settings


@pytest.fixture
def app_settings(tmp_path: Path) -> Settings:
    return Settings(
        project_root=Path(__file__).resolve().parents[1],
        env_path=tmp_path / ".env",
        reasoner_mode="mock",
        chat_mode="outbox",
        firewall_mode="in_memory",
        demo_mode=True,
        database_path=tmp_path / "network-agent.db",
        max_ttl_seconds=600,
        default_ttl_seconds=60,
        context_request_timeout_seconds=120,
        dedup_window_seconds=30,
        expiry_poll_seconds=0.1,
    )


@pytest.fixture
def client(app_settings: Settings):
    with TestClient(create_app(app_settings)) as test_client:
        yield test_client

