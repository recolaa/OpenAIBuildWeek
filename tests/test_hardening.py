from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from app.main import build_container, create_app
from app.reasoners import ReasonerError, create_mock_reasoner
from app.settings import Settings
from tests.helpers import decision_for, drop_payload


class FailingReasoner:
    async def analyze(self, evidence, *, event_type):  # type: ignore[no-untyped-def]
        raise ReasonerError("simulated provider outage")


class BlockingReasoner:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.delegate = create_mock_reasoner()

    async def analyze(self, evidence, *, event_type):  # type: ignore[no-untyped-def]
        self.started.set()
        await self.release.wait()
        return await self.delegate.analyze(evidence, event_type=event_type)


def test_reasoner_failure_never_offers_a_temporary_change(client: TestClient) -> None:
    client.app.state.container.network_agent.reasoner = FailingReasoner()

    incident = client.post(
        "/events/drop", json=drop_payload("drop-reasoner-failure")
    ).json()

    assert incident["last_error_code"] == "REASONER_UNAVAILABLE"
    assert incident["context_request"]["allowed_responses"] == [
        "KEEP_CURRENT_POLICY",
        "REQUEST_MORE_INFORMATION",
    ]
    assert client.get("/readyz").status_code == 503


def test_authorization_question_matches_enforceable_scope(client: TestClient) -> None:
    incident = client.post(
        "/events/drop", json=drop_payload("drop-question-scope")
    ).json()
    question = incident["context_request"]["question"]

    assert "10.0.2.1" in question
    assert "10.0.3.10:443/tcp" in question
    assert "source port 51842 is evidence only" in question


def test_decision_issued_before_request_is_rejected(client: TestClient) -> None:
    incident = client.post(
        "/events/drop", json=drop_payload("drop-stale-decision")
    ).json()
    decision = decision_for(incident, decision_id="decision-issued-too-early")
    decision["issued_at"] = (
        datetime.now(UTC) - timedelta(minutes=10)
    ).isoformat()

    result = client.post("/decisions", json=decision).json()

    assert result["status"] == "REJECTED"
    assert result["reason_code"] == "REQUEST_EXPIRED"


def test_configured_integration_token_protects_inputs(
    app_settings: Settings,
) -> None:
    token = "test-integration-token-12345"
    protected = replace(app_settings, integration_api_token=token)
    with TestClient(create_app(protected)) as protected_client:
        payload = drop_payload("drop-authenticated")
        assert protected_client.post("/events/drop", json=payload).status_code == 401
        response = protected_client.post(
            "/events/drop",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200


def test_network_credential_cannot_submit_chat_decision(
    app_settings: Settings,
) -> None:
    network_token = "network-source-token-12345"
    chat_token = "chat-agent-token-67890123"
    protected = replace(
        app_settings,
        network_ingest_token=network_token,
        chat_integration_token=chat_token,
    )
    network_headers = {"Authorization": f"Bearer {network_token}"}
    chat_headers = {"Authorization": f"Bearer {chat_token}"}
    with TestClient(create_app(protected)) as protected_client:
        incident_response = protected_client.post(
            "/events/drop",
            json=drop_payload("drop-separated-auth"),
            headers=network_headers,
        )
        assert incident_response.status_code == 200
        incident = incident_response.json()
        decision = decision_for(incident, decision_id="decision-separated-auth")

        assert (
            protected_client.post(
                "/decisions", json=decision, headers=network_headers
            ).status_code
            == 401
        )
        assert (
            protected_client.post(
                "/decisions", json=decision, headers=chat_headers
            ).json()["status"]
            == "APPLIED"
        )


async def test_analysis_overload_is_bounded_and_fail_closed(
    app_settings: Settings,
) -> None:
    bounded = replace(
        app_settings,
        max_concurrent_analyses=1,
        analysis_queue_timeout_seconds=0.05,
    )
    container = build_container(bounded)
    container.database.initialize()
    reasoner = BlockingReasoner()
    container.network_agent.reasoner = reasoner
    first_payload = drop_payload("drop-blocking-first")
    second_payload = drop_payload("drop-overloaded-second")
    second_payload["destination_port"] = 444

    first_task = asyncio.create_task(container.network_agent.process(first_payload))
    await reasoner.started.wait()
    second = await container.network_agent.process(second_payload)
    reasoner.release.set()
    await first_task

    assert second.last_error_code == "REASONER_OVERLOADED"
    assert second.context_request is not None
    assert [action.value for action in second.context_request.allowed_responses] == [
        "KEEP_CURRENT_POLICY",
        "REQUEST_MORE_INFORMATION",
    ]
