"""Mocked tests for outbound coordinator HTTP delivery."""

from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

import coordinator
from coordinator import build_callback_payload, deliver_coordinator_callback
from models import (
    AIAnalysisStatus,
    CallbackStatus,
    ChatContextAssessment,
    CoordinatorCallbackState,
    HumanDecision,
    HumanResponse,
    NetworkAlertCreate,
    ObservedFact,
    SecurityEvent,
)


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def responded_event() -> SecurityEvent:
    relevant_id = uuid4()
    return SecurityEvent(
        alert=NetworkAlertCreate(
            actor="Alice",
            request_summary="grant database-admin to deployment-bot",
            source_ip="203.0.113.10",
            network_risk_score=0.94,
        ),
        ai_context=ChatContextAssessment(
            observed_facts=[
                ObservedFact(
                    message_id=relevant_id,
                    author="Alice",
                    fact="FULL SECRET CHAT BODY MUST NOT BE SENT",
                    relevance="The message may explain the network origin.",
                )
            ],
            inference="The VPN may explain the unusual network origin.",
            unresolved_issue="The initiator remains unverified.",
            verification_target="Alice",
            verification_question="Did you initiate the action?",
            context_confidence=0.8,
            context_status=AIAnalysisStatus.RELEVANT_CONTEXT_FOUND,
        ),
        verification_message_id=uuid4(),
        human_response=HumanResponse(
            responder="Alice", response=HumanDecision.NO
        ),
        coordinator_callback=CoordinatorCallbackState(attempt_count=1),
    )


def configure_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(coordinator, "load_dotenv", lambda: None)
    monkeypatch.setenv(
        "COORDINATOR_RESPONSE_URL", "https://coordinator.test/human-responses"
    )


async def test_success_sends_only_summary_and_records_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_url(monkeypatch)
    event = responded_event()
    captured: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        captured["payload"] = json.loads(request.content)
        return httpx.Response(
            202,
            json={"final_coordinator_decision": "escalate"},
            request=request,
        )

    result = await deliver_coordinator_callback(
        event, transport=httpx.MockTransport(handler)
    )

    expected_keys = {
        "callback_id",
        "event_id",
        "account_user",
        "responded_by",
        "human_response",
        "responded_at",
        "context_summary",
        "relevant_message_ids",
        "network_risk_score",
    }
    assert set(captured["payload"]) == expected_keys
    assert captured["payload"]["callback_id"] == str(
        event.coordinator_callback.callback_id
    )
    assert captured["headers"]["Idempotency-Key"] == captured["payload"][
        "callback_id"
    ]
    assert captured["payload"]["account_user"] == "Alice"
    assert captured["payload"]["human_response"] == "No"
    assert captured["payload"]["network_risk_score"] == 0.94
    assert "FULL SECRET CHAT BODY" not in json.dumps(captured["payload"])
    assert result.status == CallbackStatus.DELIVERED
    assert result.response_status_code == 202
    assert result.coordinator_decision == "escalate"


async def test_timeout_returns_failed_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_url(monkeypatch)

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("mock timeout", request=request)

    result = await deliver_coordinator_callback(
        responded_event(), transport=httpx.MockTransport(handler)
    )
    assert result.status == CallbackStatus.FAILED
    assert result.response_status_code is None
    assert result.last_error == "Coordinator delivery timed out."


async def test_connection_failure_returns_failed_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_url(monkeypatch)

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("mock connection failure", request=request)

    result = await deliver_coordinator_callback(
        responded_event(), transport=httpx.MockTransport(handler)
    )
    assert result.status == CallbackStatus.FAILED
    assert result.response_status_code is None
    assert result.last_error == "Could not connect to the coordinator service."


async def test_missing_url_fails_without_http_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(coordinator, "load_dotenv", lambda: None)
    monkeypatch.delenv("COORDINATOR_RESPONSE_URL", raising=False)
    result = await deliver_coordinator_callback(responded_event())
    assert result.status == CallbackStatus.FAILED
    assert "COORDINATOR_RESPONSE_URL" in result.last_error


def test_payload_builder_requires_a_stored_response() -> None:
    event = responded_event().model_copy(update={"human_response": None})
    with pytest.raises(ValueError, match="stored human response"):
        build_callback_payload(event)
