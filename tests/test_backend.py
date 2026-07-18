"""Focused endpoint tests for the non-AI MVP flow."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

import backend
from backend import app
from models import (
    AIAnalysisStatus,
    AIErrorCategory,
    CallbackStatus,
    ChatContextAssessment,
    CoordinatorDeliveryResult,
    NetworkAlertCreate,
    ObservedFact,
    build_verification_question,
)
from store import SQLiteStore


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def reset_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[None]:
    original_store = app.state.store
    test_store = SQLiteStore(tmp_path / "backend-test.db")
    app.state.store = test_store

    async def unavailable_analysis(
        alert: NetworkAlertCreate, *args: object
    ) -> ChatContextAssessment:
        return ChatContextAssessment(
            observed_facts=[],
            inference="Automated chat-context analysis was unavailable.",
            unresolved_issue=(
                "It has not been confirmed whether the account owner initiated "
                "this action."
            ),
            verification_target=alert.actor,
            verification_question=build_verification_question(
                alert.actor, alert.request_summary, alert.detected_at
            ),
            context_confidence=0.0,
            context_status=AIAnalysisStatus.AI_UNAVAILABLE,
            ai_error=AIErrorCategory.API_ERROR,
        )

    async def unavailable_coordinator(*args: object) -> CoordinatorDeliveryResult:
        return CoordinatorDeliveryResult(
            status=CallbackStatus.FAILED,
            last_error="Mocked coordinator outage.",
        )

    # Every alert test is isolated from the network. Individual success tests
    # replace this default with a structured fake result.
    monkeypatch.setattr(backend, "analyze_chat_context", unavailable_analysis)
    monkeypatch.setattr(
        backend, "deliver_coordinator_callback", unavailable_coordinator
    )
    yield
    test_store.close()
    app.state.store = original_store


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as test_client:
        yield test_client


async def create_alert(client: httpx.AsyncClient) -> dict:
    response = await client.post(
        "/network-alerts",
        json={
            "alert_id": "monitor-42",
            "actor": "Alice",
            "request_summary": "grant database-admin to deployment-bot",
            "target_resource": "production database",
            "source_ip": "203.0.113.10",
        },
    )
    assert response.status_code == 201
    return response.json()


async def test_health(client: httpx.AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_messages_begin_empty(client: httpx.AsyncClient) -> None:
    assert (await client.get("/messages")).json() == []


async def test_create_and_list_message(client: httpx.AsyncClient) -> None:
    created = await client.post(
        "/messages", json={"author": "Alice", "content": "I am traveling today."}
    )
    assert created.status_code == 201
    assert created.json()["author"] == "Alice"
    assert created.json()["kind"] == "user"

    messages = await client.get("/messages")
    assert messages.status_code == 200
    assert [message["content"] for message in messages.json()] == [
        "I am traveling today."
    ]


@pytest.mark.parametrize(
    "payload",
    [
        {"author": "", "content": "hello"},
        {"author": "Alice", "content": "   "},
        {"author": "Alice", "content": "hello", "unexpected": True},
    ],
)
async def test_rejects_invalid_messages(
    client: httpx.AsyncClient, payload: dict
) -> None:
    assert (await client.post("/messages", json=payload)).status_code == 422


async def test_network_alert_posts_targeted_verification_message(
    client: httpx.AsyncClient,
) -> None:
    event = await create_alert(client)
    assert event["analysis_status"] == "failed"
    assert event["ai_context"]["context_status"] == "ai_unavailable"
    assert event["ai_context"]["ai_error"] == "api_error"
    assert event["ai_context"]["observed_facts"] == []
    assert event["analysis_error"] == "api_error"
    assert event["human_response"] is None

    messages = (await client.get("/messages")).json()
    assert len(messages) == 1
    assert messages[0]["kind"] == "security_verification"
    assert messages[0]["security_event_id"] == event["id"]
    assert "Alice, did you initiate this specific privileged action" in messages[0]["content"]
    assert "grant database-admin to deployment-bot" in messages[0]["content"]


async def test_network_alert_persists_structured_ai_context(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    context_message = await client.post(
        "/messages",
        json={"author": "Alice", "content": "I am traveling and using a VPN."},
    )
    message_id = context_message.json()["id"]

    async def successful_analysis(*args: object) -> ChatContextAssessment:
        return ChatContextAssessment(
            observed_facts=[
                ObservedFact(
                    message_id=message_id,
                    author="Alice",
                    fact="Alice said she is traveling and using a VPN.",
                    relevance="The VPN may explain the unusual source location.",
                )
            ],
            inference="The VPN may explain an unusual source location.",
            unresolved_issue="Chat context does not prove who initiated the action.",
            verification_target="Alice",
            verification_question="canonical question from analysis layer",
            context_confidence=0.72,
            context_status=AIAnalysisStatus.RELEVANT_CONTEXT_FOUND,
        )

    monkeypatch.setattr(backend, "analyze_chat_context", successful_analysis)
    event = await create_alert(client)

    assert event["analysis_status"] == "completed"
    assert event["analysis_error"] is None
    assert event["ai_context"]["relevant_message_ids"] == [message_id]
    assert event["ai_context"]["observed_facts"][0]["message_id"] == message_id
    assert event["ai_context"]["context_status"] == "relevant_context_found"
    assert event["ai_context"]["context_confidence"] == 0.72
    assert "specific privileged action" in event["ai_context"][
        "verification_question"
    ]


async def test_get_security_event(client: httpx.AsyncClient) -> None:
    event = await create_alert(client)
    response = await client.get(f"/security-events/{event['id']}")
    assert response.status_code == 200
    assert response.json()["alert"]["actor"] == "Alice"


async def test_missing_security_event_returns_404(client: httpx.AsyncClient) -> None:
    response = await client.get(f"/security-events/{uuid4()}")
    assert response.status_code == 404
    assert response.json()["detail"] == "Security event not found."


@pytest.mark.parametrize("decision", ["Yes", "No", "Unsure"])
async def test_target_can_record_each_supported_human_response(
    client: httpx.AsyncClient, decision: str
) -> None:
    event = await create_alert(client)
    response = await client.post(
        f"/security-events/{event['id']}/human-response",
        json={"responder": "Alice", "response": decision},
    )
    assert response.status_code == 201
    assert response.json()["human_response"]["response"] == decision
    assert response.json()["coordinator_callback"]["status"] == "failed"
    assert response.json()["coordinator_callback"]["attempt_count"] == 1


async def test_wrong_person_cannot_answer_verification(
    client: httpx.AsyncClient,
) -> None:
    event = await create_alert(client)
    response = await client.post(
        f"/security-events/{event['id']}/human-response",
        json={"responder": "Bob", "response": "Yes"},
    )
    assert response.status_code == 403
    assert "Only Alice" in response.json()["detail"]


async def test_human_response_cannot_be_overwritten(
    client: httpx.AsyncClient,
) -> None:
    event = await create_alert(client)
    path = f"/security-events/{event['id']}/human-response"
    first = await client.post(
        path, json={"responder": "Alice", "response": "Unsure"}
    )
    assert first.status_code == 201
    second = await client.post(path, json={"responder": "Alice", "response": "No"})
    assert second.status_code == 409


async def test_rejects_unknown_human_response(client: httpx.AsyncClient) -> None:
    event = await create_alert(client)
    response = await client.post(
        f"/security-events/{event['id']}/human-response",
        json={"responder": "Alice", "response": "Probably"},
    )
    assert response.status_code == 422


async def test_successful_coordinator_delivery_records_result(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def delivered(event: object) -> CoordinatorDeliveryResult:
        calls.append(str(event.coordinator_callback.callback_id))
        return CoordinatorDeliveryResult(
            status=CallbackStatus.DELIVERED,
            response_status_code=202,
            coordinator_decision="escalate",
        )

    monkeypatch.setattr(backend, "deliver_coordinator_callback", delivered)
    event = await create_alert(client)
    response = await client.post(
        f"/security-events/{event['id']}/human-response",
        json={"responder": "Alice", "response": "No"},
    )

    assert response.status_code == 201
    callback = response.json()["coordinator_callback"]
    assert callback["status"] == "delivered"
    assert callback["response_status_code"] == 202
    assert callback["attempt_count"] == 1
    assert callback["last_error"] is None
    assert callback["coordinator_decision"] == "escalate"
    assert calls == [callback["callback_id"]]


async def test_failed_callback_can_retry_with_same_id(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    callback_ids: list[str] = []

    async def fail_then_succeed(event: object) -> CoordinatorDeliveryResult:
        callback_ids.append(str(event.coordinator_callback.callback_id))
        if len(callback_ids) == 1:
            return CoordinatorDeliveryResult(
                status=CallbackStatus.FAILED,
                response_status_code=503,
                last_error="Coordinator returned HTTP 503.",
            )
        return CoordinatorDeliveryResult(
            status=CallbackStatus.DELIVERED,
            response_status_code=200,
            coordinator_decision="deny",
        )

    monkeypatch.setattr(
        backend, "deliver_coordinator_callback", fail_then_succeed
    )
    event = await create_alert(client)
    first = await client.post(
        f"/security-events/{event['id']}/human-response",
        json={"responder": "Alice", "response": "Unsure"},
    )
    first_body = first.json()
    assert first_body["human_response"]["response"] == "Unsure"
    assert first_body["coordinator_callback"]["status"] == "failed"
    assert first_body["coordinator_callback"]["response_status_code"] == 503
    assert first_body["coordinator_callback"]["attempt_count"] == 1

    retried = await client.post(
        f"/security-events/{event['id']}/coordinator-callback/retry"
    )
    assert retried.status_code == 200
    retry_callback = retried.json()["coordinator_callback"]
    assert retry_callback["status"] == "delivered"
    assert retry_callback["attempt_count"] == 2
    assert retry_callback["coordinator_decision"] == "deny"
    assert callback_ids == [
        first_body["coordinator_callback"]["callback_id"],
        first_body["coordinator_callback"]["callback_id"],
    ]


async def test_duplicate_delivery_is_not_sent_twice(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    delivery_count = 0

    async def delivered(event: object) -> CoordinatorDeliveryResult:
        nonlocal delivery_count
        delivery_count += 1
        return CoordinatorDeliveryResult(
            status=CallbackStatus.DELIVERED,
            response_status_code=200,
        )

    monkeypatch.setattr(backend, "deliver_coordinator_callback", delivered)
    event = await create_alert(client)
    response_path = f"/security-events/{event['id']}/human-response"
    payload = {"responder": "Alice", "response": "Yes"}

    assert (await client.post(response_path, json=payload)).status_code == 201
    assert (await client.post(response_path, json=payload)).status_code == 409
    retry = await client.post(
        f"/security-events/{event['id']}/coordinator-callback/retry"
    )
    assert retry.status_code == 409
    assert delivery_count == 1


async def test_retry_requires_a_stored_failed_callback(
    client: httpx.AsyncClient,
) -> None:
    event = await create_alert(client)
    response = await client.post(
        f"/security-events/{event['id']}/coordinator-callback/retry"
    )
    assert response.status_code == 409
