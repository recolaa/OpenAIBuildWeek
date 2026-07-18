"""Focused endpoint tests for the non-AI MVP flow."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import uuid4

import httpx
import pytest

import backend
from ai_context import AIContextUnavailableError
from backend import app
from models import AIContextResult


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def reset_store(monkeypatch: pytest.MonkeyPatch) -> None:
    app.state.store.reset()

    async def unavailable_analysis(*args: object) -> None:
        raise AIContextUnavailableError("Mocked OpenAI outage.")

    # Every alert test is isolated from the network. Individual success tests
    # replace this default with a structured fake result.
    monkeypatch.setattr(backend, "analyze_context", unavailable_analysis)


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
    assert event["ai_context"] is None
    assert event["analysis_error"] == "Mocked OpenAI outage."
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

    async def successful_analysis(*args: object) -> AIContextResult:
        return AIContextResult(
            observed_facts=["Alice said she is traveling and using a VPN."],
            relevant_message_ids=[message_id],
            inference="The VPN may explain an unusual source location.",
            unresolved_issue="Chat context does not prove who initiated the action.",
            verification_target="Alice",
            verification_question="canonical question from analysis layer",
            context_confidence=0.72,
        )

    monkeypatch.setattr(backend, "analyze_context", successful_analysis)
    event = await create_alert(client)

    assert event["analysis_status"] == "completed"
    assert event["analysis_error"] is None
    assert event["ai_context"]["relevant_message_ids"] == [message_id]
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
