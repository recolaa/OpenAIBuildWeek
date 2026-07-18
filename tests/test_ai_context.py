"""Unit tests for grounded Responses API context analysis."""

from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

import ai_context
from ai_context import AIContextUnavailableError, analyze_context
from models import AIContextResult, Message, NetworkAlertCreate


pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def sample_alert() -> NetworkAlertCreate:
    return NetworkAlertCreate(
        actor="Alice",
        request_summary="grant database-admin to deployment-bot",
        target_resource="production database",
        source_ip="203.0.113.10",
    )


def sample_message() -> Message:
    return Message(
        author="Alice",
        content="I am traveling and expect to connect through the company VPN.",
    )


def structured_result(message: Message) -> AIContextResult:
    return AIContextResult(
        observed_facts=["Alice said she is traveling and expects to use the VPN."],
        relevant_message_ids=[message.id],
        inference="The VPN could explain an unusual network origin.",
        unresolved_issue="The chat does not establish who initiated the request.",
        verification_target="Mallory",
        verification_question="Should this be approved?",
        context_confidence=0.81,
    )


def configure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("OPENAI_MODEL", "test-structured-model")
    monkeypatch.setattr(ai_context, "load_dotenv", lambda: None)


async def test_uses_responses_parse_with_pydantic_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    alert = sample_alert()
    message = sample_message()
    captured: dict = {}

    class FakeResponses:
        async def parse(self, **kwargs: object) -> object:
            captured.update(kwargs)
            return SimpleNamespace(output_parsed=structured_result(message))

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            captured["client_options"] = kwargs
            self.responses = FakeResponses()

    monkeypatch.setattr(ai_context, "AsyncOpenAI", FakeOpenAI)
    result = await analyze_context(alert, [message])

    assert captured["model"] == "test-structured-model"
    assert captured["text_format"] is AIContextResult
    assert captured["store"] is False
    sent_input = json.loads(captured["input"])
    assert sent_input["recent_messages"][0]["id"] == str(message.id)
    assert "never" in captured["instructions"].lower()
    assert "authorize" in captured["instructions"].lower()

    # Security-critical routing is canonicalized from the alert, regardless of
    # what the model attempted to return.
    assert result.verification_target == "Alice"
    assert "grant database-admin to deployment-bot" in result.verification_question
    assert "specific privileged action" in result.verification_question


async def test_rejects_invented_chat_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    message = sample_message()
    parsed = structured_result(message).model_copy(
        update={"relevant_message_ids": [uuid4()]}
    )

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.responses = self

        async def parse(self, **kwargs: object) -> object:
            return SimpleNamespace(output_parsed=parsed)

    monkeypatch.setattr(ai_context, "AsyncOpenAI", FakeOpenAI)

    with pytest.raises(AIContextUnavailableError, match="not supplied"):
        await analyze_context(sample_alert(), [message])


async def test_missing_api_key_is_understandable_and_makes_no_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai_context, "load_dotenv", lambda: None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_MODEL", "test-structured-model")

    def unexpected_client(**kwargs: object) -> None:
        raise AssertionError("OpenAI client should not be created")

    monkeypatch.setattr(ai_context, "AsyncOpenAI", unexpected_client)
    with pytest.raises(AIContextUnavailableError, match="OPENAI_API_KEY"):
        await analyze_context(sample_alert(), [])


async def test_empty_structured_response_is_understandable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.responses = self

        async def parse(self, **kwargs: object) -> object:
            return SimpleNamespace(output_parsed=None)

    monkeypatch.setattr(ai_context, "AsyncOpenAI", FakeOpenAI)
    with pytest.raises(AIContextUnavailableError, match="no usable structured"):
        await analyze_context(sample_alert(), [])
