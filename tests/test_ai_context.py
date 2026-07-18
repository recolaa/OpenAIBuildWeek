"""Unit tests for grounded Responses API context analysis."""

from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

import ai_context
from ai_context import analyze_chat_context
from models import AIAnalysisStatus, AIErrorCategory, Message, NetworkAlertCreate


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


def model_result(
    message: Message | None,
    *,
    question: str = "Mallory, should this action be approved?",
) -> ai_context._ModelChatContextOutput:
    facts = []
    if message is not None:
        facts.append(
            {
                "message_id": message.id,
                "author": message.author,
                "fact": "Alice said she is traveling and expects to use the VPN.",
                "relevance": "The VPN may explain an unusual network origin.",
            }
        )
    return ai_context._ModelChatContextOutput(
        observed_facts=facts,
        inference=(
            "The VPN could explain an unusual network origin, but it does not "
            "authorize the privileged action."
            if message is not None
            else "No supplied chat message explains the alert."
        ),
        unresolved_issue="The chat does not establish who initiated the request.",
        verification_question=question,
        context_confidence=0.81 if message is not None else 0.0,
        context_status=(
            "relevant_context_found" if message is not None else "no_relevant_context"
        ),
    )


def configure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
    monkeypatch.setenv("OPENAI_MODEL", "test-structured-model")
    monkeypatch.setattr(ai_context, "load_dotenv", lambda: None)


def install_fake_response(
    monkeypatch: pytest.MonkeyPatch,
    response: object,
    captured: dict[str, object] | None = None,
) -> None:
    class FakeResponses:
        async def parse(self, **kwargs: object) -> object:
            if captured is not None:
                captured.update(kwargs)
            return response

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            if captured is not None:
                captured["client_options"] = kwargs
            self.responses = FakeResponses()

    monkeypatch.setattr(ai_context, "AsyncOpenAI", FakeOpenAI)


async def test_relevant_travel_context_is_grounded_and_never_authorizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    alert = sample_alert()
    message = sample_message()
    captured: dict[str, object] = {}
    install_fake_response(
        monkeypatch,
        SimpleNamespace(output_parsed=model_result(message), output=[]),
        captured,
    )

    result = await analyze_chat_context(alert, [message])

    assert captured["model"] == "test-structured-model"
    assert captured["text_format"] is ai_context._ModelChatContextOutput
    assert captured["store"] is False
    sent_input = json.loads(str(captured["input"]))
    assert sent_input["recent_messages"][0]["id"] == str(message.id)
    assert "never" in str(captured["instructions"]).lower()
    assert "authorize" in str(captured["instructions"]).lower()
    assert result.context_status == AIAnalysisStatus.RELEVANT_CONTEXT_FOUND
    assert result.observed_facts[0].message_id == message.id
    assert result.relevant_message_ids == [message.id]
    assert "does not authorize" in result.inference


async def test_target_and_wrong_user_question_are_corrected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    message = sample_message()
    install_fake_response(
        monkeypatch,
        SimpleNamespace(output_parsed=model_result(message), output=[]),
    )

    result = await analyze_chat_context(sample_alert(), [message])

    assert result.verification_target == "Alice"
    assert result.verification_question.startswith("Alice, did you initiate")
    assert "Mallory" not in result.verification_question
    assert "grant database-admin to deployment-bot" in result.verification_question


async def test_no_relevant_messages_still_produces_verification_question(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    install_fake_response(
        monkeypatch,
        SimpleNamespace(output_parsed=model_result(None), output=[]),
    )

    result = await analyze_chat_context(sample_alert(), [])

    assert result.context_status == AIAnalysisStatus.NO_RELEVANT_CONTEXT
    assert result.observed_facts == []
    assert result.context_confidence == 0.0
    assert "grant database-admin to deployment-bot" in result.verification_question


async def test_invented_message_id_produces_safe_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    message = sample_message()
    parsed = model_result(message)
    parsed.observed_facts[0].message_id = uuid4()
    install_fake_response(
        monkeypatch, SimpleNamespace(output_parsed=parsed, output=[])
    )

    result = await analyze_chat_context(sample_alert(), [message])

    assert result.context_status == AIAnalysisStatus.AI_UNAVAILABLE
    assert result.ai_error == AIErrorCategory.INVALID_OUTPUT
    assert result.observed_facts == []


async def test_timeout_produces_safe_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.responses = self

        async def parse(self, **kwargs: object) -> object:
            raise TimeoutError("secret timeout detail")

    monkeypatch.setattr(ai_context, "AsyncOpenAI", FakeOpenAI)
    result = await analyze_chat_context(sample_alert(), [])

    assert result.context_status == AIAnalysisStatus.AI_UNAVAILABLE
    assert result.ai_error == AIErrorCategory.TIMEOUT
    assert "secret" not in result.model_dump_json()


async def test_invalid_structured_output_produces_safe_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    install_fake_response(
        monkeypatch, SimpleNamespace(output_parsed=None, output=[])
    )

    result = await analyze_chat_context(sample_alert(), [])

    assert result.context_status == AIAnalysisStatus.AI_UNAVAILABLE
    assert result.ai_error == AIErrorCategory.INVALID_OUTPUT


async def test_refusal_produces_safe_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configure_environment(monkeypatch)
    refusal = SimpleNamespace(
        output_parsed=None,
        output=[
            SimpleNamespace(
                type="message",
                content=[SimpleNamespace(type="refusal", refusal="cannot comply")],
            )
        ],
    )
    install_fake_response(monkeypatch, refusal)

    result = await analyze_chat_context(sample_alert(), [])

    assert result.context_status == AIAnalysisStatus.AI_UNAVAILABLE
    assert result.ai_error == AIErrorCategory.REFUSAL
    assert "cannot comply" not in result.model_dump_json()


async def test_missing_configuration_makes_no_openai_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ai_context, "load_dotenv", lambda: None)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_MODEL", "test-structured-model")

    def unexpected_client(**kwargs: object) -> None:
        raise AssertionError("OpenAI client should not be created")

    monkeypatch.setattr(ai_context, "AsyncOpenAI", unexpected_client)
    result = await analyze_chat_context(sample_alert(), [])

    assert result.context_status == AIAnalysisStatus.AI_UNAVAILABLE
    assert result.ai_error == AIErrorCategory.CONFIGURATION
    assert result.verification_target == "Alice"
