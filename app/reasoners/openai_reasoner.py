"""OpenAI Responses API implementation of the network evidence reasoner."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from ..schemas import AgentAnalysis, NetworkEventType
from .base import (
    BaseReasoner,
    EvidenceCapsule,
    ReasonerError,
    ReasoningResult,
    ReasoningUsage,
)
from .prompt import ANALYSIS_SCHEMA_VERSION, PROMPT_VERSION, build_reasoning_messages

DEFAULT_MODEL = "gpt-4.1-mini"
DEFAULT_MAX_OUTPUT_TOKENS = 800
MAX_OUTPUT_TOKENS_LIMIT = 4_096
SDK_MAX_RETRIES = 1


def _optional_nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _usage_value(usage: Any, name: str) -> int | None:
    if usage is None:
        return None
    if isinstance(usage, dict):
        return _optional_nonnegative_int(usage.get(name))
    return _optional_nonnegative_int(getattr(usage, name, None))


class OpenAIReasoner(BaseReasoner):
    """Produce typed network analysis with no model tools or mutation authority.

    The project API key must be supplied directly by the composition root.  This
    class never reads environment variables, configuration files, or process-wide
    SDK defaults, and it never logs the key or provider exceptions.
    """

    def __init__(
        self,
        *,
        api_key: str,
        model: str = DEFAULT_MODEL,
        max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
        timeout_seconds: float = 30.0,
        client: Any | None = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise ValueError("api_key must be supplied directly")
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string")
        if (
            isinstance(max_output_tokens, bool)
            or not isinstance(max_output_tokens, int)
            or not 1 <= max_output_tokens <= MAX_OUTPUT_TOKENS_LIMIT
        ):
            raise ValueError(
                f"max_output_tokens must be between 1 and {MAX_OUTPUT_TOKENS_LIMIT}"
            )
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        if client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:  # pragma: no cover - dependency error path
                raise RuntimeError("The openai package is required for OpenAIReasoner") from exc

            # Supplying api_key here prevents the SDK from selecting another key
            # from process state.  The SDK performs at most one transient retry.
            client = OpenAI(
                api_key=api_key,
                max_retries=SDK_MAX_RETRIES,
                timeout=timeout_seconds,
            )

        self._client = client
        self._model = model.strip()
        self._max_output_tokens = max_output_tokens

    @property
    def provider(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    @property
    def max_output_tokens(self) -> int:
        return self._max_output_tokens

    def _parse_response(
        self,
        evidence: EvidenceCapsule,
        event_type: NetworkEventType | None,
    ) -> Any:
        # Deliberately supply no tools.  Structured text is the only capability
        # available to the model; deterministic service code owns all actions.
        return self._client.responses.parse(
            model=self._model,
            input=build_reasoning_messages(evidence, event_type),
            text_format=AgentAnalysis,
            max_output_tokens=self._max_output_tokens,
            tools=[],
            store=False,
        )

    async def analyze(
        self,
        evidence: EvidenceCapsule,
        *,
        event_type: NetworkEventType,
    ) -> ReasoningResult:
        started = time.perf_counter()
        try:
            response = await asyncio.to_thread(self._parse_response, evidence, event_type)
            parsed = getattr(response, "output_parsed", None)
            if parsed is None:
                raise ReasonerError("The model returned no parsed analysis")
            analysis = (
                parsed
                if isinstance(parsed, AgentAnalysis)
                else AgentAnalysis.model_validate(parsed)
            )
        except Exception as exc:
            # The stable outer message avoids copying provider response data.  The
            # orchestration layer records ANALYSIS_FAILED and keeps policy intact.
            raise ReasonerError("OpenAI reasoner failed to produce a valid analysis") from exc

        latency_ms = (time.perf_counter() - started) * 1000
        usage = getattr(response, "usage", None)
        response_id = getattr(response, "id", None)
        response_model = getattr(response, "model", None)
        input_tokens = _usage_value(usage, "input_tokens")
        output_tokens = _usage_value(usage, "output_tokens")
        total_tokens = _usage_value(usage, "total_tokens")
        reasoning_usage = None
        if any(value is not None for value in (input_tokens, output_tokens, total_tokens)):
            reasoning_usage = ReasoningUsage(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
            )
        return ReasoningResult(
            analysis=analysis,
            provider=self.provider,
            model=response_model if isinstance(response_model, str) else self._model,
            prompt_version=PROMPT_VERSION,
            schema_version=getattr(analysis, "schema_version", ANALYSIS_SCHEMA_VERSION),
            latency_ms=latency_ms,
            usage=reasoning_usage,
            response_id=response_id if isinstance(response_id, str) else None,
        )


def create_openai_reasoner(
    *,
    api_key: str,
    model: str = DEFAULT_MODEL,
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    timeout_seconds: float = 30.0,
) -> OpenAIReasoner:
    """Create a production reasoner from explicitly supplied configuration."""

    return OpenAIReasoner(
        api_key=api_key,
        model=model,
        max_output_tokens=max_output_tokens,
        timeout_seconds=timeout_seconds,
    )
