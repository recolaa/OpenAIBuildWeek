"""Interfaces shared by network-event reasoning implementations.

Reasoners are intentionally advisory.  They turn a validated evidence capsule into
an :class:`AgentAnalysis`; they do not receive a firewall, shell, network client,
or any other mutation capability.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ..schemas import AgentAnalysis, NetworkEventType

EvidenceCapsule = Mapping[str, Any]


class ReasonerError(RuntimeError):
    """Raised when a reasoner cannot produce a schema-valid analysis."""


@dataclass(frozen=True, slots=True)
class ReasoningUsage:
    """Token accounting returned by the provider, when available."""

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None

    def __post_init__(self) -> None:
        for field_name in ("input_tokens", "output_tokens", "total_tokens"):
            value = getattr(self, field_name)
            if value is not None and value < 0:
                raise ValueError(f"{field_name} cannot be negative")


@dataclass(frozen=True, slots=True)
class ReasoningResult:
    """A typed analysis plus non-secret operational metadata.

    ``failure_code`` deliberately contains a stable code rather than an exception
    message.  Provider exceptions can contain request metadata and should only be
    handled by the service's sanitized error path.
    """

    analysis: AgentAnalysis
    provider: str
    model: str
    prompt_version: str
    schema_version: str
    latency_ms: float
    usage: ReasoningUsage | None = None
    response_id: str | None = None
    fallback_used: bool = False
    failure_code: str | None = None

    def __post_init__(self) -> None:
        if self.latency_ms < 0:
            raise ValueError("latency_ms cannot be negative")
        if self.fallback_used and self.failure_code is None:
            raise ValueError("fallback results require a stable failure_code")


@runtime_checkable
class Reasoner(Protocol):
    """Structural interface consumed by the event orchestration service."""

    @property
    def provider(self) -> str:
        """Return a stable implementation identifier (for example, ``mock``)."""

    async def analyze(
        self,
        evidence: EvidenceCapsule,
        *,
        event_type: NetworkEventType,
    ) -> ReasoningResult:
        """Analyze one immutable, validated evidence capsule."""


class BaseReasoner(ABC):
    """Convenience base class for concrete reasoners.

    ``reason`` is retained as a readable alias for callers that prefer agent-like
    terminology; orchestration code should normally call ``analyze``.
    """

    @property
    @abstractmethod
    def provider(self) -> str:
        """Return the implementation identifier used in audit metadata."""

    @abstractmethod
    async def analyze(
        self,
        evidence: EvidenceCapsule,
        *,
        event_type: NetworkEventType,
    ) -> ReasoningResult:
        """Analyze one immutable, validated evidence capsule."""

    async def reason(
        self,
        evidence: EvidenceCapsule,
        *,
        event_type: NetworkEventType,
    ) -> ReasoningResult:
        """Alias for :meth:`analyze`."""

        return await self.analyze(evidence, event_type=event_type)
