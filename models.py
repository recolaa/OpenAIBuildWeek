"""Pydantic models shared by the API, store, UI, and AI integration."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class MessageKind(str, Enum):
    USER = "user"
    SECURITY_VERIFICATION = "security_verification"


class MessageCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    author: NonEmptyText = Field(max_length=80)
    content: NonEmptyText = Field(max_length=4_000)


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    author: str
    content: str
    created_at: datetime = Field(default_factory=utc_now)
    kind: MessageKind = MessageKind.USER
    security_event_id: Optional[UUID] = None


def build_verification_question(actor: str, request_summary: str) -> str:
    """Build the mandatory question from alert data, never from chat context."""

    return (
        f'{actor}, did you initiate this specific privileged action: '
        f'"{request_summary}"?'
    )


class AIContextResult(BaseModel):
    """Structured contract for the later OpenAI context-analysis stage."""

    model_config = ConfigDict(extra="forbid")

    observed_facts: list[NonEmptyText]
    relevant_message_ids: list[UUID]
    inference: NonEmptyText
    unresolved_issue: NonEmptyText
    verification_target: NonEmptyText
    verification_question: NonEmptyText
    context_confidence: float = Field(ge=0.0, le=1.0)


class NetworkAlertCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: Optional[NonEmptyText] = Field(default=None, max_length=120)
    actor: NonEmptyText = Field(max_length=80)
    request_summary: NonEmptyText = Field(max_length=1_000)
    target_resource: Optional[NonEmptyText] = Field(default=None, max_length=500)
    source_ip: Optional[NonEmptyText] = Field(default=None, max_length=64)
    detected_at: datetime = Field(default_factory=utc_now)


class AnalysisStatus(str, Enum):
    NOT_RUN = "not_run"
    COMPLETED = "completed"
    FAILED = "failed"


class HumanDecision(str, Enum):
    YES = "Yes"
    NO = "No"
    UNSURE = "Unsure"


class HumanResponseCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    responder: NonEmptyText = Field(max_length=80)
    response: HumanDecision


class HumanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    responder: str
    response: HumanDecision
    responded_at: datetime = Field(default_factory=utc_now)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    alert: NetworkAlertCreate
    created_at: datetime = Field(default_factory=utc_now)
    analysis_status: AnalysisStatus = AnalysisStatus.NOT_RUN
    ai_context: Optional[AIContextResult] = None
    analysis_error: Optional[str] = None
    verification_message_id: UUID
    human_response: Optional[HumanResponse] = None
    coordinator_delivery_error: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
