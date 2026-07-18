"""Pydantic models shared by the API, store, UI, and AI integration."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


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


def build_verification_question(
    actor: str,
    request_summary: str,
    detected_at: Optional[datetime] = None,
) -> str:
    """Build the mandatory question from alert data, never from chat context."""

    question = (
        f'{actor}, did you initiate this specific privileged action: '
        f'"{request_summary}"'
    )
    if detected_at is not None:
        timestamp = detected_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%d at %H:%M UTC"
        )
        question += f" at approximately {timestamp}"
    return f"{question}?"


class ObservedFact(BaseModel):
    """One chat-grounded fact cited by the context assessment."""

    model_config = ConfigDict(extra="forbid")

    message_id: UUID
    author: NonEmptyText = Field(max_length=80)
    fact: NonEmptyText = Field(max_length=1_000)
    relevance: NonEmptyText = Field(max_length=1_000)


class AIAnalysisStatus(str, Enum):
    RELEVANT_CONTEXT_FOUND = "relevant_context_found"
    NO_RELEVANT_CONTEXT = "no_relevant_context"
    AI_UNAVAILABLE = "ai_unavailable"


class AIErrorCategory(str, Enum):
    CONFIGURATION = "configuration"
    TIMEOUT = "timeout"
    REFUSAL = "refusal"
    INVALID_OUTPUT = "invalid_output"
    API_ERROR = "api_error"


class ChatContextAssessment(BaseModel):
    """Grounded, application-canonicalized chat context assessment."""

    model_config = ConfigDict(extra="forbid")

    observed_facts: list[ObservedFact]
    inference: NonEmptyText
    unresolved_issue: NonEmptyText
    verification_target: NonEmptyText
    verification_question: NonEmptyText
    context_confidence: float = Field(ge=0.0, le=1.0)
    context_status: AIAnalysisStatus
    ai_error: Optional[AIErrorCategory] = None
    # Compatibility projection for the existing API/coordinator contract. It
    # is always recalculated from grounded facts and cannot add new evidence.
    relevant_message_ids: list[UUID] = Field(default_factory=list)

    @model_validator(mode="after")
    def derive_relevant_message_ids(self) -> "ChatContextAssessment":
        self.relevant_message_ids = list(
            dict.fromkeys(fact.message_id for fact in self.observed_facts)
        )
        return self


# Backward-compatible name used by existing store and coordinator code.
AIContextResult = ChatContextAssessment


class NetworkAlertCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: Optional[NonEmptyText] = Field(default=None, max_length=120)
    actor: NonEmptyText = Field(max_length=80)
    request_summary: NonEmptyText = Field(max_length=1_000)
    target_resource: Optional[NonEmptyText] = Field(default=None, max_length=500)
    source_ip: Optional[NonEmptyText] = Field(default=None, max_length=64)
    network_risk_score: float = Field(default=1.0, ge=0.0, le=1.0)
    detected_at: datetime = Field(default_factory=utc_now)


# Domain names used by the AI boundary without changing the public API models.
NetworkAlert = NetworkAlertCreate
ChatMessage = Message


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


class CallbackStatus(str, Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"


class CoordinatorCallbackState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    callback_id: UUID = Field(default_factory=uuid4)
    status: CallbackStatus = CallbackStatus.PENDING
    response_status_code: Optional[int] = Field(default=None, ge=100, le=599)
    attempt_count: int = Field(default=0, ge=0)
    last_error: Optional[str] = None
    coordinator_decision: Optional[str] = None


class CoordinatorDeliveryResult(BaseModel):
    """Internal result returned by the outbound coordinator client."""

    model_config = ConfigDict(extra="forbid")

    status: CallbackStatus
    response_status_code: Optional[int] = Field(default=None, ge=100, le=599)
    last_error: Optional[str] = None
    coordinator_decision: Optional[str] = None


class CoordinatorCallbackAttempt(BaseModel):
    """Durable audit record for one coordinator delivery attempt."""

    model_config = ConfigDict(extra="forbid")

    callback_id: UUID
    attempt_number: int = Field(ge=1)
    status: CallbackStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    response_status_code: Optional[int] = Field(default=None, ge=100, le=599)
    last_error: Optional[str] = None
    coordinator_decision: Optional[str] = None


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(default_factory=uuid4)
    alert: NetworkAlertCreate
    created_at: datetime = Field(default_factory=utc_now)
    analysis_status: AnalysisStatus = AnalysisStatus.NOT_RUN
    ai_context: Optional[ChatContextAssessment] = None
    analysis_error: Optional[str] = None
    verification_message_id: UUID
    human_response: Optional[HumanResponse] = None
    coordinator_callback: Optional[CoordinatorCallbackState] = None
    coordinator_callback_attempts: list[CoordinatorCallbackAttempt] = Field(
        default_factory=list
    )


class HealthResponse(BaseModel):
    status: str
