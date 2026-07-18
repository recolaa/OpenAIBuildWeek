"""Small thread-safe in-memory repository for the local MVP."""

from __future__ import annotations

from threading import RLock
from typing import Optional
from uuid import UUID, uuid4

from models import (
    AIContextResult,
    AnalysisStatus,
    HumanResponse,
    HumanResponseCreate,
    Message,
    MessageCreate,
    MessageKind,
    NetworkAlertCreate,
    SecurityEvent,
    build_verification_question,
)


class EventNotFoundError(LookupError):
    pass


class ResponseAlreadyRecordedError(RuntimeError):
    pass


class WrongResponderError(ValueError):
    pass


class InMemoryStore:
    """Process-local storage; all data disappears when the backend restarts."""

    def __init__(self) -> None:
        self._messages: list[Message] = []
        self._events: dict[UUID, SecurityEvent] = {}
        self._lock = RLock()

    def reset(self) -> None:
        """Clear all state. Intended for tests and local demos."""

        with self._lock:
            self._messages.clear()
            self._events.clear()

    def list_messages(self) -> list[Message]:
        with self._lock:
            return [message.model_copy(deep=True) for message in self._messages]

    def list_recent_user_messages(self, limit: int = 50) -> list[Message]:
        """Return recent human chat only, excluding security-bot prompts."""

        with self._lock:
            messages = [
                message
                for message in self._messages
                if message.kind == MessageKind.USER
            ][-limit:]
            return [message.model_copy(deep=True) for message in messages]

    def create_message(self, message: MessageCreate) -> Message:
        stored = Message(author=message.author, content=message.content)
        with self._lock:
            self._messages.append(stored)
        return stored.model_copy(deep=True)

    def create_security_event(
        self,
        alert: NetworkAlertCreate,
        *,
        ai_context: Optional[AIContextResult] = None,
        analysis_error: Optional[str] = None,
    ) -> SecurityEvent:
        """Persist analysis state and the mandatory verification prompt."""

        with self._lock:
            event_id = uuid4()
            verification_question = build_verification_question(
                alert.actor, alert.request_summary
            )
            canonical_context = (
                ai_context.model_copy(
                    update={
                        "verification_target": alert.actor,
                        "verification_question": verification_question,
                    },
                    deep=True,
                )
                if ai_context is not None
                else None
            )
            message = Message(
                author="Security Bot",
                content=verification_question,
                kind=MessageKind.SECURITY_VERIFICATION,
                security_event_id=event_id,
            )
            event = SecurityEvent(
                id=event_id,
                alert=alert,
                analysis_status=(
                    AnalysisStatus.COMPLETED
                    if canonical_context is not None
                    else AnalysisStatus.FAILED
                    if analysis_error is not None
                    else AnalysisStatus.NOT_RUN
                ),
                ai_context=canonical_context,
                analysis_error=analysis_error,
                verification_message_id=message.id,
            )
            self._messages.append(message)
            self._events[event.id] = event
            return event.model_copy(deep=True)

    def get_security_event(self, event_id: UUID) -> SecurityEvent:
        with self._lock:
            event = self._events.get(event_id)
            if event is None:
                raise EventNotFoundError(str(event_id))
            return event.model_copy(deep=True)

    def record_human_response(
        self, event_id: UUID, response: HumanResponseCreate
    ) -> SecurityEvent:
        with self._lock:
            event = self._events.get(event_id)
            if event is None:
                raise EventNotFoundError(str(event_id))
            if event.human_response is not None:
                raise ResponseAlreadyRecordedError(str(event_id))
            if response.responder.casefold() != event.alert.actor.casefold():
                raise WrongResponderError(
                    f"Only {event.alert.actor} may answer this verification request."
                )

            updated = event.model_copy(
                update={
                    "human_response": HumanResponse(
                        responder=response.responder,
                        response=response.response,
                    )
                },
                deep=True,
            )
            self._events[event_id] = updated
            return updated.model_copy(deep=True)
