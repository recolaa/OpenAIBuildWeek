"""Thread-safe SQLite persistence for chat and security-event history."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import RLock
from typing import Optional, Union
from uuid import UUID, uuid4

from models import (
    AIContextResult,
    AIAnalysisStatus,
    AnalysisStatus,
    CallbackStatus,
    CoordinatorCallbackAttempt,
    CoordinatorCallbackState,
    CoordinatorDeliveryResult,
    HumanResponse,
    HumanResponseCreate,
    Message,
    MessageCreate,
    MessageKind,
    NetworkAlertCreate,
    SecurityEvent,
    build_verification_question,
    utc_now,
)


class EventNotFoundError(LookupError):
    pass


class ResponseAlreadyRecordedError(RuntimeError):
    pass


class WrongResponderError(ValueError):
    pass


class CallbackNotAvailableError(RuntimeError):
    pass


class CallbackNotRetryableError(RuntimeError):
    pass


DatabasePath = Union[str, Path]


class SQLiteStore:
    """Durable local store; operations are serialized per process."""

    def __init__(self, database_path: DatabasePath = "chat_history.db") -> None:
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).expanduser().parent.mkdir(
                parents=True, exist_ok=True
            )
        self._connection = sqlite3.connect(
            self.database_path,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = RLock()
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.execute("PRAGMA foreign_keys = ON")
            if self.database_path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    author TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    security_event_id TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_messages_created_at
                    ON messages(created_at);
                CREATE INDEX IF NOT EXISTS idx_messages_kind_created_at
                    ON messages(kind, created_at);

                CREATE TABLE IF NOT EXISTS security_events (
                    id TEXT PRIMARY KEY,
                    alert_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    analysis_status TEXT NOT NULL,
                    ai_context_json TEXT,
                    analysis_error TEXT,
                    verification_message_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS human_responses (
                    event_id TEXT PRIMARY KEY,
                    responder TEXT NOT NULL,
                    response TEXT NOT NULL,
                    responded_at TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES security_events(id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS coordinator_callbacks (
                    callback_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL,
                    response_status_code INTEGER,
                    attempt_count INTEGER NOT NULL,
                    last_error TEXT,
                    coordinator_decision TEXT,
                    FOREIGN KEY(event_id) REFERENCES security_events(id)
                        ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS coordinator_callback_attempts (
                    callback_id TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    response_status_code INTEGER,
                    last_error TEXT,
                    coordinator_decision TEXT,
                    PRIMARY KEY(callback_id, attempt_number),
                    FOREIGN KEY(callback_id)
                        REFERENCES coordinator_callbacks(callback_id)
                        ON DELETE CASCADE
                );
                """
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def reset(self) -> None:
        """Clear all persisted state. Intended for isolated tests."""

        with self._lock, self._connection:
            self._connection.execute("DELETE FROM messages")
            self._connection.execute("DELETE FROM security_events")

    @staticmethod
    def _message_from_row(row: sqlite3.Row) -> Message:
        return Message(
            id=row["id"],
            author=row["author"],
            content=row["content"],
            created_at=row["created_at"],
            kind=row["kind"],
            security_event_id=row["security_event_id"],
        )

    def _insert_message(self, message: Message) -> None:
        self._connection.execute(
            """
            INSERT INTO messages(
                id, author, content, created_at, kind, security_event_id
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(message.id),
                message.author,
                message.content,
                message.created_at.isoformat(),
                message.kind.value,
                str(message.security_event_id)
                if message.security_event_id is not None
                else None,
            ),
        )

    def list_messages(self) -> list[Message]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM messages ORDER BY created_at, rowid"
            ).fetchall()
            return [self._message_from_row(row) for row in rows]

    def list_recent_user_messages(self, limit: int = 50) -> list[Message]:
        """Return recent human chat only, excluding security-bot prompts."""

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM messages
                WHERE kind = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (MessageKind.USER.value, limit),
            ).fetchall()
            return [self._message_from_row(row) for row in reversed(rows)]

    def create_message(self, message: MessageCreate) -> Message:
        stored = Message(author=message.author, content=message.content)
        with self._lock, self._connection:
            self._insert_message(stored)
        return stored.model_copy(deep=True)

    def create_security_event(
        self,
        alert: NetworkAlertCreate,
        *,
        ai_context: Optional[AIContextResult] = None,
        analysis_error: Optional[str] = None,
    ) -> SecurityEvent:
        """Persist analysis state and its mandatory verification message."""

        with self._lock, self._connection:
            event_id = uuid4()
            verification_question = build_verification_question(
                alert.actor, alert.request_summary, alert.detected_at
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
            if canonical_context is None:
                event_analysis_status = (
                    AnalysisStatus.FAILED
                    if analysis_error is not None
                    else AnalysisStatus.NOT_RUN
                )
            elif canonical_context.context_status == AIAnalysisStatus.AI_UNAVAILABLE:
                event_analysis_status = AnalysisStatus.FAILED
            else:
                event_analysis_status = AnalysisStatus.COMPLETED
            message = Message(
                author="Security Bot",
                content=verification_question,
                kind=MessageKind.SECURITY_VERIFICATION,
                security_event_id=event_id,
            )
            event = SecurityEvent(
                id=event_id,
                alert=alert,
                analysis_status=event_analysis_status,
                ai_context=canonical_context,
                analysis_error=(
                    canonical_context.ai_error.value
                    if canonical_context is not None
                    and canonical_context.ai_error is not None
                    else analysis_error
                ),
                verification_message_id=message.id,
            )
            self._connection.execute(
                """
                INSERT INTO security_events(
                    id, alert_json, created_at, analysis_status,
                    ai_context_json, analysis_error, verification_message_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event.id),
                    event.alert.model_dump_json(),
                    event.created_at.isoformat(),
                    event.analysis_status.value,
                    event.ai_context.model_dump_json()
                    if event.ai_context is not None
                    else None,
                    event.analysis_error,
                    str(event.verification_message_id),
                ),
            )
            self._insert_message(message)
            return event.model_copy(deep=True)

    def _event_from_row(self, row: sqlite3.Row) -> SecurityEvent:
        human_row = self._connection.execute(
            "SELECT * FROM human_responses WHERE event_id = ?", (row["id"],)
        ).fetchone()
        callback_row = self._connection.execute(
            "SELECT * FROM coordinator_callbacks WHERE event_id = ?",
            (row["id"],),
        ).fetchone()

        human_response = (
            HumanResponse(
                responder=human_row["responder"],
                response=human_row["response"],
                responded_at=human_row["responded_at"],
            )
            if human_row is not None
            else None
        )
        coordinator_callback = (
            CoordinatorCallbackState(
                callback_id=callback_row["callback_id"],
                status=callback_row["status"],
                response_status_code=callback_row["response_status_code"],
                attempt_count=callback_row["attempt_count"],
                last_error=callback_row["last_error"],
                coordinator_decision=callback_row["coordinator_decision"],
            )
            if callback_row is not None
            else None
        )

        attempt_rows = (
            self._connection.execute(
                """
                SELECT * FROM coordinator_callback_attempts
                WHERE callback_id = ?
                ORDER BY attempt_number
                """,
                (callback_row["callback_id"],),
            ).fetchall()
            if callback_row is not None
            else []
        )
        attempts = [
            CoordinatorCallbackAttempt(
                callback_id=attempt["callback_id"],
                attempt_number=attempt["attempt_number"],
                status=attempt["status"],
                started_at=attempt["started_at"],
                completed_at=attempt["completed_at"],
                response_status_code=attempt["response_status_code"],
                last_error=attempt["last_error"],
                coordinator_decision=attempt["coordinator_decision"],
            )
            for attempt in attempt_rows
        ]

        return SecurityEvent(
            id=row["id"],
            alert=NetworkAlertCreate.model_validate_json(row["alert_json"]),
            created_at=row["created_at"],
            analysis_status=row["analysis_status"],
            ai_context=AIContextResult.model_validate_json(row["ai_context_json"])
            if row["ai_context_json"] is not None
            else None,
            analysis_error=row["analysis_error"],
            verification_message_id=row["verification_message_id"],
            human_response=human_response,
            coordinator_callback=coordinator_callback,
            coordinator_callback_attempts=attempts,
        )

    def _get_event_row(self, event_id: UUID) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM security_events WHERE id = ?", (str(event_id),)
        ).fetchone()
        if row is None:
            raise EventNotFoundError(str(event_id))
        return row

    def get_security_event(self, event_id: UUID) -> SecurityEvent:
        with self._lock:
            return self._event_from_row(self._get_event_row(event_id))

    def record_human_response(
        self, event_id: UUID, response: HumanResponseCreate
    ) -> SecurityEvent:
        with self._lock, self._connection:
            event = self._event_from_row(self._get_event_row(event_id))
            if event.human_response is not None:
                raise ResponseAlreadyRecordedError(str(event_id))
            if response.responder.casefold() != event.alert.actor.casefold():
                raise WrongResponderError(
                    f"Only {event.alert.actor} may answer this verification request."
                )

            human_response = HumanResponse(
                responder=response.responder,
                response=response.response,
            )
            callback = CoordinatorCallbackState()
            self._connection.execute(
                """
                INSERT INTO human_responses(
                    event_id, responder, response, responded_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    str(event_id),
                    human_response.responder,
                    human_response.response.value,
                    human_response.responded_at.isoformat(),
                ),
            )
            self._connection.execute(
                """
                INSERT INTO coordinator_callbacks(
                    callback_id, event_id, status, response_status_code,
                    attempt_count, last_error, coordinator_decision
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(callback.callback_id),
                    str(event_id),
                    callback.status.value,
                    callback.response_status_code,
                    callback.attempt_count,
                    callback.last_error,
                    callback.coordinator_decision,
                ),
            )
            return self._event_from_row(self._get_event_row(event_id))

    def begin_callback_attempt(
        self, event_id: UUID, *, is_retry: bool
    ) -> SecurityEvent:
        """Atomically reserve and audit one initial or retry delivery attempt."""

        with self._lock, self._connection:
            event = self._event_from_row(self._get_event_row(event_id))
            callback = event.coordinator_callback
            if event.human_response is None or callback is None:
                raise CallbackNotAvailableError(str(event_id))

            if is_retry:
                if callback.status != CallbackStatus.FAILED:
                    raise CallbackNotRetryableError(
                        "Only failed coordinator callbacks can be retried."
                    )
            elif callback.status != CallbackStatus.PENDING or callback.attempt_count != 0:
                raise CallbackNotRetryableError(
                    "The coordinator callback delivery has already been attempted."
                )

            attempt_number = callback.attempt_count + 1
            started_at = utc_now()
            self._connection.execute(
                """
                UPDATE coordinator_callbacks
                SET status = ?, attempt_count = ?, response_status_code = NULL,
                    last_error = NULL, coordinator_decision = NULL
                WHERE event_id = ?
                """,
                (
                    CallbackStatus.PENDING.value,
                    attempt_number,
                    str(event_id),
                ),
            )
            self._connection.execute(
                """
                INSERT INTO coordinator_callback_attempts(
                    callback_id, attempt_number, status, started_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    str(callback.callback_id),
                    attempt_number,
                    CallbackStatus.PENDING.value,
                    started_at.isoformat(),
                ),
            )
            return self._event_from_row(self._get_event_row(event_id))

    def finish_callback_attempt(
        self, event_id: UUID, result: CoordinatorDeliveryResult
    ) -> SecurityEvent:
        """Finish an attempt without modifying its durable human response."""

        with self._lock, self._connection:
            event = self._event_from_row(self._get_event_row(event_id))
            callback = event.coordinator_callback
            if callback is None:
                raise CallbackNotAvailableError(str(event_id))
            if callback.status != CallbackStatus.PENDING or callback.attempt_count < 1:
                raise CallbackNotRetryableError(
                    "No coordinator callback attempt is currently pending."
                )

            completed_at = utc_now().isoformat()
            self._connection.execute(
                """
                UPDATE coordinator_callbacks
                SET status = ?, response_status_code = ?, last_error = ?,
                    coordinator_decision = ?
                WHERE event_id = ?
                """,
                (
                    result.status.value,
                    result.response_status_code,
                    result.last_error,
                    result.coordinator_decision,
                    str(event_id),
                ),
            )
            self._connection.execute(
                """
                UPDATE coordinator_callback_attempts
                SET status = ?, completed_at = ?, response_status_code = ?,
                    last_error = ?, coordinator_decision = ?
                WHERE callback_id = ? AND attempt_number = ?
                """,
                (
                    result.status.value,
                    completed_at,
                    result.response_status_code,
                    result.last_error,
                    result.coordinator_decision,
                    str(callback.callback_id),
                    callback.attempt_count,
                ),
            )
            return self._event_from_row(self._get_event_row(event_id))
