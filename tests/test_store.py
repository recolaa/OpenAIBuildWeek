"""Restart-persistence tests for the SQLite audit store."""

from __future__ import annotations

from pathlib import Path

from models import (
    AIContextResult,
    CallbackStatus,
    CoordinatorDeliveryResult,
    HumanResponseCreate,
    MessageCreate,
    NetworkAlertCreate,
)
from store import SQLiteStore


def test_complete_history_survives_store_restart(tmp_path: Path) -> None:
    database_path = tmp_path / "history.db"
    store = SQLiteStore(database_path)
    chat_message = store.create_message(
        MessageCreate(
            author="Sicily",
            content="I am traveling and expect to connect through the VPN.",
        )
    )
    context = AIContextResult(
        observed_facts=["Sicily said she expects to use the VPN."],
        relevant_message_ids=[chat_message.id],
        inference="The VPN may explain the unusual source address.",
        unresolved_issue="The initiator remains unverified.",
        verification_target="Sicily",
        verification_question="This value is canonicalized by the store.",
        context_confidence=0.82,
    )
    event = store.create_security_event(
        NetworkAlertCreate(
            actor="Sicily",
            request_summary="rotate the production TLS certificate",
            network_risk_score=0.88,
        ),
        ai_context=context,
    )
    store.record_human_response(
        event.id,
        HumanResponseCreate(responder="Sicily", response="Unsure"),
    )

    first_attempt = store.begin_callback_attempt(event.id, is_retry=False)
    callback_id = first_attempt.coordinator_callback.callback_id
    store.finish_callback_attempt(
        event.id,
        CoordinatorDeliveryResult(
            status=CallbackStatus.FAILED,
            response_status_code=503,
            last_error="Coordinator returned HTTP 503.",
        ),
    )
    store.begin_callback_attempt(event.id, is_retry=True)
    store.finish_callback_attempt(
        event.id,
        CoordinatorDeliveryResult(
            status=CallbackStatus.DELIVERED,
            response_status_code=202,
            coordinator_decision="escalate",
        ),
    )
    store.close()

    reopened = SQLiteStore(database_path)
    messages = reopened.list_messages()
    restored = reopened.get_security_event(event.id)

    assert [message.content for message in messages] == [
        "I am traveling and expect to connect through the VPN.",
        'Sicily, did you initiate this specific privileged action: '
        '"rotate the production TLS certificate"?',
    ]
    assert restored.ai_context.relevant_message_ids == [chat_message.id]
    assert restored.human_response.response.value == "Unsure"
    assert restored.coordinator_callback.callback_id == callback_id
    assert restored.coordinator_callback.status == CallbackStatus.DELIVERED
    assert restored.coordinator_callback.attempt_count == 2
    assert restored.coordinator_callback.coordinator_decision == "escalate"
    assert [attempt.status for attempt in restored.coordinator_callback_attempts] == [
        CallbackStatus.FAILED,
        CallbackStatus.DELIVERED,
    ]
    assert restored.coordinator_callback_attempts[0].response_status_code == 503
    assert restored.coordinator_callback_attempts[1].response_status_code == 202
    reopened.close()

