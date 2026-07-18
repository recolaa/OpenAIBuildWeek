"""Minimal async client for idempotent coordinator response delivery."""

from __future__ import annotations

import os
from typing import Any, Optional

import httpx
from dotenv import load_dotenv

from models import (
    CallbackStatus,
    CoordinatorDeliveryResult,
    SecurityEvent,
)


COORDINATOR_TIMEOUT_SECONDS = 3.0


def _context_summary(event: SecurityEvent) -> str:
    context = event.ai_context
    if context is not None:
        return f"{context.inference} Unresolved: {context.unresolved_issue}"
    if event.analysis_error:
        return "Context analysis was unavailable; human verification remained required."
    return "No context analysis was available; human verification remained required."


def build_callback_payload(event: SecurityEvent) -> dict[str, Any]:
    """Build the strict summary payload; chat message bodies are never included."""

    callback = event.coordinator_callback
    human_response = event.human_response
    if callback is None or human_response is None:
        raise ValueError("A stored human response and callback state are required.")

    return {
        "callback_id": str(callback.callback_id),
        "event_id": str(event.id),
        "account_user": event.alert.actor,
        "responded_by": human_response.responder,
        "human_response": human_response.response.value,
        "responded_at": human_response.responded_at.isoformat(),
        "context_summary": _context_summary(event),
        "relevant_message_ids": [
            str(message_id)
            for message_id in (
                event.ai_context.relevant_message_ids if event.ai_context else []
            )
        ],
        "network_risk_score": event.alert.network_risk_score,
    }


def _coordinator_decision(response: httpx.Response) -> Optional[str]:
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None

    for key in ("final_coordinator_decision", "final_decision", "decision"):
        value = body.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


async def deliver_coordinator_callback(
    event: SecurityEvent,
    *,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> CoordinatorDeliveryResult:
    """Deliver one attempt using the event's stable callback ID."""

    load_dotenv()
    response_url = os.getenv("COORDINATOR_RESPONSE_URL", "").strip()
    if not response_url:
        return CoordinatorDeliveryResult(
            status=CallbackStatus.FAILED,
            last_error=(
                "Coordinator delivery is unavailable: "
                "COORDINATOR_RESPONSE_URL is not configured."
            ),
        )

    try:
        payload = build_callback_payload(event)
    except ValueError as exc:
        return CoordinatorDeliveryResult(
            status=CallbackStatus.FAILED, last_error=str(exc)
        )

    try:
        async with httpx.AsyncClient(
            timeout=COORDINATOR_TIMEOUT_SECONDS,
            transport=transport,
        ) as client:
            response = await client.post(
                response_url,
                json=payload,
                headers={"Idempotency-Key": payload["callback_id"]},
            )
    except httpx.TimeoutException:
        return CoordinatorDeliveryResult(
            status=CallbackStatus.FAILED,
            last_error="Coordinator delivery timed out.",
        )
    except httpx.RequestError:
        return CoordinatorDeliveryResult(
            status=CallbackStatus.FAILED,
            last_error="Could not connect to the coordinator service.",
        )

    decision = _coordinator_decision(response)
    if not 200 <= response.status_code < 300:
        return CoordinatorDeliveryResult(
            status=CallbackStatus.FAILED,
            response_status_code=response.status_code,
            last_error=f"Coordinator returned HTTP {response.status_code}.",
            coordinator_decision=decision,
        )

    return CoordinatorDeliveryResult(
        status=CallbackStatus.DELIVERED,
        response_status_code=response.status_code,
        coordinator_decision=decision,
    )

