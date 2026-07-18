"""FastAPI backend for the local workplace security chat MVP."""

from __future__ import annotations

from uuid import UUID

from fastapi import FastAPI, HTTPException, status

from ai_context import AIContextUnavailableError, analyze_context

from models import (
    HealthResponse,
    HumanResponseCreate,
    Message,
    MessageCreate,
    NetworkAlertCreate,
    SecurityEvent,
)
from store import (
    EventNotFoundError,
    InMemoryStore,
    ResponseAlreadyRecordedError,
    WrongResponderError,
)


app = FastAPI(
    title="Workplace Security Chat MVP",
    version="0.1.0",
    description="Local group chat, AI context analysis, and human verification.",
)
app.state.store = InMemoryStore()


def get_store() -> InMemoryStore:
    return app.state.store


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok")


@app.get("/messages", response_model=list[Message])
async def list_messages() -> list[Message]:
    return get_store().list_messages()


@app.post(
    "/messages", response_model=Message, status_code=status.HTTP_201_CREATED
)
async def create_message(message: MessageCreate) -> Message:
    return get_store().create_message(message)


@app.post(
    "/network-alerts",
    response_model=SecurityEvent,
    status_code=status.HTTP_201_CREATED,
)
async def create_network_alert(alert: NetworkAlertCreate) -> SecurityEvent:
    recent_messages = get_store().list_recent_user_messages()
    try:
        ai_context = await analyze_context(alert, recent_messages)
    except AIContextUnavailableError as exc:
        # Preserve the alert and mandatory human-verification path even when the
        # optional context dependency fails. Context is never authorization.
        return get_store().create_security_event(
            alert, analysis_error=str(exc)
        )

    return get_store().create_security_event(alert, ai_context=ai_context)


@app.get("/security-events/{event_id}", response_model=SecurityEvent)
async def get_security_event(event_id: UUID) -> SecurityEvent:
    try:
        return get_store().get_security_event(event_id)
    except EventNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Security event not found.") from exc


@app.post(
    "/security-events/{event_id}/human-response",
    response_model=SecurityEvent,
    status_code=status.HTTP_201_CREATED,
)
async def record_human_response(
    event_id: UUID, response: HumanResponseCreate
) -> SecurityEvent:
    try:
        return get_store().record_human_response(event_id, response)
    except EventNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Security event not found.") from exc
    except ResponseAlreadyRecordedError as exc:
        raise HTTPException(
            status_code=409,
            detail="A human response has already been recorded for this event.",
        ) from exc
    except WrongResponderError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
