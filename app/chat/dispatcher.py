from __future__ import annotations

import asyncio
from typing import Any

import httpx

from app.database import Database


class ChatDispatcher:
    """Delivers durable context requests or leaves them available for polling."""

    def __init__(
        self,
        database: Database,
        *,
        mode: str,
        url: str | None = None,
        token: str | None = None,
        max_attempts: int = 3,
    ):
        self.database = database
        self.mode = mode
        self.url = url
        self.token = token
        self.max_attempts = max_attempts

    async def dispatch(self, payload: dict[str, Any]) -> bool:
        if self.mode == "outbox":
            # The durable row is the delivery mechanism. A future chat agent can poll
            # GET /context-requests and answer through POST /decisions.
            return True
        if not self.url:
            raise RuntimeError("HTTP chat delivery requires a configured URL")

        headers = {"Idempotency-Key": str(payload["request_id"])}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        last_error: str | None = None
        async with httpx.AsyncClient(timeout=10.0) as client:
            for attempt in range(1, self.max_attempts + 1):
                try:
                    response = await client.post(self.url, json=payload, headers=headers)
                    response.raise_for_status()
                    self.database.update_context_delivery(payload["request_id"], delivered=True)
                    return True
                except httpx.HTTPError as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    if attempt < self.max_attempts:
                        await asyncio.sleep(min(2 ** (attempt - 1), 4))
        self.database.update_context_delivery(
            payload["request_id"], delivered=False, error=last_error
        )
        return False
