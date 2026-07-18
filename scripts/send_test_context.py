from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Return missing organizational context to the latest request"
    )
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--answer",
        default=(
            "The application owner says this HTTPS retry is expected during an "
            "approved deployment window."
        ),
    )
    parser.add_argument("--token", default=None)
    args = parser.parse_args()
    base = args.url.rstrip("/")
    headers = (
        {"Authorization": f"Bearer {args.token}"} if args.token is not None else None
    )
    requests = []
    for request_status in ("PENDING", "DELIVERED"):
        result = httpx.get(
            f"{base}/context-requests",
            params={"status": request_status},
            headers=headers,
            timeout=10,
        )
        result.raise_for_status()
        requests = result.json()
        if requests:
            break
    if not requests:
        raise SystemExit("No active context request is waiting")
    request = requests[0]
    payload = {
        "schema_version": "chat-context-response-v1",
        "response_id": f"context-answer-{uuid.uuid4().hex[:12]}",
        "request_id": request["request_id"],
        "event_id": request["event_id"],
        "incident_id": request["incident_id"],
        "incident_version": request["incident_version"],
        "context_round": request["context_round"],
        "provided_context": [args.answer],
        "provided_by": {"id": "demo-chat-agent", "role": "network-manager"},
        "issued_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    result = httpx.post(
        f"{base}/context-responses",
        json=payload,
        headers=headers,
        timeout=45,
    )
    result.raise_for_status()
    print(json.dumps(result.json(), indent=2))


if __name__ == "__main__":
    main()
