from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Reply to the latest chat context request")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument(
        "--decision",
        choices=["allow", "block", "deny", "more"],
        default="allow",
    )
    parser.add_argument("--ttl", type=int, default=15)
    parser.add_argument("--token", default=None)
    args = parser.parse_args()
    base = args.url.rstrip("/")
    headers = (
        {"Authorization": f"Bearer {args.token}"} if args.token is not None else None
    )
    requests = []
    for request_status in ("PENDING", "DELIVERED"):
        response = httpx.get(
            f"{base}/context-requests",
            params={"status": request_status},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        requests = response.json()
        if requests:
            break
    if not requests:
        raise SystemExit("No active context request is waiting")
    request = requests[0]
    action = {
        "allow": "ALLOW_TEMPORARY",
        "block": "BLOCK_TEMPORARY",
        "deny": "DENY",
        "more": "REQUEST_MORE_INFORMATION",
    }[args.decision]
    if action not in request["allowed_responses"] and not (
        action == "DENY" and "KEEP_CURRENT_POLICY" in request["allowed_responses"]
    ):
        raise SystemExit(f"{action} is not allowed for this request")
    payload = {
        "schema_version": "decision-v1",
        "decision_id": f"decision-{uuid.uuid4().hex[:12]}",
        "request_id": request["request_id"],
        "event_id": request["event_id"],
        "incident_id": request["incident_id"],
        "incident_version": request["incident_version"],
        "decision": action,
        "justification": "Simulated authorized response from the chat-side agent",
        "issued_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    if action in {"ALLOW_TEMPORARY", "BLOCK_TEMPORARY"}:
        if request["permitted_grant_scope"] is None:
            raise SystemExit("This request has no exact scope and cannot change the firewall")
        payload.update(
            {
                "grant_scope": request["permitted_grant_scope"],
                "ttl_seconds": args.ttl,
                "approved_by": {"id": "demo-manager", "role": "network-manager"},
            }
        )
    response = httpx.post(
        f"{base}/decisions", json=payload, headers=headers, timeout=15
    )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
