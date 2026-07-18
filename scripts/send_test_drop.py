from __future__ import annotations

import argparse
import json
import uuid
from datetime import UTC, datetime

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a fake firewall drop to IntentBridge")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--event-id", default=None)
    parser.add_argument("--token", default=None)
    args = parser.parse_args()
    payload = {
        "schema_version": "drop-event-v1",
        "event_id": args.event_id or f"drop-{uuid.uuid4().hex[:10]}",
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source_ip": "10.0.2.1",
        "destination_ip": "10.0.3.10",
        "source_port": 51842,
        "destination_port": 443,
        "protocol": "tcp",
        "direction": "forward",
        "rule_id": "BLOCK_VPN_SOURCE",
        "drop_reason": "Source IP categorized as VPN exit node",
        "interface_in": "eth0",
        "interface_out": "eth1",
    }
    headers = (
        {"Authorization": f"Bearer {args.token}"} if args.token is not None else None
    )
    response = httpx.post(
        f"{args.url.rstrip('/')}/events/drop",
        json=payload,
        headers=headers,
        timeout=45,
    )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
