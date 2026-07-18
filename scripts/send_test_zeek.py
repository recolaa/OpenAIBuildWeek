from __future__ import annotations

import argparse
import json
import time
import uuid

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a fake Zeek connection record")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--token", default=None)
    args = parser.parse_args()
    uid = f"Cx{uuid.uuid4().hex[:10]}"
    payload = {
        "schema_version": "zeek-event-v1",
        "event_id": f"zeek-{uid}",
        "log_type": "conn",
        "sensor_id": "zeek-demo-1",
        "record": {
            "ts": time.time(),
            "uid": uid,
            "id.orig_h": "10.0.2.44",
            "id.orig_p": 55001,
            "id.resp_h": "10.0.3.10",
            "id.resp_p": 22,
            "proto": "tcp",
            "service": "ssh",
            "conn_state": "S0",
            "orig_pkts": 3,
            "orig_bytes": 420,
        },
    }
    headers = (
        {"Authorization": f"Bearer {args.token}"} if args.token is not None else None
    )
    response = httpx.post(
        f"{args.url.rstrip('/')}/events/zeek",
        json=payload,
        headers=headers,
        timeout=45,
    )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
