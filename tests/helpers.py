from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def now_text() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def drop_payload(event_id: str = "drop-test-1") -> dict[str, Any]:
    return {
        "schema_version": "drop-event-v1",
        "event_id": event_id,
        "timestamp": now_text(),
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


def decision_for(
    incident: dict[str, Any],
    *,
    decision_id: str = "decision-test-1",
    decision: str = "ALLOW_TEMPORARY",
    ttl_seconds: int = 30,
) -> dict[str, Any]:
    request = incident["context_request"]
    payload: dict[str, Any] = {
        "schema_version": "decision-v1",
        "decision_id": decision_id,
        "request_id": request["request_id"],
        "event_id": request["event_id"],
        "incident_id": request["incident_id"],
        "incident_version": request["incident_version"],
        "decision": decision,
        "justification": "Authorized test of the exact observed service flow",
        "issued_at": now_text(),
    }
    if decision in {"ALLOW_TEMPORARY", "BLOCK_TEMPORARY"}:
        payload.update(
            {
                "grant_scope": request["permitted_grant_scope"],
                "ttl_seconds": ttl_seconds,
                "approved_by": {"id": "manager-test", "role": "network-manager"},
            }
        )
    return payload

