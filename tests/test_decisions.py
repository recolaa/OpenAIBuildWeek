from __future__ import annotations

import time

from fastapi.testclient import TestClient

from tests.helpers import decision_for, drop_payload


def _incident(client: TestClient, event_id: str = "drop-decision-1") -> dict:
    response = client.post("/events/drop", json=drop_payload(event_id))
    assert response.status_code == 200
    return response.json()


def test_exact_temporary_approval_is_applied_and_expires(client: TestClient) -> None:
    incident = _incident(client)
    # Leave enough headroom for slower Windows/CI filesystem and SQLite startup.
    decision = decision_for(incident, ttl_seconds=2)

    response = client.post("/decisions", json=decision)

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "APPLIED"
    assert result["reason_code"] == "EXACT_SCOPE_TEMPORARY_GRANT"
    scope = incident["context_request"]["permitted_grant_scope"]
    assert client.post("/demo/check-flow", json=scope).json()["allowed"] is True

    time.sleep(2.2)
    client.post("/demo/expire")
    assert client.post("/demo/check-flow", json=scope).json()["allowed"] is False
    final = client.get(f"/incidents/{incident['incident_id']}").json()
    assert final["state"] == "REVOKED"


def test_mismatched_scope_is_rejected(client: TestClient) -> None:
    incident = _incident(client, "drop-mismatch-1")
    decision = decision_for(incident, decision_id="decision-mismatch")
    decision["grant_scope"]["destination_port"] = 22

    result = client.post("/decisions", json=decision).json()

    assert result["status"] == "REJECTED"
    assert result["reason_code"] == "SCOPE_MISMATCH"
    final = client.get(f"/incidents/{incident['incident_id']}").json()
    assert final["state"] == "WAITING_FOR_CONTEXT"


def test_cidr_scope_is_rejected_by_contract(client: TestClient) -> None:
    incident = _incident(client, "drop-cidr-1")
    decision = decision_for(incident, decision_id="decision-cidr")
    decision["grant_scope"]["source_ip"] = "0.0.0.0/0"

    response = client.post("/decisions", json=decision)

    assert response.status_code == 422


def test_overlong_ttl_and_wrong_role_are_rejected(client: TestClient) -> None:
    first = _incident(client, "drop-ttl-1")
    too_long = decision_for(first, decision_id="decision-ttl", ttl_seconds=601)
    result = client.post("/decisions", json=too_long).json()
    assert result["reason_code"] == "TTL_EXCEEDS_POLICY"

    second = _incident(client, "drop-role-1")
    wrong_role = decision_for(second, decision_id="decision-role")
    wrong_role["approved_by"]["role"] = "untrusted-bot"
    result = client.post("/decisions", json=wrong_role).json()
    assert result["reason_code"] == "APPROVER_NOT_ALLOWED"


def test_denial_retains_policy_without_firewall_change(client: TestClient) -> None:
    incident = _incident(client, "drop-deny-1")
    decision = decision_for(incident, decision_id="decision-deny", decision="DENY")

    result = client.post("/decisions", json=decision).json()

    assert result["status"] == "REJECTED"
    assert result["reason_code"] == "DECISION_DENIED"
    final = client.get(f"/incidents/{incident['incident_id']}").json()
    assert final["state"] == "DENIED"
