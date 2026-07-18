from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import decision_for, drop_payload, now_text


def test_context_response_creates_correlated_followup_then_accepts_decision(
    client: TestClient,
) -> None:
    first = client.post(
        "/events/drop", json=drop_payload("drop-context-rounds")
    ).json()
    request = first["context_request"]
    response_payload = {
        "schema_version": "chat-context-response-v1",
        "response_id": "context-answer-round-1",
        "request_id": request["request_id"],
        "event_id": request["event_id"],
        "incident_id": request["incident_id"],
        "incident_version": request["incident_version"],
        "context_round": 1,
        "provided_context": [
            "The application owner reports this HTTPS retry is expected during deployment."
        ],
        "provided_by": {"id": "chat-agent-test", "role": "network-manager"},
        "issued_at": now_text(),
    }

    response = client.post("/context-responses", json=response_payload)

    assert response.status_code == 200
    second = response.json()
    assert second["state"] == "WAITING_FOR_CONTEXT"
    assert second["context_request"]["context_round"] == 2
    assert second["context_request"]["previous_request_id"] == request["request_id"]
    assert second["context_request"]["incident_version"] == second["version"]
    assert (
        client.get("/context-responses/context-answer-round-1").json()["trust"]
        == "UNTRUSTED_ADVISORY"
    )

    decision = decision_for(
        second, decision_id="decision-after-context", ttl_seconds=30
    )
    result = client.post("/decisions", json=decision).json()

    assert result["status"] == "APPLIED"
    assert result["reason_code"] == "EXACT_SCOPE_TEMPORARY_GRANT"

