from __future__ import annotations

from fastapi.testclient import TestClient

from tests.helpers import drop_payload


def test_drop_creates_analysis_and_context_request(client: TestClient) -> None:
    response = client.post("/events/drop", json=drop_payload())

    assert response.status_code == 200
    incident = response.json()
    assert incident["state"] == "WAITING_FOR_CONTEXT"
    assert incident["analysis"]["recommended_action"] == "REQUEST_CONTEXT"
    assert incident["analysis"]["observed_facts"]
    request = incident["context_request"]
    assert request["event_id"] == "drop-test-1"
    assert request["permitted_grant_scope"] == {
        "source_ip": "10.0.2.1",
        "destination_ip": "10.0.3.10",
        "destination_port": 443,
        "protocol": "tcp",
        "direction": "forward",
        "interface_in": "eth0",
        "interface_out": "eth1",
    }
    assert "ALLOW_TEMPORARY" in request["allowed_responses"]

    outbox = client.get("/context-requests")
    assert outbox.status_code == 200
    assert outbox.json()[0]["request_id"] == request["request_id"]


def test_one_hundred_repeated_drops_create_one_incident(client: TestClient) -> None:
    first_incident_id = None
    for index in range(100):
        response = client.post("/events/drop", json=drop_payload(f"drop-burst-{index}"))
        assert response.status_code == 200
        incident = response.json()
        first_incident_id = first_incident_id or incident["incident_id"]
        assert incident["incident_id"] == first_incident_id

    final = client.get(f"/incidents/{first_incident_id}").json()
    assert final["packet_count"] == 100
    assert len(client.get("/context-requests").json()) == 1


def test_zeek_record_is_normalized_and_sent_for_context(client: TestClient) -> None:
    payload = {
        "schema_version": "zeek-event-v1",
        "event_id": "zeek-test-1",
        "log_type": "conn",
        "record": {
            "ts": 1784394060.125,
            "uid": "CxTest001",
            "id.orig_h": "10.0.2.44",
            "id.orig_p": 55001,
            "id.resp_h": "10.0.3.10",
            "id.resp_p": 22,
            "proto": "tcp",
            "service": "ssh",
            "conn_state": "S0",
        },
    }

    response = client.post("/events/zeek", json=payload)

    assert response.status_code == 200
    incident = response.json()
    assert incident["event"]["source"] == "zeek"
    assert incident["event"]["flow"]["destination_port"] == 22
    assert incident["context_request"] is not None


def test_incomplete_zeek_still_requests_non_enforceable_context(client: TestClient) -> None:
    payload = {
        "schema_version": "zeek-event-v1",
        "event_id": "zeek-incomplete-1",
        "log_type": "notice",
        "record": {
            "ts": 1784394060.125,
            "uid": "CxIncomplete",
            "note": "An unusual condition needs owner context",
        },
    }

    response = client.post("/events/zeek", json=payload)

    assert response.status_code == 200
    request = response.json()["context_request"]
    assert request["observed_flow"] is None
    assert request["permitted_grant_scope"] is None
    assert "ALLOW_TEMPORARY" not in request["allowed_responses"]
    assert "BLOCK_TEMPORARY" not in request["allowed_responses"]
