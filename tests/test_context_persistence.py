from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.database import ContextConflict, Database, DecisionConflict
from app.schemas import ChatContextResponse, ContextRequest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _iso(offset_seconds: int = 0) -> str:
    return (
        (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")
    )


def _waiting_incident(database: Database, event_id: str) -> dict:
    event = _fixture("normalized_drop_vpn_https.json")
    event["event_id"] = event_id
    incident, duplicate = database.create_or_deduplicate_event(event, event_id, 30)
    assert duplicate is False
    database.transition_incident(incident["incident_id"], {"DETECTED"}, "ANALYZING")
    return database.transition_incident(
        incident["incident_id"], {"ANALYZING"}, "WAITING_FOR_CONTEXT"
    )


def _first_request(incident: dict, event_id: str) -> ContextRequest:
    payload = _fixture("context_request_vpn_https.json")
    payload.update(
        {
            "request_id": f"ctx-{event_id}",
            "event_id": event_id,
            "incident_id": incident["incident_id"],
            "incident_version": incident["version"],
            "created_at": _iso(),
            "expires_at": _iso(120),
        }
    )
    return ContextRequest.model_validate(payload)


def test_context_response_claim_and_followup_are_versioned_atomically(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "context.db")
    database.initialize()
    event_id = "drop-context-rounds"
    incident = _waiting_incident(database, event_id)
    first = _first_request(incident, event_id)
    database.create_context_request(first.model_dump(mode="json"))

    response_payload = _fixture("chat_context_response_vpn_https.json")
    response_payload.update(
        {
            "response_id": "ctx-response-rounds-1",
            "request_id": first.request_id,
            "event_id": event_id,
            "incident_id": incident["incident_id"],
            "incident_version": incident["version"],
            "issued_at": _iso(),
        }
    )
    response = ChatContextResponse.model_validate(response_payload)
    updated, old_request, stored = database.store_context_response(response.model_dump(mode="json"))

    assert updated["version"] == incident["version"] + 1
    assert old_request["status"] == "RESPONSE_RECEIVED"
    assert stored["status"] == "RECEIVED"
    with pytest.raises(DecisionConflict):
        database.claim_context_request(
            "decision-too-late",
            first.request_id,
            incident["version"],
            {"decision_id": "decision-too-late"},
        )

    database.claim_context_response(response.response_id, updated["version"])
    followup_payload = _fixture("context_request_vpn_https_round_2.json")
    followup_payload.update(
        {
            "request_id": "ctx-rounds-2",
            "previous_request_id": first.request_id,
            "event_id": event_id,
            "incident_id": incident["incident_id"],
            "incident_version": updated["version"],
            "created_at": _iso(),
            "expires_at": _iso(120),
        }
    )
    followup = ContextRequest.model_validate(followup_payload)
    created = database.create_followup_context_request(
        followup.model_dump(mode="json"), response.response_id
    )

    assert created["context_round"] == 2
    assert created["previous_request_id"] == first.request_id
    assert database.get_context_request(first.request_id)["status"] == "CONSUMED"
    assert database.get_context_response(response.response_id)["status"] == "CONSUMED"
    assert len(database.list_context_requests(limit=10)) == 2


def test_context_response_replay_and_round_skipping_fail_closed(tmp_path: Path) -> None:
    database = Database(tmp_path / "context-replay.db")
    database.initialize()
    event_id = "drop-context-replay"
    incident = _waiting_incident(database, event_id)
    first = _first_request(incident, event_id)
    database.create_context_request(first.model_dump(mode="json"))
    payload = _fixture("chat_context_response_vpn_https.json")
    payload.update(
        {
            "response_id": "ctx-response-replay-1",
            "request_id": first.request_id,
            "event_id": event_id,
            "incident_id": incident["incident_id"],
            "incident_version": incident["version"],
            "issued_at": _iso(),
        }
    )
    response = ChatContextResponse.model_validate(payload)
    database.store_context_response(response.model_dump(mode="json"))
    with pytest.raises(ContextConflict, match="already"):
        database.store_context_response(response.model_dump(mode="json"))


def test_managed_rule_lifecycle_hides_uninstalled_and_cleanup_rules(tmp_path: Path) -> None:
    database = Database(tmp_path / "rules.db")
    database.initialize()
    incident = _waiting_incident(database, "drop-rule-lifecycle")
    rule_id = "ibr-1784395000-0123456789abcdef0123456789abcdef"
    database.reserve_managed_rule(
        rule_id=rule_id,
        incident_id=incident["incident_id"],
        decision_id="decision-rule-lifecycle",
        action="ALLOW",
        expires_at=_iso(60),
        scope={"source_ip": "10.0.2.1"},
    )
    assert database.list_active_rules() == []
    database.activate_managed_rule(rule_id, {"rule_id": rule_id})
    assert [row["rule_id"] for row in database.list_desired_rules()] == [rule_id]

    database.mark_rule_cleanup_required(rule_id, "COMPENSATION_FAILED")
    assert database.list_active_rules() == []
    assert database.list_rules_requiring_cleanup()[0]["rule_id"] == rule_id
    database.mark_rule_revoked(rule_id)
    assert database.list_rules_requiring_cleanup() == []


def test_initialize_migrates_legacy_single_request_constraint(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE context_requests (
                request_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL UNIQUE,
                event_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                delivery_attempts INTEGER NOT NULL DEFAULT 0,
                last_delivery_error TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )

    database = Database(path)
    database.initialize()
    with database.connect() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(context_requests)")}
        unique_indexes = [
            [
                column["name"]
                for column in connection.execute(f"PRAGMA index_info('{index['name']}')")
            ]
            for index in connection.execute("PRAGMA index_list(context_requests)")
            if index["unique"]
        ]
    assert {"context_round", "previous_request_id"}.issubset(columns)
    assert ["incident_id"] not in unique_indexes
    assert ["incident_id", "context_round"] in unique_indexes
