from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path
from typing import Any

from app.time_utils import isoformat_z, parse_timestamp, utc_now


class DatabaseError(RuntimeError):
    pass


class StateConflict(DatabaseError):
    pass


class DecisionConflict(DatabaseError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class ContextConflict(DatabaseError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


class ClosingConnection(sqlite3.Connection):
    """Commit or roll back like sqlite3's context manager, then close on Windows."""

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


JSON_COLUMNS = {
    "event_json",
    "evidence_json",
    "analysis_json",
    "decision_json",
    "enforcement_json",
    "payload_json",
    "details_json",
    "scope_json",
    "receipt_json",
}


INCIDENT_MUTABLE_COLUMNS = {
    "state",
    "evidence_json",
    "analysis_json",
    "request_id",
    "request_expires_at",
    "decision_id",
    "decision_json",
    "enforcement_json",
    "firewall_rule_id",
    "expires_at",
    "last_error_code",
    "last_error_detail",
}


def _json_dump(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    for column in JSON_COLUMNS:
        if column in result and result[column] is not None:
            result[column] = json.loads(result[column])
    for flag in ("deduplicated",):
        if flag in result:
            result[flag] = bool(result[flag])
    return result


class Database:
    """Small SQLite repository with serialized writes and explicit transactions."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=10,
            check_same_thread=False,
            factory=ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    primary_event_id TEXT NOT NULL UNIQUE,
                    fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    packet_count INTEGER NOT NULL DEFAULT 1,
                    state TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 0,
                    event_json TEXT NOT NULL,
                    evidence_json TEXT,
                    analysis_json TEXT,
                    request_id TEXT,
                    request_expires_at TEXT,
                    decision_id TEXT,
                    decision_json TEXT,
                    enforcement_json TEXT,
                    firewall_rule_id TEXT,
                    expires_at TEXT,
                    last_error_code TEXT,
                    last_error_detail TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_fingerprint_seen
                    ON incidents(fingerprint, last_seen_at);
                CREATE INDEX IF NOT EXISTS idx_incidents_state
                    ON incidents(state);

                CREATE TABLE IF NOT EXISTS network_events (
                    event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    received_at TEXT NOT NULL,
                    deduplicated INTEGER NOT NULL,
                    event_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS context_requests (
                    request_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    event_id TEXT NOT NULL,
                    context_round INTEGER NOT NULL DEFAULT 1,
                    previous_request_id TEXT REFERENCES context_requests(request_id),
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    delivery_attempts INTEGER NOT NULL DEFAULT 0,
                    last_delivery_error TEXT,
                    payload_json TEXT NOT NULL,
                    UNIQUE(incident_id, context_round)
                );

                CREATE INDEX IF NOT EXISTS idx_context_requests_status
                    ON context_requests(status, created_at);

                CREATE TABLE IF NOT EXISTS decisions (
                    decision_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    incident_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason_code TEXT,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS managed_rules (
                    rule_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(incident_id),
                    decision_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    revoked_at TEXT,
                    last_error TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_managed_rules_expiry
                    ON managed_rules(status, expires_at);

                CREATE TABLE IF NOT EXISTS audit_events (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    incident_id TEXT,
                    event_id TEXT,
                    component TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_incident
                    ON audit_events(incident_id, audit_id);
                """
            )
            self._migrate_context_requests(connection)
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_context_requests_status
                    ON context_requests(status, created_at);

                CREATE TABLE IF NOT EXISTS context_responses (
                    response_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE REFERENCES context_requests(request_id),
                    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                    event_id TEXT NOT NULL,
                    incident_version INTEGER NOT NULL,
                    context_round INTEGER NOT NULL,
                    received_at TEXT NOT NULL,
                    claimed_at TEXT,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_context_responses_status
                    ON context_responses(status, received_at);
                """
            )

    def _migrate_context_requests(self, connection: sqlite3.Connection) -> None:
        """Remove the v1 one-request-per-incident constraint without losing rows."""

        columns = {row["name"] for row in connection.execute("PRAGMA table_info(context_requests)")}
        has_single_incident_unique = False
        for index in connection.execute("PRAGMA index_list(context_requests)"):
            if not index["unique"]:
                continue
            indexed_columns = [
                row["name"] for row in connection.execute(f"PRAGMA index_info('{index['name']}')")
            ]
            if indexed_columns == ["incident_id"]:
                has_single_incident_unique = True
                break

        if {
            "context_round",
            "previous_request_id",
        }.issubset(columns) and not has_single_incident_unique:
            return

        connection.execute("ALTER TABLE context_requests RENAME TO context_requests_legacy")
        connection.execute(
            """
            CREATE TABLE context_requests (
                request_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
                event_id TEXT NOT NULL,
                context_round INTEGER NOT NULL DEFAULT 1,
                previous_request_id TEXT REFERENCES context_requests(request_id),
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                status TEXT NOT NULL,
                delivery_attempts INTEGER NOT NULL DEFAULT 0,
                last_delivery_error TEXT,
                payload_json TEXT NOT NULL,
                UNIQUE(incident_id, context_round)
            )
            """
        )
        round_expression = "context_round" if "context_round" in columns else "1"
        previous_expression = "previous_request_id" if "previous_request_id" in columns else "NULL"
        connection.execute(
            f"""
            INSERT INTO context_requests (
                request_id, incident_id, event_id, context_round, previous_request_id,
                created_at, expires_at, status, delivery_attempts,
                last_delivery_error, payload_json
            )
            SELECT request_id, incident_id, event_id, {round_expression},
                   {previous_expression}, created_at, expires_at, status,
                   delivery_attempts, last_delivery_error, payload_json
            FROM context_requests_legacy
            """
        )
        connection.execute("DROP TABLE context_requests_legacy")

    def healthcheck(self) -> bool:
        with self.connect() as connection:
            return connection.execute("SELECT 1").fetchone()[0] == 1

    def create_or_deduplicate_event(
        self,
        event: dict[str, Any],
        fingerprint: str,
        dedup_window_seconds: int,
    ) -> tuple[dict[str, Any], bool]:
        now = utc_now()
        now_text = isoformat_z(now)
        cutoff = isoformat_z(now - timedelta(seconds=dedup_window_seconds))
        event_id = str(event["event_id"])
        event_json = _json_dump(event)

        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing_event = connection.execute(
                "SELECT incident_id FROM network_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if existing_event:
                incident = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id = ?",
                    (existing_event["incident_id"],),
                ).fetchone()
                connection.commit()
                return _row_to_dict(incident) or {}, True

            duplicate = connection.execute(
                """
                SELECT * FROM incidents
                WHERE fingerprint = ? AND last_seen_at >= ?
                ORDER BY last_seen_at DESC LIMIT 1
                """,
                (fingerprint, cutoff),
            ).fetchone()
            if duplicate:
                incident_id = duplicate["incident_id"]
                connection.execute(
                    """
                    UPDATE incidents
                    SET packet_count = packet_count + 1,
                        last_seen_at = ?, updated_at = ?
                    WHERE incident_id = ?
                    """,
                    (now_text, now_text, incident_id),
                )
                connection.execute(
                    """
                    INSERT INTO network_events
                        (event_id, incident_id, received_at, deduplicated, event_json)
                    VALUES (?, ?, ?, 1, ?)
                    """,
                    (event_id, incident_id, now_text, event_json),
                )
                incident = connection.execute(
                    "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
                ).fetchone()
                connection.commit()
                return _row_to_dict(incident) or {}, True

            incident_id = f"inc-{uuid.uuid4().hex[:16]}"
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, primary_event_id, fingerprint, created_at, updated_at,
                    first_seen_at, last_seen_at, packet_count, state, version, event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'DETECTED', 0, ?)
                """,
                (
                    incident_id,
                    event_id,
                    fingerprint,
                    now_text,
                    now_text,
                    now_text,
                    now_text,
                    event_json,
                ),
            )
            connection.execute(
                """
                INSERT INTO network_events
                    (event_id, incident_id, received_at, deduplicated, event_json)
                VALUES (?, ?, ?, 0, ?)
                """,
                (event_id, incident_id, now_text, event_json),
            )
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            connection.commit()
            return _row_to_dict(incident) or {}, False

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            return _row_to_dict(
                connection.execute(
                    "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
                ).fetchone()
            )

    def get_incident_by_event(self, event_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT i.* FROM incidents i
                JOIN network_events e ON e.incident_id = i.incident_id
                WHERE e.event_id = ?
                """,
                (event_id,),
            ).fetchone()
            return _row_to_dict(row)

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [_row_to_dict(row) or {} for row in rows]

    def transition_incident(
        self,
        incident_id: str,
        allowed_states: Iterable[str],
        new_state: str,
        **fields: Any,
    ) -> dict[str, Any]:
        unknown = set(fields) - INCIDENT_MUTABLE_COLUMNS
        if unknown:
            raise DatabaseError(f"Unsupported incident fields: {sorted(unknown)}")
        now_text = isoformat_z()
        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if current is None:
                raise DatabaseError(f"Unknown incident {incident_id}")
            allowed = set(allowed_states)
            if current["state"] not in allowed:
                raise StateConflict(
                    f"Cannot transition {incident_id} from {current['state']} to {new_state}"
                )

            assignments = ["state = ?", "version = version + 1", "updated_at = ?"]
            values: list[Any] = [new_state, now_text]
            for key, value in fields.items():
                assignments.append(f"{key} = ?")
                values.append(
                    _json_dump(value) if key in JSON_COLUMNS and value is not None else value
                )
            values.append(incident_id)
            connection.execute(
                f"UPDATE incidents SET {', '.join(assignments)} WHERE incident_id = ?", values
            )
            updated = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            connection.commit()
            return _row_to_dict(updated) or {}

    def update_incident(self, incident_id: str, **fields: Any) -> dict[str, Any]:
        unknown = set(fields) - INCIDENT_MUTABLE_COLUMNS
        if unknown:
            raise DatabaseError(f"Unsupported incident fields: {sorted(unknown)}")
        if not fields:
            incident = self.get_incident(incident_id)
            if incident is None:
                raise DatabaseError(f"Unknown incident {incident_id}")
            return incident
        assignments = ["updated_at = ?"]
        values: list[Any] = [isoformat_z()]
        for key, value in fields.items():
            assignments.append(f"{key} = ?")
            values.append(_json_dump(value) if key in JSON_COLUMNS and value is not None else value)
        values.append(incident_id)
        with self._lock, self.connect() as connection:
            connection.execute(
                f"UPDATE incidents SET {', '.join(assignments)} WHERE incident_id = ?", values
            )
            updated = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if updated is None:
                raise DatabaseError(f"Unknown incident {incident_id}")
            return _row_to_dict(updated) or {}

    @staticmethod
    def _insert_context_request(connection: sqlite3.Connection, payload: dict[str, Any]) -> None:
        connection.execute(
            """
            INSERT INTO context_requests (
                request_id, incident_id, event_id, context_round,
                previous_request_id, created_at, expires_at, status,
                delivery_attempts, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', 0, ?)
            """,
            (
                payload["request_id"],
                payload["incident_id"],
                payload["event_id"],
                payload.get("context_round", 1),
                payload.get("previous_request_id"),
                payload["created_at"],
                payload["expires_at"],
                _json_dump(payload),
            ),
        )
        connection.execute(
            """
            UPDATE incidents
            SET request_id = ?, request_expires_at = ?, updated_at = ?
            WHERE incident_id = ?
            """,
            (
                payload["request_id"],
                payload["expires_at"],
                isoformat_z(),
                payload["incident_id"],
            ),
        )

    def create_context_request(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create the first request round; later rounds require a claimed response."""

        context_round = payload.get("context_round", 1)
        if context_round != 1 or payload.get("previous_request_id") is not None:
            raise ContextConflict(
                "FOLLOWUP_REQUIRES_CONTEXT_RESPONSE",
                "Later request rounds must use create_followup_context_request",
            )
        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (payload["incident_id"],)
            ).fetchone()
            if incident is None:
                raise ContextConflict("UNKNOWN_INCIDENT", "Incident does not exist")
            if incident["primary_event_id"] != payload["event_id"]:
                raise ContextConflict(
                    "CONTEXT_CORRELATION_MISMATCH",
                    "Context request event does not match the incident",
                )
            if incident["state"] != "WAITING_FOR_CONTEXT":
                raise ContextConflict("INCIDENT_NOT_WAITING", "Incident is not awaiting context")
            if incident["version"] != payload["incident_version"]:
                raise ContextConflict("STALE_INCIDENT_VERSION", "Context request version is stale")
            self._insert_context_request(connection, payload)
            row = connection.execute(
                "SELECT * FROM context_requests WHERE request_id = ?",
                (payload["request_id"],),
            ).fetchone()
            connection.commit()
            return _row_to_dict(row) or {}

    def get_context_request(self, request_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            return _row_to_dict(
                connection.execute(
                    "SELECT * FROM context_requests WHERE request_id = ?", (request_id,)
                ).fetchone()
            )

    def store_context_response(
        self, payload: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Persist one response and atomically invalidate its request version."""

        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM context_responses WHERE response_id = ?",
                (payload["response_id"],),
            ).fetchone():
                raise ContextConflict(
                    "REPLAYED_CONTEXT_RESPONSE", "Context response ID has already been used"
                )
            request = connection.execute(
                "SELECT * FROM context_requests WHERE request_id = ?",
                (payload["request_id"],),
            ).fetchone()
            if request is None:
                raise ContextConflict("UNKNOWN_REQUEST", "Context request does not exist")
            if request["status"] not in {"PENDING", "DELIVERED"}:
                raise ContextConflict("REQUEST_ALREADY_USED", "Context request is no longer active")
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (request["incident_id"],)
            ).fetchone()
            if incident is None:
                raise ContextConflict("UNKNOWN_INCIDENT", "Incident does not exist")
            if incident["state"] != "WAITING_FOR_CONTEXT":
                raise ContextConflict("INCIDENT_NOT_WAITING", "Incident is not awaiting context")
            if incident["version"] != payload["incident_version"]:
                raise ContextConflict("STALE_INCIDENT_VERSION", "Context response version is stale")
            if (
                payload["incident_id"] != request["incident_id"]
                or payload["event_id"] != request["event_id"]
                or payload["context_round"] != request["context_round"]
            ):
                raise ContextConflict(
                    "CONTEXT_CORRELATION_MISMATCH",
                    "Context response does not match the active request round",
                )
            if parse_timestamp(request["expires_at"]) <= utc_now():
                raise ContextConflict("REQUEST_EXPIRED", "Context request has expired")

            now_text = isoformat_z()
            connection.execute(
                """
                INSERT INTO context_responses (
                    response_id, request_id, incident_id, event_id,
                    incident_version, context_round, received_at, status, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'RECEIVED', ?)
                """,
                (
                    payload["response_id"],
                    payload["request_id"],
                    payload["incident_id"],
                    payload["event_id"],
                    payload["incident_version"],
                    payload["context_round"],
                    now_text,
                    _json_dump(payload),
                ),
            )
            connection.execute(
                "UPDATE context_requests SET status = 'RESPONSE_RECEIVED' WHERE request_id = ?",
                (payload["request_id"],),
            )
            connection.execute(
                """
                UPDATE incidents
                SET version = version + 1, updated_at = ?
                WHERE incident_id = ? AND version = ?
                """,
                (now_text, payload["incident_id"], payload["incident_version"]),
            )
            updated_incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (payload["incident_id"],)
            ).fetchone()
            updated_request = connection.execute(
                "SELECT * FROM context_requests WHERE request_id = ?",
                (payload["request_id"],),
            ).fetchone()
            response = connection.execute(
                "SELECT * FROM context_responses WHERE response_id = ?",
                (payload["response_id"],),
            ).fetchone()
            connection.commit()
            return (
                _row_to_dict(updated_incident) or {},
                _row_to_dict(updated_request) or {},
                _row_to_dict(response) or {},
            )

    def get_context_response(self, response_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            return _row_to_dict(
                connection.execute(
                    "SELECT * FROM context_responses WHERE response_id = ?", (response_id,)
                ).fetchone()
            )

    def claim_context_response(
        self, response_id: str, incident_version: int
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Claim a stored response once for reanalysis or follow-up generation."""

        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            response = connection.execute(
                "SELECT * FROM context_responses WHERE response_id = ?", (response_id,)
            ).fetchone()
            if response is None:
                raise ContextConflict("UNKNOWN_CONTEXT_RESPONSE", "Response does not exist")
            if response["status"] != "RECEIVED":
                raise ContextConflict(
                    "CONTEXT_RESPONSE_ALREADY_CLAIMED", "Response is no longer claimable"
                )
            request = connection.execute(
                "SELECT * FROM context_requests WHERE request_id = ?",
                (response["request_id"],),
            ).fetchone()
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (response["incident_id"],)
            ).fetchone()
            if request is None or incident is None:
                raise ContextConflict(
                    "CONTEXT_CORRELATION_MISMATCH", "Response correlation rows are missing"
                )
            if incident["state"] != "WAITING_FOR_CONTEXT":
                raise ContextConflict("INCIDENT_NOT_WAITING", "Incident is not awaiting context")
            if incident["version"] != incident_version:
                raise ContextConflict("STALE_INCIDENT_VERSION", "Context response claim is stale")
            now_text = isoformat_z()
            connection.execute(
                """
                UPDATE context_responses SET status = 'CLAIMED', claimed_at = ?
                WHERE response_id = ? AND status = 'RECEIVED'
                """,
                (now_text, response_id),
            )
            claimed = connection.execute(
                "SELECT * FROM context_responses WHERE response_id = ?", (response_id,)
            ).fetchone()
            connection.commit()
            return (
                _row_to_dict(incident) or {},
                _row_to_dict(request) or {},
                _row_to_dict(claimed) or {},
            )

    def create_followup_context_request(
        self, payload: dict[str, Any], response_id: str
    ) -> dict[str, Any]:
        """Consume a claimed response and create exactly the next request round."""

        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            response = connection.execute(
                "SELECT * FROM context_responses WHERE response_id = ?", (response_id,)
            ).fetchone()
            if response is None or response["status"] != "CLAIMED":
                raise ContextConflict(
                    "CONTEXT_RESPONSE_NOT_CLAIMED",
                    "A claimed context response is required for a follow-up round",
                )
            previous = connection.execute(
                "SELECT * FROM context_requests WHERE request_id = ?",
                (response["request_id"],),
            ).fetchone()
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (response["incident_id"],)
            ).fetchone()
            if previous is None or incident is None:
                raise ContextConflict(
                    "CONTEXT_CORRELATION_MISMATCH", "Follow-up correlation rows are missing"
                )
            expected_round = previous["context_round"] + 1
            if (
                payload["incident_id"] != response["incident_id"]
                or payload["event_id"] != response["event_id"]
                or payload.get("previous_request_id") != previous["request_id"]
                or payload.get("context_round") != expected_round
            ):
                raise ContextConflict(
                    "CONTEXT_CORRELATION_MISMATCH",
                    "Follow-up request is not the next correlated context round",
                )
            if incident["state"] != "WAITING_FOR_CONTEXT":
                raise ContextConflict("INCIDENT_NOT_WAITING", "Incident is not awaiting context")
            if payload["incident_version"] != incident["version"]:
                raise ContextConflict(
                    "STALE_INCIDENT_VERSION", "Follow-up request version is stale"
                )

            self._insert_context_request(connection, payload)
            now_text = isoformat_z()
            connection.execute(
                "UPDATE context_requests SET status = 'CONSUMED' WHERE request_id = ?",
                (previous["request_id"],),
            )
            connection.execute(
                """
                UPDATE context_responses
                SET status = 'CONSUMED', completed_at = ? WHERE response_id = ?
                """,
                (now_text, response_id),
            )
            created = connection.execute(
                "SELECT * FROM context_requests WHERE request_id = ?",
                (payload["request_id"],),
            ).fetchone()
            connection.commit()
            return _row_to_dict(created) or {}

    def complete_context_response(self, response_id: str) -> None:
        """Consume a claimed response when reanalysis creates no follow-up request."""

        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            response = connection.execute(
                "SELECT * FROM context_responses WHERE response_id = ?", (response_id,)
            ).fetchone()
            if response is None or response["status"] != "CLAIMED":
                raise ContextConflict(
                    "CONTEXT_RESPONSE_NOT_CLAIMED", "Response is not currently claimed"
                )
            now_text = isoformat_z()
            connection.execute(
                """
                UPDATE context_responses
                SET status = 'CONSUMED', completed_at = ? WHERE response_id = ?
                """,
                (now_text, response_id),
            )
            connection.execute(
                "UPDATE context_requests SET status = 'CONSUMED' WHERE request_id = ?",
                (response["request_id"],),
            )
            connection.commit()

    def list_context_requests(
        self, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        with self.connect() as connection:
            if status:
                rows = connection.execute(
                    """
                    SELECT * FROM context_requests
                    WHERE status = ? ORDER BY created_at DESC LIMIT ?
                    """,
                    (status, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM context_requests ORDER BY created_at DESC LIMIT ?", (limit,)
                ).fetchall()
            return [_row_to_dict(row) or {} for row in rows]

    def update_context_delivery(
        self, request_id: str, *, delivered: bool, error: str | None = None
    ) -> None:
        status = "DELIVERED" if delivered else "PENDING"
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE context_requests
                SET status = ?, delivery_attempts = delivery_attempts + 1,
                    last_delivery_error = ?
                WHERE request_id = ?
                """,
                (status, error, request_id),
            )

    def claim_context_request(
        self,
        decision_id: str,
        request_id: str,
        incident_version: int,
        decision_payload: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        now_text = isoformat_z()
        with self._lock, self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM decisions WHERE decision_id = ?", (decision_id,)
            ).fetchone():
                raise DecisionConflict("REPLAYED_DECISION", "Decision ID has already been used")
            request = connection.execute(
                "SELECT * FROM context_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            if request is None:
                raise DecisionConflict("UNKNOWN_REQUEST", "Context request does not exist")
            if request["status"] not in {"PENDING", "DELIVERED"}:
                raise DecisionConflict(
                    "REQUEST_ALREADY_USED", "Context request is no longer active"
                )
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (request["incident_id"],)
            ).fetchone()
            if incident is None:
                raise DecisionConflict("UNKNOWN_INCIDENT", "Incident does not exist")
            if incident["state"] != "WAITING_FOR_CONTEXT":
                raise DecisionConflict(
                    "INCIDENT_NOT_WAITING", "Incident is not awaiting a context decision"
                )
            if incident["version"] != incident_version:
                raise DecisionConflict("STALE_INCIDENT_VERSION", "Incident version does not match")
            if parse_timestamp(request["expires_at"]) <= utc_now():
                connection.execute(
                    "UPDATE context_requests SET status = 'EXPIRED' WHERE request_id = ?",
                    (request_id,),
                )
                raise DecisionConflict("REQUEST_EXPIRED", "Context request has expired")

            connection.execute(
                """
                INSERT INTO decisions (
                    decision_id, request_id, incident_id, received_at, status, payload_json
                ) VALUES (?, ?, ?, ?, 'CLAIMED', ?)
                """,
                (
                    decision_id,
                    request_id,
                    incident["incident_id"],
                    now_text,
                    _json_dump(decision_payload),
                ),
            )
            connection.execute(
                "UPDATE context_requests SET status = 'CONSUMED' WHERE request_id = ?",
                (request_id,),
            )
            connection.commit()
            return _row_to_dict(incident) or {}, _row_to_dict(request) or {}

    def record_unclaimed_decision(
        self,
        decision_id: str,
        request_id: str,
        incident_id: str,
        payload: dict[str, Any],
        status: str,
        reason_code: str,
    ) -> None:
        try:
            with self._lock, self.connect() as connection:
                connection.execute(
                    """
                    INSERT INTO decisions (
                        decision_id, request_id, incident_id, received_at,
                        status, reason_code, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision_id,
                        request_id,
                        incident_id,
                        isoformat_z(),
                        status,
                        reason_code,
                        _json_dump(payload),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise DecisionConflict(
                "REPLAYED_DECISION", "Decision ID has already been used"
            ) from exc

    def update_decision_status(self, decision_id: str, status: str, reason_code: str) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                "UPDATE decisions SET status = ?, reason_code = ? WHERE decision_id = ?",
                (status, reason_code, decision_id),
            )

    def add_managed_rule(
        self,
        *,
        rule_id: str,
        incident_id: str,
        decision_id: str,
        action: str,
        expires_at: str,
        scope: dict[str, Any],
        receipt: dict[str, Any],
    ) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO managed_rules (
                    rule_id, incident_id, decision_id, action, created_at,
                    expires_at, status, scope_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
                """,
                (
                    rule_id,
                    incident_id,
                    decision_id,
                    action,
                    isoformat_z(),
                    expires_at,
                    _json_dump(scope),
                    _json_dump(receipt),
                ),
            )

    def reserve_managed_rule(
        self,
        *,
        rule_id: str,
        incident_id: str,
        decision_id: str,
        action: str,
        expires_at: str,
        scope: dict[str, Any],
    ) -> dict[str, Any]:
        """Persist PENDING_INSTALL intent before mutating a firewall adapter."""

        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO managed_rules (
                    rule_id, incident_id, decision_id, action, created_at,
                    expires_at, status, scope_json, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING_INSTALL', ?, '{}')
                """,
                (
                    rule_id,
                    incident_id,
                    decision_id,
                    action,
                    isoformat_z(),
                    expires_at,
                    _json_dump(scope),
                ),
            )
            row = connection.execute(
                "SELECT * FROM managed_rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            return _row_to_dict(row) or {}

    def activate_managed_rule(self, rule_id: str, receipt: dict[str, Any]) -> dict[str, Any]:
        """Attach an install receipt and expose a reserved rule as ACTIVE."""

        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE managed_rules
                SET status = 'ACTIVE', receipt_json = ?, last_error = NULL
                WHERE rule_id = ? AND status = 'PENDING_INSTALL'
                """,
                (_json_dump(receipt), rule_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"Managed rule {rule_id} is not reserved for installation")
            row = connection.execute(
                "SELECT * FROM managed_rules WHERE rule_id = ?", (rule_id,)
            ).fetchone()
            return _row_to_dict(row) or {}

    def mark_rule_cleanup_required(
        self,
        rule_id: str,
        error: str,
        *,
        receipt: dict[str, Any] | None = None,
    ) -> None:
        """Retain enough state to retry compensation after uncertain installation."""

        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE managed_rules
                SET status = 'CLEANUP_REQUIRED', last_error = ?,
                    receipt_json = COALESCE(?, receipt_json)
                WHERE rule_id = ? AND status IN ('PENDING_INSTALL', 'ACTIVE', 'CLEANUP_REQUIRED')
                """,
                (
                    error,
                    _json_dump(receipt) if receipt is not None else None,
                    rule_id,
                ),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"Unknown managed rule {rule_id}")

    def get_managed_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            return _row_to_dict(
                connection.execute(
                    "SELECT * FROM managed_rules WHERE rule_id = ?", (rule_id,)
                ).fetchone()
            )

    def list_active_rules(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM managed_rules WHERE status = 'ACTIVE' ORDER BY expires_at"
            ).fetchall()
            return [_row_to_dict(row) or {} for row in rows]

    def list_desired_rules(self) -> list[dict[str, Any]]:
        """Return only fully installed rules that should exist in the adapter."""

        return self.list_active_rules()

    def list_rules_requiring_cleanup(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM managed_rules
                WHERE status = 'CLEANUP_REQUIRED' ORDER BY expires_at
                """
            ).fetchall()
            return [_row_to_dict(row) or {} for row in rows]

    def list_pending_rules(self) -> list[dict[str, Any]]:
        """Return installs that were reserved but never confirmed active."""

        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM managed_rules
                WHERE status = 'PENDING_INSTALL' ORDER BY expires_at
                """
            ).fetchall()
            return [_row_to_dict(row) or {} for row in rows]

    def list_expired_rules(self) -> list[dict[str, Any]]:
        now_text = isoformat_z()
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM managed_rules
                WHERE status = 'ACTIVE' AND expires_at <= ?
                ORDER BY expires_at
                """,
                (now_text,),
            ).fetchall()
            return [_row_to_dict(row) or {} for row in rows]

    def mark_rule_revoked(self, rule_id: str) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                UPDATE managed_rules
                SET status = 'REVOKED', revoked_at = ?, last_error = NULL
                WHERE rule_id = ?
                """,
                (isoformat_z(), rule_id),
            )

    def mark_rule_error(self, rule_id: str, error: str) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                "UPDATE managed_rules SET last_error = ? WHERE rule_id = ?", (error, rule_id)
            )

    def audit(
        self,
        component: str,
        action: str,
        *,
        incident_id: str | None = None,
        event_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_events (
                    timestamp, incident_id, event_id, component, action, details_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    isoformat_z(),
                    incident_id,
                    event_id,
                    component,
                    action,
                    _json_dump(details or {}),
                ),
            )

    def timeline(self, incident_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM audit_events
                WHERE incident_id = ? ORDER BY audit_id
                """,
                (incident_id,),
            ).fetchall()
            return [_row_to_dict(row) or {} for row in rows]

    def expire_context_requests(self) -> list[str]:
        now_text = isoformat_z()
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                """
                SELECT request_id, incident_id FROM context_requests
                WHERE status IN ('PENDING', 'DELIVERED') AND expires_at <= ?
                """,
                (now_text,),
            ).fetchall()
            incident_ids = [row["incident_id"] for row in rows]
            connection.execute(
                """
                UPDATE context_requests SET status = 'EXPIRED'
                WHERE status IN ('PENDING', 'DELIVERED') AND expires_at <= ?
                """,
                (now_text,),
            )
            for incident_id in incident_ids:
                connection.execute(
                    """
                    UPDATE incidents
                    SET state = 'EXPIRED', version = version + 1, updated_at = ?
                    WHERE incident_id = ? AND state = 'WAITING_FOR_CONTEXT'
                    """,
                    (now_text, incident_id),
                )
            return incident_ids
