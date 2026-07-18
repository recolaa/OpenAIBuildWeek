"""Source-specific validation and normalization into ``NetworkEventIn``."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, NoReturn

from pydantic import ValidationError

from app.schemas import (
    EventSource,
    FirewallDropEvent,
    GenericNetworkEventIn,
    NetworkEventIn,
    NetworkEventType,
    NetworkFlow,
    NetworkProtocol,
    PolicyMetadata,
    RuleAction,
    Severity,
    TrafficDirection,
    ZeekEventIn,
)


class NormalizationError(ValueError):
    """Raised when a source payload is valid JSON but cannot be normalized."""


def _fail(message: str) -> NoReturn:
    raise NormalizationError(message)


def _generated_event_id(source: str, payload: Mapping[str, Any]) -> str:
    """Generate a retry-stable ID from source evidence, never from a secret."""

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=False,
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:24]
    return f"evt-{source}-{digest}"


def normalize_firewall_drop(event: FirewallDropEvent | Mapping[str, Any]) -> NetworkEventIn:
    """Validate and normalize one ``drop-event-v1`` payload."""

    try:
        drop = (
            event
            if isinstance(event, FirewallDropEvent)
            else FirewallDropEvent.model_validate(event)
        )
    except ValidationError as exc:
        raise NormalizationError("invalid firewall drop event") from exc

    identity_payload = drop.model_dump(mode="json", exclude={"event_id"})
    event_id = drop.event_id or _generated_event_id("firewall", identity_payload)
    reason = drop.drop_reason or f"Traffic denied by firewall rule {drop.rule_id}"
    policy = PolicyMetadata(
        rule_id=drop.rule_id,
        description=drop.drop_reason,
        action=RuleAction.BLOCK,
    )
    source_context: dict[str, Any] = {
        "input_schema_version": drop.schema_version,
        "interface_in": drop.interface_in,
        "interface_out": drop.interface_out,
    }
    source_context.update(drop.raw_context)
    source_context = {key: value for key, value in source_context.items() if value is not None}

    return NetworkEventIn(
        schema_version="network-event-v1",
        event_id=event_id,
        timestamp=drop.timestamp,
        source=EventSource.FIREWALL,
        event_type=NetworkEventType.FIREWALL_DROP,
        flow=NetworkFlow(
            source_ip=drop.source_ip,
            destination_ip=drop.destination_ip,
            source_port=drop.source_port,
            destination_port=drop.destination_port,
            protocol=NetworkProtocol(drop.protocol.value),
            direction=TrafficDirection(drop.direction.value),
            interface_in=drop.interface_in,
            interface_out=drop.interface_out,
            packet_count=drop.packet_count,
        ),
        reason=reason,
        policy_metadata=policy,
        severity=Severity.MEDIUM,
        raw_context=source_context,
    )


def normalize_generic_event(
    event: GenericNetworkEventIn | NetworkEventIn | Mapping[str, Any],
) -> NetworkEventIn:
    """Normalize a generic adapter payload or revalidate a canonical event."""

    if isinstance(event, NetworkEventIn):
        return NetworkEventIn.model_validate(event.model_dump())
    try:
        generic = (
            event
            if isinstance(event, GenericNetworkEventIn)
            else GenericNetworkEventIn.model_validate(event)
        )
    except ValidationError as exc:
        raise NormalizationError("invalid generic network event") from exc

    identity_payload = generic.model_dump(mode="json", exclude={"event_id"})
    return NetworkEventIn(
        schema_version="network-event-v1",
        event_id=generic.event_id or _generated_event_id("generic", identity_payload),
        timestamp=generic.timestamp,
        source=generic.source,
        event_type=generic.event_type,
        flow=generic.flow,
        reason=generic.reason,
        policy_metadata=generic.policy_metadata,
        severity=generic.severity,
        raw_context=generic.raw_context,
    )


def _record_value(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in record:
            return record[name]
        if "." in name:
            current: Any = record
            for component in name.split("."):
                if not isinstance(current, Mapping) or component not in current:
                    break
                current = current[component]
            else:
                return current
    return None


def _zeek_timestamp(wrapper: ZeekEventIn) -> datetime:
    if wrapper.timestamp is not None:
        return wrapper.timestamp
    raw = _record_value(wrapper.record, "ts", "timestamp")
    if type(raw) in (int, float):
        try:
            return datetime.fromtimestamp(float(raw), tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise NormalizationError("Zeek ts is outside the supported range") from exc
    if isinstance(raw, str):
        stripped = raw.strip()
        try:
            numeric = float(stripped)
        except ValueError:
            try:
                if stripped.endswith(("Z", "z")):
                    stripped = f"{stripped[:-1]}+00:00"
                parsed = datetime.fromisoformat(stripped)
            except ValueError as exc:
                raise NormalizationError("Zeek timestamp is not ISO-8601") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise NormalizationError("Zeek timestamp must include a UTC offset") from None
            return parsed.astimezone(UTC)
        try:
            return datetime.fromtimestamp(numeric, tz=UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise NormalizationError("Zeek ts is outside the supported range") from exc
    raise NormalizationError("Zeek wrapper needs timestamp or record.ts")


def _optional_port(value: Any, field_name: str) -> int | None:
    if value is None or value == "-":
        return None
    if type(value) is not int:
        raise NormalizationError(f"Zeek {field_name} must be an integer")
    if not 1 <= value <= 65535:
        raise NormalizationError(f"Zeek {field_name} must be between 1 and 65535")
    return value


def _zeek_protocol(record: Mapping[str, Any]) -> NetworkProtocol:
    value = _record_value(record, "proto", "protocol", "transport")
    if value is None:
        return NetworkProtocol.OTHER
    if not isinstance(value, str):
        raise NormalizationError("Zeek protocol must be a string")
    normalized = value.strip().lower()
    if normalized == "tcp":
        return NetworkProtocol.TCP
    if normalized == "udp":
        return NetworkProtocol.UDP
    if normalized in {"icmp", "icmp6", "ipv6-icmp"}:
        return NetworkProtocol.ICMP
    return NetworkProtocol.OTHER


def _zeek_event_type(log_type: str, record: Mapping[str, Any]) -> NetworkEventType:
    normalized = log_type.strip().lower().removesuffix(".log")
    action = _record_value(record, "action", "verdict")
    if isinstance(action, str) and action.lower() in {"drop", "dropped", "deny", "blocked"}:
        return NetworkEventType.FIREWALL_DROP
    return {
        "conn": NetworkEventType.CONNECTION,
        "dns": NetworkEventType.DNS,
        "http": NetworkEventType.HTTP,
        "ssl": NetworkEventType.TLS,
        "tls": NetworkEventType.TLS,
        "notice": NetworkEventType.NOTICE,
        "weird": NetworkEventType.ALERT,
        "intel": NetworkEventType.ALERT,
        "signatures": NetworkEventType.ALERT,
    }.get(normalized, NetworkEventType.OTHER)


def _zeek_reason(log_type: str, record: Mapping[str, Any]) -> str:
    value = _record_value(
        record,
        "msg",
        "message",
        "reason",
        "note",
        "signature",
        "query",
        "uri",
        "service",
    )
    if value is None:
        return f"Zeek {log_type} telemetry"
    if not isinstance(value, (str, int, float, bool)):
        return f"Zeek {log_type} telemetry"
    rendered = str(value).strip()
    if not rendered:
        return f"Zeek {log_type} telemetry"
    return rendered[:2048]


def normalize_zeek_event(event: ZeekEventIn | Mapping[str, Any]) -> NetworkEventIn:
    """Normalize common Zeek JSON keys while retaining the complete bounded record."""

    try:
        wrapper = event if isinstance(event, ZeekEventIn) else ZeekEventIn.model_validate(event)
    except ValidationError as exc:
        raise NormalizationError("invalid Zeek event wrapper") from exc

    record = wrapper.record
    source_ip = _record_value(record, "id.orig_h", "src_ip", "source_ip")
    destination_ip = _record_value(record, "id.resp_h", "dst_ip", "destination_ip")
    source_port = _optional_port(
        _record_value(record, "id.orig_p", "src_port", "source_port"),
        "source port",
    )
    destination_port = _optional_port(
        _record_value(record, "id.resp_p", "dst_port", "destination_port"),
        "destination port",
    )
    timestamp = _zeek_timestamp(wrapper)
    record_uid = _record_value(record, "uid")
    event_id = wrapper.event_id
    if event_id is None and isinstance(record_uid, str) and 0 < len(record_uid.strip()) <= 100:
        safe_uid = re_sub_identifier(record_uid.strip())
        event_id = f"zeek-{safe_uid}"
    if event_id is None:
        event_id = _generated_event_id(
            "zeek",
            wrapper.model_dump(mode="json", exclude={"event_id"}),
        )

    rule_id_value = _record_value(record, "rule_id", "policy", "signature_id")
    policy: PolicyMetadata | None = None
    if isinstance(rule_id_value, (str, int)) and str(rule_id_value).strip():
        policy = PolicyMetadata(rule_id=str(rule_id_value).strip()[:128])

    raw_context: dict[str, Any] = {
        "input_schema_version": wrapper.schema_version,
        "zeek_log_type": wrapper.log_type,
        "record": record,
    }
    if wrapper.sensor_id is not None:
        raw_context["sensor_id"] = wrapper.sensor_id

    try:
        return NetworkEventIn(
            schema_version="network-event-v1",
            event_id=event_id,
            timestamp=timestamp,
            source=EventSource.ZEEK,
            event_type=_zeek_event_type(wrapper.log_type, record),
            flow=NetworkFlow(
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol=_zeek_protocol(record),
                direction=TrafficDirection.UNKNOWN,
                packet_count=_record_value(record, "orig_pkts", "packet_count"),
                byte_count=_record_value(record, "orig_bytes", "byte_count"),
                community_id=_record_value(record, "community_id"),
            ),
            reason=_zeek_reason(wrapper.log_type, record),
            policy_metadata=policy,
            severity=(
                Severity.HIGH
                if _zeek_event_type(wrapper.log_type, record) is NetworkEventType.ALERT
                else Severity.MEDIUM
            ),
            raw_context=raw_context,
        )
    except ValidationError as exc:
        raise NormalizationError("Zeek record contains invalid typed flow fields") from exc


def re_sub_identifier(value: str) -> str:
    """Keep source IDs readable while constraining them to safe identifier text."""

    safe = "".join(
        character if (character.isascii() and character.isalnum()) or character in "._:-" else "-"
        for character in value
    )
    return safe[:100] or "record"


def normalize_network_event(
    event: (
        NetworkEventIn | FirewallDropEvent | GenericNetworkEventIn | ZeekEventIn | Mapping[str, Any]
    ),
) -> NetworkEventIn:
    """Validate, dispatch, and normalize any supported network event payload."""

    if isinstance(event, NetworkEventIn):
        return normalize_generic_event(event)
    if isinstance(event, FirewallDropEvent):
        return normalize_firewall_drop(event)
    if isinstance(event, GenericNetworkEventIn):
        return normalize_generic_event(event)
    if isinstance(event, ZeekEventIn):
        return normalize_zeek_event(event)
    if not isinstance(event, Mapping):
        raise NormalizationError("network event must be a JSON object")

    schema_version = event.get("schema_version")
    if schema_version == "drop-event-v1":
        return normalize_firewall_drop(event)
    if schema_version == "generic-network-event-v1":
        return normalize_generic_event(event)
    if schema_version == "network-event-v1":
        try:
            return NetworkEventIn.model_validate(event)
        except ValidationError as exc:
            raise NormalizationError("invalid canonical network event") from exc
    if schema_version == "zeek-event-v1":
        return normalize_zeek_event(event)
    _fail(
        "unsupported schema_version; expected drop-event-v1, "
        "generic-network-event-v1, network-event-v1, or zeek-event-v1"
    )


__all__ = [
    "NormalizationError",
    "normalize_firewall_drop",
    "normalize_generic_event",
    "normalize_network_event",
    "normalize_zeek_event",
]
