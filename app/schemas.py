"""Strict, versioned contracts for the IntentBridge network agent.

The models in this module are deliberately data-only.  In particular, no
external contract contains a shell command, firewall expression, or arbitrary
topology mutation.  Arbitrary JSON is accepted only in the explicitly bounded
``raw_context`` and Zeek ``record`` evidence containers.
"""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from enum import Enum, StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    model_validator,
)

RAW_CONTEXT_MAX_BYTES = 32 * 1024
ZEEK_RECORD_MAX_BYTES = 24 * 1024
JSON_MAX_DEPTH = 8
JSON_MAX_ITEMS = 512
JSON_MAX_STRING_LENGTH = 8 * 1024


def _parse_utc_datetime(value: Any) -> datetime:
    """Accept an aware datetime or ISO-8601 string and canonicalize to UTC."""

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("timestamp must not be empty")
        if candidate.endswith(("Z", "z")):
            candidate = f"{candidate[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601") from exc
    else:
        raise ValueError("timestamp must be an aware datetime or ISO-8601 string")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(UTC)


def _parse_ip_address(value: Any) -> IPv4Address | IPv6Address:
    """Parse one exact IP address; networks, wildcards, and hostnames fail."""

    if isinstance(value, (IPv4Address, IPv6Address)):
        return value
    if not isinstance(value, str):
        raise ValueError("IP address must be a string")
    candidate = value.strip()
    if not candidate or "/" in candidate or "*" in candidate or "%" in candidate:
        raise ValueError("an exact, unscoped IP address is required")
    try:
        return ip_address(candidate)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc


def _enum_parser[EnumT: Enum](enum_type: type[EnumT]):
    """Allow exact JSON enum strings without enabling other coercions."""

    def parse(value: Any) -> EnumT:
        if isinstance(value, enum_type):
            return value
        if type(value) is str:
            try:
                return enum_type(value)
            except ValueError as exc:
                raise ValueError(f"invalid {enum_type.__name__}: {value!r}") from exc
        raise ValueError(f"{enum_type.__name__} must be a string")

    return parse


def _validate_json_tree(value: JsonValue, *, max_bytes: int) -> JsonValue:
    item_count = 0

    def visit(node: JsonValue, depth: int) -> None:
        nonlocal item_count
        if depth > JSON_MAX_DEPTH:
            raise ValueError(f"JSON evidence exceeds maximum depth {JSON_MAX_DEPTH}")
        item_count += 1
        if item_count > JSON_MAX_ITEMS:
            raise ValueError(f"JSON evidence exceeds maximum item count {JSON_MAX_ITEMS}")

        if isinstance(node, str):
            if len(node) > JSON_MAX_STRING_LENGTH:
                raise ValueError("JSON evidence contains an oversized string")
            return
        if node is None or isinstance(node, (bool, int)):
            return
        if isinstance(node, float):
            if not math.isfinite(node):
                raise ValueError("JSON evidence numbers must be finite")
            return
        if isinstance(node, list):
            for item in node:
                visit(item, depth + 1)
            return
        if isinstance(node, dict):
            for key, item in node.items():
                if not isinstance(key, str):
                    raise ValueError("JSON evidence object keys must be strings")
                if len(key) > 256:
                    raise ValueError("JSON evidence contains an oversized key")
                visit(item, depth + 1)
            return
        raise ValueError("evidence must contain JSON-compatible values only")

    visit(value, 0)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("evidence must be valid JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"JSON evidence exceeds maximum size {max_bytes} bytes")
    return value


def _bounded_raw_context(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return _validate_json_tree(value, max_bytes=RAW_CONTEXT_MAX_BYTES)  # type: ignore[return-value]


def _bounded_zeek_record(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return _validate_json_tree(value, max_bytes=ZEEK_RECORD_MAX_BYTES)  # type: ignore[return-value]


UtcDatetime = Annotated[datetime, BeforeValidator(_parse_utc_datetime)]
IPAddress = Annotated[
    IPv4Address | IPv6Address,
    BeforeValidator(_parse_ip_address),
]
Port = Annotated[int, Field(ge=1, le=65535)]
PositiveCount = Annotated[int, Field(ge=1, le=2_147_483_647)]
NonNegativeCount = Annotated[int, Field(ge=0, le=9_223_372_036_854_775_807)]
TTLSeconds = Annotated[int, Field(ge=1, le=86_400)]
Identifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$",
    ),
]
ShortText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=256),
]
InterfaceName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,63}$",
    ),
]
Description = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=2_048),
]
LongText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=4_096),
]
BoundedRawContext = Annotated[
    dict[str, JsonValue],
    AfterValidator(_bounded_raw_context),
]
BoundedZeekRecord = Annotated[
    dict[str, JsonValue],
    AfterValidator(_bounded_zeek_record),
]


class StrictModel(BaseModel):
    """Base configuration shared by all external and API contracts."""

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_assignment=True,
        validate_default=True,
        populate_by_name=True,
    )


class EventSource(StrEnum):
    FIREWALL = "firewall"
    ZEEK = "zeek"
    IDS = "ids"
    GENERIC = "generic"
    MANUAL = "manual"


class NetworkEventType(StrEnum):
    FIREWALL_DROP = "FIREWALL_DROP"
    CONNECTION = "CONNECTION"
    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS"
    NOTICE = "NOTICE"
    ALERT = "ALERT"
    POLICY_CHANGE = "POLICY_CHANGE"
    OTHER = "OTHER"


class NetworkProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class TransportProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class TrafficDirection(StrEnum):
    INPUT = "input"
    OUTPUT = "output"
    FORWARD = "forward"
    UNKNOWN = "unknown"


class FirewallDirection(StrEnum):
    INPUT = "input"
    OUTPUT = "output"
    FORWARD = "forward"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleAction(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class AnalysisAction(StrEnum):
    REQUEST_CONTEXT = "REQUEST_CONTEXT"
    KEEP_BLOCKED = "KEEP_BLOCKED"
    ESCALATE = "ESCALATE"
    IGNORE_DUPLICATE = "IGNORE_DUPLICATE"


class DecisionAction(StrEnum):
    ALLOW_TEMPORARY = "ALLOW_TEMPORARY"
    BLOCK_TEMPORARY = "BLOCK_TEMPORARY"
    KEEP_CURRENT_POLICY = "KEEP_CURRENT_POLICY"
    DENY = "DENY"
    REQUEST_MORE_INFORMATION = "REQUEST_MORE_INFORMATION"


class ContextRequestType(StrEnum):
    NETWORK_ACCESS_CONTEXT = "NETWORK_ACCESS_CONTEXT"


class IncidentState(StrEnum):
    DETECTED = "DETECTED"
    ANALYZING = "ANALYZING"
    WAITING_FOR_CONTEXT = "WAITING_FOR_CONTEXT"
    APPROVED = "APPROVED"
    ENFORCING = "ENFORCING"
    ENFORCED = "ENFORCED"
    REVOKED = "REVOKED"
    ENFORCEMENT_FAILED = "ENFORCEMENT_FAILED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    KEPT_BLOCKED = "KEPT_BLOCKED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"


class EventDisposition(StrEnum):
    ACCEPTED = "ACCEPTED"
    DUPLICATE = "DUPLICATE"
    REJECTED = "REJECTED"


class EnforcementStatus(StrEnum):
    APPLIED = "APPLIED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"
    FAILED = "FAILED"


class EnforcementReasonCode(StrEnum):
    EXACT_SCOPE_TEMPORARY_GRANT = "EXACT_SCOPE_TEMPORARY_GRANT"
    EXACT_SCOPE_TEMPORARY_BLOCK = "EXACT_SCOPE_TEMPORARY_BLOCK"
    CURRENT_POLICY_RETAINED = "CURRENT_POLICY_RETAINED"
    DECISION_DENIED = "DECISION_DENIED"
    MORE_INFORMATION_REQUIRED = "MORE_INFORMATION_REQUIRED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    TTL_EXCEEDS_POLICY = "TTL_EXCEEDS_POLICY"
    TTL_INVALID = "TTL_INVALID"
    REQUEST_EXPIRED = "REQUEST_EXPIRED"
    REPLAYED_DECISION = "REPLAYED_DECISION"
    APPROVER_NOT_ALLOWED = "APPROVER_NOT_ALLOWED"
    STALE_INCIDENT_VERSION = "STALE_INCIDENT_VERSION"
    INCIDENT_NOT_FOUND = "INCIDENT_NOT_FOUND"
    REQUEST_MISMATCH = "REQUEST_MISMATCH"
    INVALID_INCIDENT_STATE = "INVALID_INCIDENT_STATE"
    POLICY_DISALLOWS_EXCEPTION = "POLICY_DISALLOWS_EXCEPTION"
    MALFORMED_DECISION = "MALFORMED_DECISION"
    FIREWALL_ERROR = "FIREWALL_ERROR"
    RULE_EXPIRED = "RULE_EXPIRED"
    RULE_REVOKED = "RULE_REVOKED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AdvisoryTrust(StrEnum):
    """Marks prose that is context for reasoning, never authorization evidence."""

    UNTRUSTED_ADVISORY = "UNTRUSTED_ADVISORY"


# Enum fields use exact string-to-enum parsers.  This preserves strict scalar
# behavior when FastAPI has already decoded a JSON request into Python values.
EventSourceValue = Annotated[EventSource, BeforeValidator(_enum_parser(EventSource))]
NetworkEventTypeValue = Annotated[NetworkEventType, BeforeValidator(_enum_parser(NetworkEventType))]
NetworkProtocolValue = Annotated[NetworkProtocol, BeforeValidator(_enum_parser(NetworkProtocol))]
TransportProtocolValue = Annotated[
    TransportProtocol, BeforeValidator(_enum_parser(TransportProtocol))
]
TrafficDirectionValue = Annotated[TrafficDirection, BeforeValidator(_enum_parser(TrafficDirection))]
FirewallDirectionValue = Annotated[
    FirewallDirection, BeforeValidator(_enum_parser(FirewallDirection))
]
SeverityValue = Annotated[Severity, BeforeValidator(_enum_parser(Severity))]
RuleActionValue = Annotated[RuleAction, BeforeValidator(_enum_parser(RuleAction))]
AnalysisActionValue = Annotated[AnalysisAction, BeforeValidator(_enum_parser(AnalysisAction))]
DecisionActionValue = Annotated[DecisionAction, BeforeValidator(_enum_parser(DecisionAction))]
ContextRequestTypeValue = Annotated[
    ContextRequestType, BeforeValidator(_enum_parser(ContextRequestType))
]
IncidentStateValue = Annotated[IncidentState, BeforeValidator(_enum_parser(IncidentState))]
EventDispositionValue = Annotated[EventDisposition, BeforeValidator(_enum_parser(EventDisposition))]
EnforcementStatusValue = Annotated[
    EnforcementStatus, BeforeValidator(_enum_parser(EnforcementStatus))
]
EnforcementReasonCodeValue = Annotated[
    EnforcementReasonCode, BeforeValidator(_enum_parser(EnforcementReasonCode))
]
AdvisoryTrustValue = Annotated[AdvisoryTrust, BeforeValidator(_enum_parser(AdvisoryTrust))]


class NetworkFlow(StrictModel):
    """Observed flow data; fields may be absent for non-flow Zeek records."""

    source_ip: IPAddress | None = None
    destination_ip: IPAddress | None = None
    source_port: Port | None = None
    destination_port: Port | None = None
    protocol: NetworkProtocolValue = NetworkProtocol.OTHER
    direction: TrafficDirectionValue = TrafficDirection.UNKNOWN
    interface_in: InterfaceName | None = None
    interface_out: InterfaceName | None = None
    packet_count: NonNegativeCount | None = None
    byte_count: NonNegativeCount | None = None
    community_id: ShortText | None = None


class FlowScope(StrictModel):
    """An exact, single-service scope suitable for deterministic validation."""

    source_ip: IPAddress
    destination_ip: IPAddress
    destination_port: Port
    protocol: TransportProtocolValue
    direction: Literal["forward"] = "forward"
    interface_in: InterfaceName | None = None
    interface_out: InterfaceName | None = None

    @model_validator(mode="after")
    def require_one_address_family(self) -> Self:
        if self.source_ip.version != self.destination_ip.version:
            raise ValueError("source_ip and destination_ip must use the same address family")
        if (self.interface_in is None) is not (self.interface_out is None):
            raise ValueError(
                "interface_in and interface_out must either both be present or both be absent"
            )
        return self


class ObservedFlow(FlowScope):
    """Original evidence retains the ephemeral source port when available."""

    source_port: Port | None = None
    timestamp: UtcDatetime


class PolicyMetadata(StrictModel):
    rule_id: Identifier | None = None
    description: Description | None = None
    action: RuleActionValue | None = None
    risk_level: SeverityValue | None = None
    maximum_ttl_seconds: TTLSeconds | None = None
    requires_human_context: bool | None = None
    tags: Annotated[list[ShortText], Field(max_length=32)] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_meaningful_metadata(self) -> Self:
        if not any(
            (
                self.rule_id,
                self.description,
                self.action,
                self.risk_level,
                self.maximum_ttl_seconds,
                self.requires_human_context is not None,
                self.tags,
            )
        ):
            raise ValueError("policy_metadata must contain at least one fact")
        return self


class NetworkEventIn(StrictModel):
    """Canonical event consumed by incident and reasoning services."""

    schema_version: Literal["network-event-v1"]
    event_id: Identifier
    timestamp: UtcDatetime
    source: EventSourceValue
    event_type: NetworkEventTypeValue
    flow: NetworkFlow
    reason: Description
    policy_metadata: PolicyMetadata | None = None
    severity: SeverityValue = Severity.MEDIUM
    raw_context: BoundedRawContext = Field(default_factory=dict)


class GenericNetworkEventIn(StrictModel):
    """Versioned generic input for network integrations without a custom adapter."""

    schema_version: Literal["generic-network-event-v1"]
    event_id: Identifier | None = None
    timestamp: UtcDatetime
    source: EventSourceValue = EventSource.GENERIC
    event_type: NetworkEventTypeValue
    flow: NetworkFlow
    reason: Description
    policy_metadata: PolicyMetadata | None = None
    severity: SeverityValue = Severity.MEDIUM
    raw_context: BoundedRawContext = Field(default_factory=dict)


class FirewallDropEvent(StrictModel):
    """Network/firewall drop input matching ``drop-event-v1``."""

    schema_version: Literal["drop-event-v1"]
    event_id: Identifier | None = None
    timestamp: UtcDatetime
    source_ip: IPAddress
    destination_ip: IPAddress
    source_port: Port
    destination_port: Port
    protocol: TransportProtocolValue
    direction: FirewallDirectionValue
    rule_id: Identifier | None = None
    drop_reason: Description | None = None
    interface_in: InterfaceName | None = None
    interface_out: InterfaceName | None = None
    packet_count: PositiveCount = 1
    raw_context: BoundedRawContext = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_drop_explanation(self) -> Self:
        if self.rule_id is None and self.drop_reason is None:
            raise ValueError("at least one of rule_id or drop_reason is required")
        return self


class ZeekEventIn(StrictModel):
    """Strict wrapper around one bounded arbitrary Zeek JSON record."""

    schema_version: Literal["zeek-event-v1"]
    event_id: Identifier | None = None
    timestamp: UtcDatetime | None = None
    log_type: ShortText
    sensor_id: Identifier | None = None
    record: BoundedZeekRecord


class AgentAnalysis(StrictModel):
    schema_version: Literal["agent-analysis-v1"]
    summary: Description
    observed_facts: Annotated[list[Description], Field(max_length=32)]
    inferences: Annotated[list[Description], Field(max_length=32)]
    missing_context: Annotated[list[Description], Field(max_length=32)]
    recommended_action: AnalysisActionValue
    question: Description | None = None
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]

    @model_validator(mode="after")
    def validate_action_payload(self) -> Self:
        if self.recommended_action is AnalysisAction.REQUEST_CONTEXT and self.question is None:
            raise ValueError("REQUEST_CONTEXT requires a focused question")
        if self.recommended_action is AnalysisAction.IGNORE_DUPLICATE and self.question is not None:
            raise ValueError("IGNORE_DUPLICATE must not ask a new question")
        return self


class ContextAnalysisSummary(StrictModel):
    summary: Description
    missing_context: Annotated[list[Description], Field(min_length=1, max_length=32)]
    trust: AdvisoryTrustValue = AdvisoryTrust.UNTRUSTED_ADVISORY


class MatchedPolicy(StrictModel):
    rule_id: Identifier
    description: Description
    maximum_ttl_seconds: TTLSeconds


class ContextRequest(StrictModel):
    schema_version: Literal["context-request-v1"]
    request_id: Identifier
    event_id: Identifier
    incident_id: Identifier
    incident_version: Annotated[int, Field(ge=1)]
    context_round: Annotated[int, Field(ge=1, le=100)] = 1
    previous_request_id: Identifier | None = None
    type: ContextRequestTypeValue = ContextRequestType.NETWORK_ACCESS_CONTEXT
    severity: SeverityValue
    created_at: UtcDatetime
    expires_at: UtcDatetime
    observed_flow: ObservedFlow | None = None
    permitted_grant_scope: FlowScope | None = None
    matched_policy: MatchedPolicy
    agent_analysis: ContextAnalysisSummary
    question: Description
    allowed_responses: Annotated[list[DecisionActionValue], Field(min_length=1, max_length=5)]
    maximum_ttl_seconds: TTLSeconds

    @model_validator(mode="after")
    def validate_request_consistency(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        if (self.observed_flow is None) is not (self.permitted_grant_scope is None):
            raise ValueError(
                "observed_flow and permitted_grant_scope must either both be present "
                "or both be absent"
            )
        if self.observed_flow is not None and self.permitted_grant_scope is not None:
            expected_scope = FlowScope(
                source_ip=self.observed_flow.source_ip,
                destination_ip=self.observed_flow.destination_ip,
                destination_port=self.observed_flow.destination_port,
                protocol=self.observed_flow.protocol,
                direction=self.observed_flow.direction,
                interface_in=self.observed_flow.interface_in,
                interface_out=self.observed_flow.interface_out,
            )
            if self.permitted_grant_scope != expected_scope:
                raise ValueError(
                    "permitted_grant_scope must exactly match the observed service flow"
                )
        elif any(
            response in {DecisionAction.ALLOW_TEMPORARY, DecisionAction.BLOCK_TEMPORARY}
            for response in self.allowed_responses
        ):
            raise ValueError(
                "temporary network changes cannot be offered without an exact observed flow"
            )
        if len(set(self.allowed_responses)) != len(self.allowed_responses):
            raise ValueError("allowed_responses must not contain duplicates")
        if self.context_round == 1 and self.previous_request_id is not None:
            raise ValueError("the first context round cannot have previous_request_id")
        if self.context_round > 1 and self.previous_request_id is None:
            raise ValueError("later context rounds require previous_request_id")
        if self.previous_request_id == self.request_id:
            raise ValueError("previous_request_id cannot equal request_id")
        return self


class ApproverIdentity(StrictModel):
    id: Identifier
    role: Identifier
    display_name: ShortText | None = None


class ChatDecision(StrictModel):
    schema_version: Literal["decision-v1"]
    decision_id: Identifier
    request_id: Identifier
    event_id: Identifier
    incident_id: Identifier
    incident_version: Annotated[int, Field(ge=1)]
    decision: DecisionActionValue
    grant_scope: FlowScope | None = None
    ttl_seconds: TTLSeconds | None = None
    approved_by: ApproverIdentity | None = None
    justification: LongText
    issued_at: UtcDatetime

    @model_validator(mode="after")
    def validate_decision_shape(self) -> Self:
        temporary = self.decision in {
            DecisionAction.ALLOW_TEMPORARY,
            DecisionAction.BLOCK_TEMPORARY,
        }
        if temporary:
            missing: list[str] = []
            if self.grant_scope is None:
                missing.append("grant_scope")
            if self.ttl_seconds is None:
                missing.append("ttl_seconds")
            if self.approved_by is None:
                missing.append("approved_by")
            if missing:
                raise ValueError(f"{self.decision.value} requires {', '.join(missing)}")
        elif self.grant_scope is not None or self.ttl_seconds is not None:
            raise ValueError("non-temporary decisions must not include scope or TTL")
        return self

    @property
    def effective_decision(self) -> DecisionAction:
        """Map legacy DENY to the canonical keep-current-policy behavior."""

        if self.decision is DecisionAction.DENY:
            return DecisionAction.KEEP_CURRENT_POLICY
        return self.decision


class ChatContextResponse(StrictModel):
    """Untrusted organizational context returned for one active request round."""

    schema_version: Literal["chat-context-response-v1"]
    response_id: Identifier
    request_id: Identifier
    event_id: Identifier
    incident_id: Identifier
    incident_version: Annotated[int, Field(ge=1)]
    context_round: Annotated[int, Field(ge=1, le=100)]
    provided_context: Annotated[list[LongText], Field(min_length=1, max_length=32)]
    provided_by: ApproverIdentity
    issued_at: UtcDatetime
    trust: AdvisoryTrustValue = AdvisoryTrust.UNTRUSTED_ADVISORY


class EnforcementResult(StrictModel):
    schema_version: Literal["enforcement-result-v1"]
    decision_id: Identifier
    event_id: Identifier
    incident_id: Identifier | None = None
    status: EnforcementStatusValue
    reason_code: EnforcementReasonCodeValue
    firewall_rule_id: Identifier | None = None
    expires_at: UtcDatetime | None = None
    detail: Description | None = None

    @model_validator(mode="after")
    def validate_applied_result(self) -> Self:
        if self.status is EnforcementStatus.APPLIED:
            if self.firewall_rule_id is None or self.expires_at is None:
                raise ValueError("APPLIED requires firewall_rule_id and expires_at")
        return self


class EventAcceptedResponse(StrictModel):
    event_id: Identifier
    incident_id: Identifier
    state: IncidentStateValue
    deduplicated: bool


class NetworkEventResponse(StrictModel):
    event: NetworkEventIn
    incident_id: Identifier
    disposition: EventDispositionValue


class IncidentResponse(StrictModel):
    incident_id: Identifier
    primary_event_id: Identifier
    state: IncidentStateValue
    version: Annotated[int, Field(ge=1)]
    created_at: UtcDatetime
    updated_at: UtcDatetime
    first_seen_at: UtcDatetime
    last_seen_at: UtcDatetime
    packet_count: PositiveCount
    event: NetworkEventIn
    analysis: AgentAnalysis | None = None
    context_request: ContextRequest | None = None
    enforcement_result: EnforcementResult | None = None
    last_error_code: Identifier | None = None
    last_error_detail: Description | None = None

    @model_validator(mode="after")
    def validate_incident_times(self) -> Self:
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at cannot precede first_seen_at")
        if self.updated_at < self.created_at:
            raise ValueError("updated_at cannot precede created_at")
        return self


class AuditTimelineEvent(StrictModel):
    timestamp: UtcDatetime
    incident_id: Identifier
    event_id: Identifier | None = None
    component: Identifier
    action: Identifier
    raw_context: BoundedRawContext = Field(default_factory=dict)


class IncidentTimelineResponse(StrictModel):
    incident_id: Identifier
    events: Annotated[list[AuditTimelineEvent], Field(max_length=10_000)]


class IncidentListResponse(StrictModel):
    incidents: list[IncidentResponse]
    total: NonNegativeCount


# Compatibility names used by the build specification and likely integration
# code.  They intentionally reference the same frozen contract definitions.
DropEventIn = FirewallDropEvent
FirewallDropEventIn = FirewallDropEvent
GenericNetworkEvent = GenericNetworkEventIn
ZeekEvent = ZeekEventIn
DecisionIn = ChatDecision
ContextResponseIn = ChatContextResponse
ContextRequestOut = ContextRequest
EventIngestResponse = EventAcceptedResponse
Direction = TrafficDirection


ExternalNetworkEvent = FirewallDropEvent | GenericNetworkEventIn | ZeekEventIn | NetworkEventIn


__all__ = [
    "AgentAnalysis",
    "AnalysisAction",
    "AdvisoryTrust",
    "ApproverIdentity",
    "AuditTimelineEvent",
    "BoundedRawContext",
    "BoundedZeekRecord",
    "ChatDecision",
    "ChatContextResponse",
    "ContextAnalysisSummary",
    "ContextRequest",
    "ContextRequestOut",
    "ContextRequestType",
    "ContextResponseIn",
    "DecisionAction",
    "DecisionIn",
    "Direction",
    "DropEventIn",
    "EnforcementReasonCode",
    "EnforcementResult",
    "EnforcementStatus",
    "EventAcceptedResponse",
    "EventDisposition",
    "EventIngestResponse",
    "EventSource",
    "ExternalNetworkEvent",
    "FirewallDirection",
    "FirewallDropEvent",
    "FirewallDropEventIn",
    "FlowScope",
    "GenericNetworkEvent",
    "GenericNetworkEventIn",
    "IPAddress",
    "InterfaceName",
    "IncidentListResponse",
    "IncidentResponse",
    "IncidentState",
    "IncidentTimelineResponse",
    "MatchedPolicy",
    "NetworkEventIn",
    "NetworkEventResponse",
    "NetworkEventType",
    "NetworkFlow",
    "NetworkProtocol",
    "ObservedFlow",
    "PolicyMetadata",
    "Port",
    "RuleAction",
    "Severity",
    "StrictModel",
    "TTLSeconds",
    "TrafficDirection",
    "TransportProtocol",
    "UtcDatetime",
    "ZeekEvent",
    "ZeekEventIn",
]
