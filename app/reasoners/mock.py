"""Deterministic network evidence reasoner for local development and tests."""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Mapping
from typing import Any

from ..schemas import AgentAnalysis, AnalysisAction, NetworkEventType
from .base import BaseReasoner, EvidenceCapsule, ReasoningResult
from .prompt import ANALYSIS_SCHEMA_VERSION, PROMPT_VERSION, event_type_label

MOCK_MODEL = "deterministic-network-reasoner-v1"
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(mode="python")
        if isinstance(dumped, Mapping):
            return dumped
    return {}


def _event(evidence: EvidenceCapsule) -> Mapping[str, Any]:
    for key in ("event", "network_event", "normalized_event", "telemetry"):
        candidate = _mapping(evidence.get(key))
        if candidate:
            return candidate
    return evidence


def _first(source: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = source.get(key)
        if value is not None and value != "":
            return value
    return None


def _safe_ip(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def _safe_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _safe_protocol(value: Any) -> str | None:
    if value is None:
        return None
    protocol = str(getattr(value, "value", value)).lower()
    return protocol if protocol in {"tcp", "udp", "icmp", "icmpv6"} else None


def _safe_identifier(value: Any) -> str | None:
    if value is None:
        return None
    candidate = str(getattr(value, "value", value))
    return candidate if _SAFE_IDENTIFIER.fullmatch(candidate) else None


def _truthy_flag(source: Mapping[str, Any], *keys: str) -> bool:
    return any(source.get(key) is True for key in keys)


def _action(value: str) -> AnalysisAction:
    """Construct by value so this stays independent of Enum member spelling style."""

    return AnalysisAction(value)


def _flow_question(
    source_ip: str | None,
    destination_ip: str | None,
    destination_port: int | None,
    protocol: str | None,
    *,
    elevated: bool = False,
) -> str:
    if source_ip and destination_ip:
        service = destination_ip
        if destination_port is not None:
            service += f":{destination_port}"
        transport = f" over {protocol.upper()}" if protocol else ""
        if elevated:
            return (
                f"Can a security operator verify whether activity from {source_ip} to "
                f"{service}{transport} is expected and safe, and identify the responsible owner?"
            )
        return (
            f"Is activity from {source_ip} to {service}{transport} currently expected and "
            "organizationally authorized, and if so for what approved purpose?"
        )
    if source_ip:
        return (
            "Can a security operator identify the intended destination and confirm whether "
            "activity "
            f"from {source_ip} is currently expected and authorized?"
        )
    if destination_ip:
        return (
            f"Can a security operator identify the source and confirm whether activity involving "
            f"{destination_ip} is currently expected and authorized?"
        )
    return (
        "Can a security operator identify the affected source and destination and confirm whether "
        "this activity is expected and authorized?"
    )


def build_fail_closed_analysis() -> AgentAnalysis:
    """Return a context-only fallback that can never authorize network access."""

    return AgentAnalysis(
        schema_version=ANALYSIS_SCHEMA_VERSION,
        summary=(
            "A network event could not be fully analyzed; existing policy must remain in effect."
        ),
        observed_facts=[],
        inferences=[],
        missing_context=[
            "Whether the exact observed network activity is organizationally authorized"
        ],
        recommended_action=_action("REQUEST_CONTEXT"),
        question="Is this exact observed service flow authorized temporarily?",
        confidence=0.0,
    )


def build_mock_analysis(
    evidence: EvidenceCapsule,
    event_type: NetworkEventType | None = None,
) -> AgentAnalysis:
    """Build a cautious, repeatable analysis from common firewall and Zeek fields."""

    event = _event(evidence)
    flow = _mapping(event.get("flow"))
    zeek_record = _mapping(event.get("record"))
    source_ip = _safe_ip(
        _first(event, "source_ip", "src_ip", "id.orig_h")
        or _first(flow, "source_ip", "src_ip")
        or _first(zeek_record, "source_ip", "src_ip", "id.orig_h")
    )
    destination_ip = _safe_ip(
        _first(event, "destination_ip", "dest_ip", "dst_ip", "id.resp_h")
        or _first(flow, "destination_ip", "dest_ip", "dst_ip")
        or _first(zeek_record, "destination_ip", "dest_ip", "dst_ip", "id.resp_h")
    )
    source_port = _safe_port(
        _first(event, "source_port", "src_port", "id.orig_p")
        or _first(flow, "source_port", "src_port")
        or _first(zeek_record, "source_port", "src_port", "id.orig_p")
    )
    destination_port = _safe_port(
        _first(event, "destination_port", "dest_port", "dst_port", "id.resp_p")
        or _first(flow, "destination_port", "dest_port", "dst_port")
        or _first(
            zeek_record,
            "destination_port",
            "dest_port",
            "dst_port",
            "id.resp_p",
        )
    )
    protocol = _safe_protocol(
        _first(event, "protocol", "proto", "transport")
        or _first(flow, "protocol", "proto", "transport")
        or _first(zeek_record, "protocol", "proto", "transport")
    )
    event_policy = _mapping(event.get("policy_metadata"))
    rule_id = _safe_identifier(
        _first(event, "rule_id", "policy_id") or _first(event_policy, "rule_id", "policy_id")
    )

    raw_kind = event_type_label(event_type)
    if event_type is None:
        raw_kind = str(
            getattr(
                _first(event, "event_type", "type", "source_type", "sensor_type"),
                "value",
                _first(event, "event_type", "type", "source_type", "sensor_type") or "unspecified",
            )
        )
    kind = raw_kind.upper()
    disposition = str(
        getattr(event.get("disposition"), "value", event.get("disposition") or "")
    ).upper()
    is_drop = (
        "DROP" in kind
        or "DENY" in kind
        or "drop_reason" in event
        or disposition in {"BLOCKED", "DENIED", "DROPPED"}
    )
    source_label = str(getattr(event.get("source"), "value", event.get("source") or "")).upper()
    is_zeek = (
        "ZEEK" in kind
        or "ZEEK" in source_label
        or "log_type" in event
        or bool(zeek_record)
        or any(key in event for key in ("uid", "conn_state", "notice_type"))
    )
    duplicate = _truthy_flag(evidence, "duplicate", "deduplicated", "is_duplicate")

    severity_value = _first(event, "severity", "risk_level") or _first(
        evidence, "severity", "risk_level"
    )
    severity = str(getattr(severity_value, "value", severity_value or "")).lower()
    elevated = severity in {"high", "critical"}

    facts: list[str] = []
    safe_kind = _safe_identifier(raw_kind)
    if safe_kind and safe_kind.lower() != "unspecified":
        facts.append(f"The validated event category is {safe_kind}.")
    if source_ip:
        facts.append(f"The observed source IP is {source_ip}.")
    if destination_ip:
        destination = destination_ip
        if destination_port is not None:
            destination += f":{destination_port}"
        if protocol:
            destination += f" over {protocol.upper()}"
        facts.append(f"The observed destination service is {destination}.")
    elif destination_port is not None:
        facts.append(f"The observed destination port is {destination_port}.")
    if source_port is not None:
        facts.append(f"The observed source port is {source_port}.")
    if rule_id:
        facts.append(f"The reporting control identified rule {rule_id}.")
    if is_drop:
        facts.append("The event reports that configured policy blocked the activity.")
    elif is_zeek:
        facts.append("The event was reported as network telemetry by a Zeek-compatible source.")
    if duplicate:
        facts.append("The evidence capsule explicitly marks this event as a duplicate.")

    policy = _mapping(
        evidence.get("matched_policy") or evidence.get("policy") or event.get("policy_metadata")
    )
    policy_rule = _safe_identifier(_first(policy, "rule_id", "policy_id"))
    if policy_rule and policy_rule != rule_id:
        facts.append(f"The evidence capsule matched policy {policy_rule}.")

    blocked_source = evidence.get("blocked_source")
    if isinstance(blocked_source, Mapping) and blocked_source.get("matched") is True:
        facts.append("The source matched the configured blocked-source dataset.")

    if duplicate:
        return AgentAnalysis(
            schema_version=ANALYSIS_SCHEMA_VERSION,
            summary=(
                "The evidence marks this as a duplicate network event, so no second context "
                "request is needed."
            ),
            observed_facts=facts,
            inferences=[],
            missing_context=[],
            recommended_action=_action("IGNORE_DUPLICATE"),
            question=None,
            confidence=1.0,
        )

    missing: list[str] = []
    if source_ip is None:
        missing.append("The validated source IP associated with the event")
    if destination_ip is None:
        missing.append("The validated destination IP associated with the event")
    if protocol is None:
        missing.append("The network protocol associated with the event")
    if destination_port is None and protocol in {"tcp", "udp"}:
        missing.append("The destination service port associated with the event")
    missing.extend(
        [
            "Whether the activity is expected for the identified asset owner",
            "Whether the exact observed service flow is currently authorized",
        ]
    )

    question = _flow_question(
        source_ip,
        destination_ip,
        destination_port,
        protocol,
        elevated=elevated,
    )

    if source_ip is None or destination_ip is None:
        summary = (
            "Network telemetry was received, but it lacks enough validated flow identity for a "
            "scoped access decision; existing policy should remain in effect."
        )
        inferences = [
            "The incomplete telemetry may need correlation with another sensor before human "
            "intent can be evaluated."
        ]
        action = _action("ESCALATE")
        confidence = 0.45
    elif is_drop:
        summary = (
            f"Activity from {source_ip} to {destination_ip}"
            f"{f':{destination_port}' if destination_port is not None else ''} was blocked by "
            "configured policy, "
            "but network evidence alone cannot establish organizational intent."
        )
        inferences = [
            "The activity could be legitimate work that is not represented by current policy.",
            "It could also be unauthorized; the network evidence does not distinguish those "
            "possibilities.",
        ]
        action = _action("REQUEST_CONTEXT")
        confidence = 0.9 if rule_id else 0.8
    elif is_zeek:
        summary = (
            f"Zeek-compatible telemetry reported activity from {source_ip} to {destination_ip}"
            f"{f':{destination_port}' if destination_port is not None else ''}; human or "
            "organizational context "
            "is needed to determine whether it is expected."
        )
        inferences = [
            "The activity may be expected application behavior or suspicious activity; this "
            "telemetry alone does not establish which."
        ]
        action = _action("ESCALATE" if elevated else "REQUEST_CONTEXT")
        confidence = 0.82 if elevated else 0.76
    else:
        summary = (
            f"Network activity from {source_ip} to {destination_ip}"
            f"{f':{destination_port}' if destination_port is not None else ''} was observed; its "
            "business purpose "
            "and authorization are not present in the evidence."
        )
        inferences = [
            "The activity may be routine or unauthorized; additional organizational context is "
            "required."
        ]
        action = _action("ESCALATE" if elevated else "REQUEST_CONTEXT")
        confidence = 0.72

    return AgentAnalysis(
        schema_version=ANALYSIS_SCHEMA_VERSION,
        summary=summary,
        observed_facts=facts,
        inferences=inferences,
        missing_context=missing,
        recommended_action=action,
        question=question,
        confidence=confidence,
    )


class MockReasoner(BaseReasoner):
    """Cheap deterministic implementation used for the disconnected demo."""

    @property
    def provider(self) -> str:
        return "mock"

    async def analyze(
        self,
        evidence: EvidenceCapsule,
        *,
        event_type: NetworkEventType,
    ) -> ReasoningResult:
        started = time.perf_counter()
        analysis = build_mock_analysis(evidence, event_type)
        latency_ms = (time.perf_counter() - started) * 1000
        return ReasoningResult(
            analysis=analysis,
            provider=self.provider,
            model=MOCK_MODEL,
            prompt_version=PROMPT_VERSION,
            schema_version=ANALYSIS_SCHEMA_VERSION,
            latency_ms=latency_ms,
        )


def create_mock_reasoner() -> MockReasoner:
    """Create the deterministic reasoner without configuration or credentials."""

    return MockReasoner()
