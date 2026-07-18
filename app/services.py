from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.chat import ChatDispatcher
from app.database import ContextConflict, Database, DecisionConflict
from app.firewall import (
    ExactServiceScope,
    FirewallAdapter,
    FirewallError,
    FirewallReceipt,
    FirewallReconciliationError,
    ValidatedFlowGrant,
    group_managed_grants,
)
from app.normalizers import normalize_network_event
from app.policy import PolicyLoader
from app.reasoners import Reasoner
from app.reasoners.mock import build_fail_closed_analysis
from app.schemas import (
    AgentAnalysis,
    ApproverIdentity,
    ChatContextResponse,
    ChatDecision,
    ContextAnalysisSummary,
    ContextRequest,
    DecisionAction,
    EnforcementReasonCode,
    EnforcementResult,
    EnforcementStatus,
    FlowScope,
    IncidentResponse,
    IncidentState,
    IncidentTimelineResponse,
    MatchedPolicy,
    NetworkEventIn,
    NetworkProtocol,
    ObservedFlow,
    RuleAction,
    TrafficDirection,
)
from app.settings import Settings
from app.time_utils import isoformat_z, parse_timestamp, utc_now


def _fingerprint(event: NetworkEventIn) -> str:
    flow = event.flow
    rule_id = event.policy_metadata.rule_id if event.policy_metadata else None
    material = {
        "source": event.source.value,
        "event_type": event.event_type.value,
        "source_ip": str(flow.source_ip) if flow.source_ip else None,
        "destination_ip": str(flow.destination_ip) if flow.destination_ip else None,
        "destination_port": flow.destination_port,
        "protocol": flow.protocol.value,
        "rule_id": rule_id,
        "reason": event.reason,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _usage_dict(result: Any) -> dict[str, int | None] | None:
    usage = getattr(result, "usage", None)
    if usage is None:
        return None
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "total_tokens": usage.total_tokens,
    }


def _receipt_to_dict(receipt: FirewallReceipt) -> dict[str, Any]:
    scope = receipt.exact_scope
    return {
        "rule_id": receipt.rule_id,
        "exact_scope": {
            "source_ip": str(scope.source_ip),
            "destination_ip": str(scope.destination_ip),
            "destination_port": scope.destination_port,
            "protocol": scope.protocol,
            "direction": scope.direction,
            "interface_in": scope.interface_in,
            "interface_out": scope.interface_out,
        },
        "action": receipt.action.value,
        "chain": receipt.chain,
        "expires_at": isoformat_z(receipt.expires_at),
        "installed_at": isoformat_z(receipt.installed_at) if receipt.installed_at else None,
        "adapter": receipt.adapter,
        "install_argv": list(receipt.install_argv),
        "delete_argv": list(receipt.delete_argv),
    }


def _receipt_from_rule(row: dict[str, Any]) -> FirewallReceipt:
    data = row["receipt_json"]
    scope_data = data.get("exact_scope") or row["scope_json"]
    exact_scope = ExactServiceScope(
        source_ip=scope_data["source_ip"],
        destination_ip=scope_data["destination_ip"],
        destination_port=scope_data["destination_port"],
        protocol=scope_data["protocol"],
        direction=scope_data.get("direction"),
        interface_in=scope_data.get("interface_in"),
        interface_out=scope_data.get("interface_out"),
    )
    return FirewallReceipt(
        rule_id=row["rule_id"],
        exact_scope=exact_scope,
        action=RuleAction(row["action"]),
        chain=data.get(
            "chain", "CONTEXT_ALLOW" if row["action"] == "ALLOW" else "CONTEXT_BLOCK"
        ),
        expires_at=parse_timestamp(data.get("expires_at") or row["expires_at"]),
        installed_at=(
            parse_timestamp(data["installed_at"]) if data.get("installed_at") else None
        ),
        adapter=data.get("adapter", "reconstructed"),
        install_argv=tuple(data.get("install_argv") or ()),
        delete_argv=tuple(data.get("delete_argv") or ()),
    )


@dataclass(slots=True)
class NetworkAgentService:
    settings: Settings
    database: Database
    policies: PolicyLoader
    reasoner: Reasoner
    chat: ChatDispatcher
    _analysis_slots: asyncio.Semaphore = field(init=False, repr=False)
    last_reasoner_status: str = field(init=False, default="not_checked")
    last_reasoner_checked_at: datetime | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._analysis_slots = asyncio.Semaphore(self.settings.max_concurrent_analyses)

    async def _analyze(
        self, evidence: dict[str, Any], event: NetworkEventIn
    ) -> tuple[AgentAnalysis, dict[str, Any] | None, str | None]:
        """Run bounded advisory inference and return a fail-closed result on failure."""

        acquired = False
        try:
            await asyncio.wait_for(
                self._analysis_slots.acquire(),
                timeout=self.settings.analysis_queue_timeout_seconds,
            )
            acquired = True
        except TimeoutError:
            self.last_reasoner_status = "overloaded"
            self.last_reasoner_checked_at = utc_now()
            return build_fail_closed_analysis(), None, "REASONER_OVERLOADED"

        try:
            result = await self.reasoner.analyze(evidence, event_type=event.event_type)
            self.last_reasoner_status = "ok"
            self.last_reasoner_checked_at = utc_now()
            return (
                result.analysis,
                {
                    "provider": result.provider,
                    "model": result.model,
                    "prompt_version": result.prompt_version,
                    "schema_version": result.schema_version,
                    "latency_ms": round(result.latency_ms, 2),
                    "usage": _usage_dict(result),
                    "response_id": result.response_id,
                },
                None,
            )
        except Exception:
            # No exception text crosses the trust boundary: provider errors can
            # contain request metadata. Existing network policy stays in effect.
            self.last_reasoner_status = "failed"
            self.last_reasoner_checked_at = utc_now()
            return build_fail_closed_analysis(), None, "REASONER_UNAVAILABLE"
        finally:
            if acquired:
                self._analysis_slots.release()

    async def process(self, incoming: Any) -> IncidentResponse:
        event = normalize_network_event(incoming)
        event_data = event.model_dump(mode="json")
        incident, deduplicated = self.database.create_or_deduplicate_event(
            event_data,
            _fingerprint(event),
            self.settings.dedup_window_seconds,
        )
        incident_id = incident["incident_id"]
        if deduplicated:
            self.database.audit(
                "event_service",
                "DUPLICATE_EVENT_COALESCED",
                incident_id=incident_id,
                event_id=event.event_id,
                details={"packet_count": incident["packet_count"]},
            )
            return self.incident_response(incident_id)

        self.database.audit(
            "event_service",
            "NETWORK_EVENT_RECEIVED",
            incident_id=incident_id,
            event_id=event.event_id,
            details={
                "source": event.source.value,
                "event_type": event.event_type.value,
                "severity": event.severity.value,
            },
        )
        self.database.transition_incident(
            incident_id, {IncidentState.DETECTED.value}, IncidentState.ANALYZING.value
        )
        evidence = self.policies.build_evidence(event)
        self.database.update_incident(incident_id, evidence_json=evidence)
        self.database.audit(
            "policy_service",
            "EVIDENCE_CAPSULE_BUILT",
            incident_id=incident_id,
            event_id=event.event_id,
            details={
                "matched_rule_id": evidence["matched_policy"].get("rule_id", "DEFAULT")
            },
        )

        analysis, reasoning_metadata, reasoner_failure = await self._analyze(evidence, event)
        if reasoning_metadata is not None:
            self.database.audit(
                "reasoner",
                "ANALYSIS_COMPLETED",
                incident_id=incident_id,
                event_id=event.event_id,
                details=reasoning_metadata,
            )
        else:
            self.database.audit(
                "reasoner",
                "ANALYSIS_FAILED_FAIL_CLOSED",
                incident_id=incident_id,
                event_id=event.event_id,
                details={"error_code": reasoner_failure},
            )

        analysis_data = analysis.model_dump(mode="json")
        self.database.update_incident(
            incident_id,
            analysis_json=analysis_data,
            last_error_code=reasoner_failure,
            last_error_detail=(
                "The configured reasoner failed; existing policy remains in effect."
                if reasoner_failure
                else None
            ),
        )

        if analysis.recommended_action.value in {"REQUEST_CONTEXT", "ESCALATE"}:
            waiting = self.database.transition_incident(
                incident_id,
                {IncidentState.ANALYZING.value},
                IncidentState.WAITING_FOR_CONTEXT.value,
            )
            request = self._build_context_request(
                event,
                evidence,
                analysis,
                waiting,
                reasoner_failure=reasoner_failure,
            )
            request_data = request.model_dump(mode="json")
            self.database.create_context_request(request_data)
            delivered = await self.chat.dispatch(request_data)
            self.database.audit(
                "chat_dispatcher",
                "CONTEXT_REQUEST_AVAILABLE" if delivered else "CONTEXT_DELIVERY_PENDING",
                incident_id=incident_id,
                event_id=event.event_id,
                details={"request_id": request.request_id, "chat_mode": self.settings.chat_mode},
            )
        else:
            terminal = (
                IncidentState.KEPT_BLOCKED
                if analysis.recommended_action.value in {"KEEP_BLOCKED", "IGNORE_DUPLICATE"}
                else IncidentState.ANALYSIS_FAILED
            )
            self.database.transition_incident(
                incident_id,
                {IncidentState.ANALYZING.value},
                terminal.value,
            )

        return self.incident_response(incident_id)

    def _build_context_request(
        self,
        event: NetworkEventIn,
        evidence: dict[str, Any],
        analysis: AgentAnalysis,
        incident: dict[str, Any],
        *,
        reasoner_failure: str | None = None,
        context_round: int = 1,
        previous_request_id: str | None = None,
    ) -> ContextRequest:
        flow = event.flow
        interface_in = event.raw_context.get("interface_in")
        interface_out = event.raw_context.get("interface_out")
        base_scope_complete = (
            flow.source_ip is not None
            and flow.destination_ip is not None
            and flow.destination_port is not None
            and flow.protocol in {NetworkProtocol.TCP, NetworkProtocol.UDP}
            and flow.source_ip.version == 4
            and flow.destination_ip.version == 4
            and flow.direction is TrafficDirection.FORWARD
            and isinstance(interface_in, str)
            and isinstance(interface_out, str)
        )
        observed: ObservedFlow | None = None
        permitted_scope: FlowScope | None = None
        if base_scope_complete:
            try:
                permitted_scope = FlowScope(
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    destination_port=flow.destination_port,
                    protocol=flow.protocol.value,
                    direction="forward",
                    interface_in=interface_in,
                    interface_out=interface_out,
                )
                observed = ObservedFlow(
                    **permitted_scope.model_dump(),
                    source_port=flow.source_port,
                    timestamp=event.timestamp,
                )
            except ValueError:
                permitted_scope = None
                observed = None
        complete_scope = permitted_scope is not None

        allowed = self.policies.allowed_decisions(
            event.event_type.value, complete_scope, evidence=evidence
        )
        if reasoner_failure:
            allowed = ["KEEP_CURRENT_POLICY", "REQUEST_MORE_INFORMATION"]
        maximum_ttl = self.policies.maximum_ttl(evidence, self.settings.max_ttl_seconds)
        created_at = utc_now()
        expires_at = created_at + timedelta(
            seconds=self.settings.context_request_timeout_seconds
        )
        policy_data = dict(evidence.get("matched_policy") or {})
        policy_rule_id = str(policy_data.get("rule_id") or "DEFAULT")
        policy_description = str(
            policy_data.get("description") or "No named local policy description was available"
        )
        if permitted_scope is not None:
            source_port_note = (
                f" Observed source port {flow.source_port} is evidence only and is not "
                "part of the firewall rule."
                if flow.source_port is not None
                else " Source port was not observed and is not part of the firewall rule."
            )
            question = (
                "Should the current policy be changed temporarily for only the exact "
                f"forward flow {permitted_scope.source_ip} to "
                f"{permitted_scope.destination_ip}:{permitted_scope.destination_port}/"
                f"{permitted_scope.protocol.value} through "
                f"{permitted_scope.interface_in} to {permitted_scope.interface_out}?"
                f"{source_port_note}"
            )
        else:
            question = (
                "Can the responsible human or chat agent provide the missing trusted context? "
                "No network change is available until an IPv4 forward TCP/UDP service flow "
                "and an authorizing local policy are present."
            )
        missing_context = analysis.missing_context or [
            "Whether this network activity is expected and authorized"
        ]
        return ContextRequest(
            schema_version="context-request-v1",
            request_id=f"ctx-{uuid.uuid4().hex[:20]}",
            event_id=event.event_id,
            incident_id=incident["incident_id"],
            incident_version=incident["version"],
            context_round=context_round,
            previous_request_id=previous_request_id,
            severity=event.severity,
            created_at=created_at,
            expires_at=expires_at,
            observed_flow=observed,
            permitted_grant_scope=permitted_scope,
            matched_policy=MatchedPolicy(
                rule_id=policy_rule_id,
                description=policy_description,
                maximum_ttl_seconds=maximum_ttl,
            ),
            agent_analysis=ContextAnalysisSummary(
                summary=analysis.summary,
                missing_context=missing_context,
            ),
            question=question,
            allowed_responses=allowed,
            maximum_ttl_seconds=maximum_ttl,
        )

    async def process_context_response(
        self,
        response: ChatContextResponse,
        *,
        verified_provider: ApproverIdentity | None = None,
    ) -> IncidentResponse:
        """Store attributed context, reanalyze it, and optionally ask the next question."""

        response_data = response.model_dump(mode="json")
        if self.settings.chat_integration_token or self.settings.integration_api_token:
            if verified_provider is None:
                raise ContextConflict(
                    "UNAUTHENTICATED_CONTEXT", "Verified chat-agent identity is required"
                )
            response_data["provided_by"] = verified_provider.model_dump(mode="json")
            response = ChatContextResponse.model_validate(response_data)

        if len(json.dumps(response_data["provided_context"]).encode("utf-8")) > 16_384:
            raise ContextConflict(
                "CONTEXT_TOO_LARGE", "Combined supplied context exceeds 16 KiB"
            )
        request = self.database.get_context_request(response.request_id)
        if request is None:
            raise ContextConflict("UNKNOWN_REQUEST", "Context request does not exist")
        now = utc_now()
        clock_skew = timedelta(seconds=self.settings.decision_clock_skew_seconds)
        if response.issued_at < parse_timestamp(request["created_at"]) - clock_skew:
            raise ContextConflict(
                "STALE_CONTEXT_RESPONSE", "Context response predates its request"
            )
        if response.issued_at > now + clock_skew:
            raise ContextConflict(
                "FUTURE_CONTEXT_RESPONSE", "Context response time is in the future"
            )
        if response.issued_at > parse_timestamp(request["expires_at"]) + clock_skew:
            raise ContextConflict(
                "STALE_CONTEXT_RESPONSE",
                "Context response was issued after the request expired",
            )

        incident, _request, _stored_response = self.database.store_context_response(
            response_data
        )
        incident, _request, _stored_response = self.database.claim_context_response(
            response.response_id, incident["version"]
        )
        analyzing = self.database.transition_incident(
            incident["incident_id"],
            {IncidentState.WAITING_FOR_CONTEXT.value},
            IncidentState.ANALYZING.value,
        )
        event = NetworkEventIn.model_validate(analyzing["event_json"])
        evidence = dict(analyzing.get("evidence_json") or self.policies.build_evidence(event))
        supplemental = list(evidence.get("supplemental_context") or [])
        supplemental.append(
            {
                "response_id": response.response_id,
                "request_id": response.request_id,
                "context_round": response.context_round,
                "provided_context": response.provided_context,
                "provided_by": response.provided_by.model_dump(mode="json"),
                "issued_at": response.issued_at.isoformat(),
                "trust": "UNTRUSTED_ADVISORY",
            }
        )
        evidence["supplemental_context"] = supplemental
        evidence["safety_boundary"] = {
            **dict(evidence.get("safety_boundary") or {}),
            "supplemental_context_is_untrusted": True,
            "supplemental_context_cannot_authorize_firewall_changes": True,
        }
        self.database.update_incident(analyzing["incident_id"], evidence_json=evidence)
        self.database.audit(
            "context_service",
            "CONTEXT_RESPONSE_RECEIVED",
            incident_id=analyzing["incident_id"],
            event_id=event.event_id,
            details={
                "response_id": response.response_id,
                "request_id": response.request_id,
                "context_round": response.context_round,
                "trust": "UNTRUSTED_ADVISORY",
            },
        )

        analysis, metadata, reasoner_failure = await self._analyze(evidence, event)
        self.database.update_incident(
            analyzing["incident_id"],
            analysis_json=analysis.model_dump(mode="json"),
            last_error_code=reasoner_failure,
            last_error_detail=(
                "Reanalysis failed; existing policy remains in effect."
                if reasoner_failure
                else None
            ),
        )
        self.database.audit(
            "reasoner",
            "CONTEXT_REANALYSIS_COMPLETED" if metadata else "CONTEXT_REANALYSIS_FAILED",
            incident_id=analyzing["incident_id"],
            event_id=event.event_id,
            details=metadata or {"error_code": reasoner_failure},
        )

        asks_again = analysis.recommended_action.value in {"REQUEST_CONTEXT", "ESCALATE"}
        can_ask_again = response.context_round < self.settings.max_context_rounds
        if asks_again and can_ask_again and reasoner_failure is None:
            waiting = self.database.transition_incident(
                analyzing["incident_id"],
                {IncidentState.ANALYZING.value},
                IncidentState.WAITING_FOR_CONTEXT.value,
            )
            followup = self._build_context_request(
                event,
                evidence,
                analysis,
                waiting,
                context_round=response.context_round + 1,
                previous_request_id=response.request_id,
            )
            followup_data = followup.model_dump(mode="json")
            self.database.create_followup_context_request(
                followup_data, response.response_id
            )
            delivered = await self.chat.dispatch(followup_data)
            self.database.audit(
                "chat_dispatcher",
                "FOLLOWUP_CONTEXT_REQUEST_AVAILABLE"
                if delivered
                else "FOLLOWUP_CONTEXT_DELIVERY_PENDING",
                incident_id=analyzing["incident_id"],
                event_id=event.event_id,
                details={
                    "request_id": followup.request_id,
                    "previous_request_id": response.request_id,
                    "context_round": followup.context_round,
                },
            )
        else:
            if reasoner_failure:
                terminal = IncidentState.ANALYSIS_FAILED
                error_code = reasoner_failure
                error_detail = "Context reanalysis failed; the existing policy remains active"
            elif asks_again and not can_ask_again:
                terminal = IncidentState.KEPT_BLOCKED
                error_code = "MAX_CONTEXT_ROUNDS"
                error_detail = "Maximum context rounds reached; existing policy was retained"
            elif analysis.recommended_action.value in {"KEEP_BLOCKED", "IGNORE_DUPLICATE"}:
                terminal = IncidentState.KEPT_BLOCKED
                error_code = None
                error_detail = None
            else:
                terminal = IncidentState.ANALYSIS_FAILED
                error_code = "UNSUPPORTED_ANALYSIS_OUTCOME"
                error_detail = "No safe follow-up action was available"
            self.database.transition_incident(
                analyzing["incident_id"],
                {IncidentState.ANALYZING.value},
                terminal.value,
                last_error_code=error_code,
                last_error_detail=error_detail,
            )
            self.database.complete_context_response(response.response_id)

        return self.incident_response(analyzing["incident_id"])

    def incident_response(self, incident_id: str) -> IncidentResponse:
        incident = self.database.get_incident(incident_id)
        if incident is None:
            raise KeyError(incident_id)
        context_request = None
        if incident.get("request_id"):
            row = self.database.get_context_request(incident["request_id"])
            if row:
                context_request = ContextRequest.model_validate(row["payload_json"])
        return IncidentResponse(
            incident_id=incident["incident_id"],
            primary_event_id=incident["primary_event_id"],
            state=incident["state"],
            version=incident["version"],
            created_at=incident["created_at"],
            updated_at=incident["updated_at"],
            first_seen_at=incident["first_seen_at"],
            last_seen_at=incident["last_seen_at"],
            packet_count=incident["packet_count"],
            event=NetworkEventIn.model_validate(incident["event_json"]),
            analysis=(
                AgentAnalysis.model_validate(incident["analysis_json"])
                if incident.get("analysis_json")
                else None
            ),
            context_request=context_request,
            enforcement_result=(
                EnforcementResult.model_validate(incident["enforcement_json"])
                if incident.get("enforcement_json")
                else None
            ),
            last_error_code=incident.get("last_error_code"),
            last_error_detail=incident.get("last_error_detail"),
        )

    def timeline(self, incident_id: str) -> IncidentTimelineResponse:
        if self.database.get_incident(incident_id) is None:
            raise KeyError(incident_id)
        events = [
            {
                "timestamp": row["timestamp"],
                "incident_id": incident_id,
                "event_id": row.get("event_id"),
                "component": row["component"],
                "action": row["action"],
                "raw_context": row["details_json"],
            }
            for row in self.database.timeline(incident_id)
        ]
        return IncidentTimelineResponse(incident_id=incident_id, events=events)


@dataclass(slots=True)
class DecisionService:
    settings: Settings
    database: Database
    firewall: FirewallAdapter
    policies: PolicyLoader

    def _rejected(
        self,
        decision: ChatDecision,
        reason: EnforcementReasonCode,
        detail: str,
    ) -> EnforcementResult:
        return EnforcementResult(
            schema_version="enforcement-result-v1",
            decision_id=decision.decision_id,
            event_id=decision.event_id,
            incident_id=decision.incident_id,
            status=EnforcementStatus.REJECTED,
            reason_code=reason,
            detail=detail,
        )

    def _validate(
        self,
        decision: ChatDecision,
        verified_approver: ApproverIdentity | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], DecisionAction] | EnforcementResult:
        request = self.database.get_context_request(decision.request_id)
        if request is None:
            return self._rejected(
                decision, EnforcementReasonCode.REQUEST_MISMATCH, "Unknown context request"
            )
        incident = self.database.get_incident(request["incident_id"])
        if incident is None:
            return self._rejected(
                decision, EnforcementReasonCode.INCIDENT_NOT_FOUND, "Unknown incident"
            )
        if (
            decision.event_id != request["event_id"]
            or decision.incident_id != request["incident_id"]
        ):
            return self._rejected(
                decision,
                EnforcementReasonCode.REQUEST_MISMATCH,
                "Decision correlation IDs do not match the request",
            )
        if incident["state"] != IncidentState.WAITING_FOR_CONTEXT.value:
            return self._rejected(
                decision,
                EnforcementReasonCode.INVALID_INCIDENT_STATE,
                "Incident is not waiting for context",
            )
        if decision.incident_version != incident["version"]:
            return self._rejected(
                decision,
                EnforcementReasonCode.STALE_INCIDENT_VERSION,
                "Incident version is stale",
            )
        now = utc_now()
        if parse_timestamp(request["expires_at"]) <= now:
            return self._rejected(
                decision, EnforcementReasonCode.REQUEST_EXPIRED, "Context request expired"
            )
        request_created_at = parse_timestamp(request["created_at"])
        clock_skew = timedelta(seconds=self.settings.decision_clock_skew_seconds)
        if decision.issued_at < request_created_at - clock_skew:
            return self._rejected(
                decision,
                EnforcementReasonCode.REQUEST_EXPIRED,
                "Decision predates the context request",
            )
        if decision.issued_at > now + clock_skew:
            return self._rejected(
                decision, EnforcementReasonCode.REQUEST_EXPIRED, "Decision time is in the future"
            )
        if decision.issued_at > parse_timestamp(request["expires_at"]) + clock_skew:
            return self._rejected(
                decision,
                EnforcementReasonCode.REQUEST_EXPIRED,
                "Decision was issued after the context request expired",
            )

        payload = request["payload_json"]
        action = decision.effective_decision
        allowed = set(payload["allowed_responses"])
        if action.value not in allowed:
            return self._rejected(
                decision,
                EnforcementReasonCode.POLICY_DISALLOWS_EXCEPTION,
                "The requested action is not allowed for this incident",
            )

        temporary = action in {
            DecisionAction.ALLOW_TEMPORARY,
            DecisionAction.BLOCK_TEMPORARY,
        }
        if temporary:
            evidence = incident.get("evidence_json") or {}
            authorization = self.policies.revalidate_temporary_action(
                evidence,
                action,
                configured_maximum_ttl=self.settings.max_ttl_seconds,
            )
            if not authorization.authorized:
                return self._rejected(
                    decision,
                    EnforcementReasonCode.POLICY_DISALLOWS_EXCEPTION,
                    f"Current local policy rejected the temporary action: "
                    f"{authorization.reason_code}",
                )
            approver = verified_approver or decision.approved_by
            if (
                self.settings.chat_integration_token
                or self.settings.integration_api_token
            ) and verified_approver is None:
                approver = None
            if approver is None or approver.role not in self.settings.allowed_approver_roles:
                return self._rejected(
                    decision,
                    EnforcementReasonCode.APPROVER_NOT_ALLOWED,
                    "Approver role is not permitted",
                )
            expected_scope_data = payload.get("permitted_grant_scope")
            if expected_scope_data is None or decision.grant_scope is None:
                return self._rejected(
                    decision,
                    EnforcementReasonCode.SCOPE_MISMATCH,
                    "No exact service scope is available",
                )
            expected_scope = FlowScope.model_validate(expected_scope_data)
            if decision.grant_scope != expected_scope:
                return self._rejected(
                    decision,
                    EnforcementReasonCode.SCOPE_MISMATCH,
                    "Grant scope differs from the observed service flow",
                )
            ttl = decision.ttl_seconds or 0
            maximum = min(
                payload["maximum_ttl_seconds"],
                self.settings.max_ttl_seconds,
                authorization.maximum_ttl_seconds or self.settings.max_ttl_seconds,
            )
            if ttl <= 0:
                return self._rejected(
                    decision, EnforcementReasonCode.TTL_INVALID, "TTL must be positive"
                )
            if ttl > maximum:
                return self._rejected(
                    decision,
                    EnforcementReasonCode.TTL_EXCEEDS_POLICY,
                    "TTL exceeds the configured policy maximum",
                )
        return incident, request, action

    async def handle(
        self,
        decision: ChatDecision,
        *,
        verified_approver: ApproverIdentity | None = None,
    ) -> EnforcementResult:
        decision_data = decision.model_dump(mode="json")
        if verified_approver is not None:
            decision_data["verified_approver"] = verified_approver.model_dump(mode="json")
        validated = self._validate(decision, verified_approver)
        if isinstance(validated, EnforcementResult):
            try:
                self.database.record_unclaimed_decision(
                    decision.decision_id,
                    decision.request_id,
                    decision.incident_id,
                    decision_data,
                    "REJECTED",
                    validated.reason_code.value,
                )
            except DecisionConflict:
                return self._rejected(
                    decision,
                    EnforcementReasonCode.REPLAYED_DECISION,
                    "Decision ID has already been used",
                )
            self.database.audit(
                "decision_service",
                "DECISION_REJECTED",
                incident_id=decision.incident_id,
                event_id=decision.event_id,
                details={
                    "decision_id": decision.decision_id,
                    "reason": validated.reason_code.value,
                },
            )
            return validated

        incident, request, action = validated
        if action is DecisionAction.REQUEST_MORE_INFORMATION:
            try:
                self.database.record_unclaimed_decision(
                    decision.decision_id,
                    decision.request_id,
                    decision.incident_id,
                    decision_data,
                    "MORE_INFORMATION_REQUIRED",
                    EnforcementReasonCode.MORE_INFORMATION_REQUIRED.value,
                )
            except DecisionConflict:
                return self._rejected(
                    decision,
                    EnforcementReasonCode.REPLAYED_DECISION,
                    "Decision ID has already been used",
                )
            return self._rejected(
                decision,
                EnforcementReasonCode.MORE_INFORMATION_REQUIRED,
                "The incident remains open for more information",
            )

        try:
            self.database.claim_context_request(
                decision.decision_id,
                decision.request_id,
                decision.incident_version,
                decision_data,
            )
        except DecisionConflict as exc:
            reason = {
                "REPLAYED_DECISION": EnforcementReasonCode.REPLAYED_DECISION,
                "STALE_INCIDENT_VERSION": EnforcementReasonCode.STALE_INCIDENT_VERSION,
                "REQUEST_EXPIRED": EnforcementReasonCode.REQUEST_EXPIRED,
            }.get(exc.reason_code, EnforcementReasonCode.INVALID_INCIDENT_STATE)
            return self._rejected(decision, reason, str(exc))

        if action is DecisionAction.KEEP_CURRENT_POLICY:
            state = (
                IncidentState.DENIED
                if decision.decision is DecisionAction.DENY
                else IncidentState.KEPT_BLOCKED
            )
            reason = (
                EnforcementReasonCode.DECISION_DENIED
                if decision.decision is DecisionAction.DENY
                else EnforcementReasonCode.CURRENT_POLICY_RETAINED
            )
            result = EnforcementResult(
                schema_version="enforcement-result-v1",
                decision_id=decision.decision_id,
                event_id=decision.event_id,
                incident_id=decision.incident_id,
                status=EnforcementStatus.REJECTED,
                reason_code=reason,
                detail="Existing network policy was retained; no rule was changed",
            )
            self.database.transition_incident(
                incident["incident_id"],
                {IncidentState.WAITING_FOR_CONTEXT.value},
                state.value,
                decision_id=decision.decision_id,
                decision_json=decision_data,
                enforcement_json=result.model_dump(mode="json"),
            )
            self.database.update_decision_status(decision.decision_id, "NO_CHANGE", reason.value)
            self.database.audit(
                "decision_service",
                "CURRENT_POLICY_RETAINED",
                incident_id=decision.incident_id,
                event_id=decision.event_id,
                details={"decision_id": decision.decision_id, "reason": reason.value},
            )
            return result

        self.database.transition_incident(
            incident["incident_id"],
            {IncidentState.WAITING_FOR_CONTEXT.value},
            IncidentState.APPROVED.value,
            decision_id=decision.decision_id,
            decision_json=decision_data,
        )
        self.database.transition_incident(
            incident["incident_id"],
            {IncidentState.APPROVED.value},
            IncidentState.ENFORCING.value,
        )
        expires_at = (utc_now() + timedelta(seconds=decision.ttl_seconds or 0)).replace(
            microsecond=0
        )
        rule_action = (
            RuleAction.ALLOW
            if action is DecisionAction.ALLOW_TEMPORARY
            else RuleAction.BLOCK
        )
        grant = ValidatedFlowGrant(
            scope=decision.grant_scope,
            action=rule_action,
            expires_at=expires_at,
        )
        receipt: FirewallReceipt | None = None
        reserved_rule: dict[str, Any] | None = None
        try:
            topology_verifier = getattr(
                self.firewall, "verify_parent_chain_topology", None
            )
            if topology_verifier is not None:
                await topology_verifier()
            reserved_rule = self.database.reserve_managed_rule(
                rule_id=grant.rule_id,
                incident_id=decision.incident_id,
                decision_id=decision.decision_id,
                action=rule_action.value,
                expires_at=isoformat_z(expires_at),
                scope=decision.grant_scope.model_dump(mode="json"),
            )
            receipt = await self.firewall.install_exact_grant(grant)
            receipt_data = _receipt_to_dict(receipt)
            reason = (
                EnforcementReasonCode.EXACT_SCOPE_TEMPORARY_GRANT
                if rule_action is RuleAction.ALLOW
                else EnforcementReasonCode.EXACT_SCOPE_TEMPORARY_BLOCK
            )
            result = EnforcementResult(
                schema_version="enforcement-result-v1",
                decision_id=decision.decision_id,
                event_id=decision.event_id,
                incident_id=decision.incident_id,
                status=EnforcementStatus.APPLIED,
                reason_code=reason,
                firewall_rule_id=receipt.rule_id,
                expires_at=expires_at,
                detail="A temporary exact-service rule was applied",
            )
            self.database.activate_managed_rule(receipt.rule_id, receipt_data)
            self.database.transition_incident(
                incident["incident_id"],
                {IncidentState.ENFORCING.value},
                IncidentState.ENFORCED.value,
                firewall_rule_id=receipt.rule_id,
                expires_at=isoformat_z(expires_at),
                enforcement_json=result.model_dump(mode="json"),
            )
            self.database.update_decision_status(decision.decision_id, "APPLIED", reason.value)
            self.database.audit(
                "firewall_executor",
                "TEMPORARY_RULE_APPLIED",
                incident_id=decision.incident_id,
                event_id=decision.event_id,
                details={
                    "decision_id": decision.decision_id,
                    "rule_id": receipt.rule_id,
                    "action": rule_action.value,
                    "expires_at": isoformat_z(expires_at),
                },
            )
            return result
        except Exception:
            cleanup_receipt = receipt
            if cleanup_receipt is None and reserved_rule is not None:
                try:
                    cleanup_receipt = _receipt_from_rule(reserved_rule)
                except Exception:
                    cleanup_receipt = None
            cleanup_succeeded = False
            if cleanup_receipt is not None:
                try:
                    await self.firewall.revoke(cleanup_receipt)
                    cleanup_succeeded = True
                except Exception:
                    cleanup_succeeded = False
            if reserved_rule is not None:
                try:
                    if cleanup_succeeded:
                        self.database.mark_rule_revoked(reserved_rule["rule_id"])
                    else:
                        self.database.mark_rule_cleanup_required(
                            reserved_rule["rule_id"],
                            "COMPENSATING_REVOCATION_REQUIRED",
                            receipt=(
                                _receipt_to_dict(cleanup_receipt)
                                if cleanup_receipt is not None
                                else None
                            ),
                        )
                except Exception:
                    pass
            result = EnforcementResult(
                schema_version="enforcement-result-v1",
                decision_id=decision.decision_id,
                event_id=decision.event_id,
                incident_id=decision.incident_id,
                status=EnforcementStatus.FAILED,
                reason_code=EnforcementReasonCode.FIREWALL_ERROR,
                detail="The restricted firewall adapter failed; existing policy remains in effect",
            )
            try:
                current = self.database.get_incident(incident["incident_id"])
                if current and current["state"] in {
                    IncidentState.ENFORCING.value,
                    IncidentState.ENFORCED.value,
                }:
                    self.database.transition_incident(
                        incident["incident_id"],
                        {
                            IncidentState.ENFORCING.value,
                            IncidentState.ENFORCED.value,
                        },
                        IncidentState.ENFORCEMENT_FAILED.value,
                        enforcement_json=result.model_dump(mode="json"),
                        last_error_code="FIREWALL_ERROR",
                        last_error_detail="Restricted firewall enforcement failed",
                    )
                self.database.update_decision_status(
                    decision.decision_id,
                    "FAILED",
                    EnforcementReasonCode.FIREWALL_ERROR.value,
                )
                self.database.audit(
                    "firewall_executor",
                    "TEMPORARY_RULE_FAILED",
                    incident_id=decision.incident_id,
                    event_id=decision.event_id,
                    details={
                        "decision_id": decision.decision_id,
                        "error_code": "FIREWALL_ERROR",
                        "cleanup_succeeded": cleanup_succeeded,
                    },
                )
            except Exception:
                pass
            return result


@dataclass(slots=True)
class ExpiryService:
    settings: Settings
    database: Database
    firewall: FirewallAdapter
    policies: PolicyLoader
    _lock: asyncio.Lock = field(init=False, repr=False)
    last_success_at: datetime | None = field(init=False, default=None)
    last_error_at: datetime | None = field(init=False, default=None)
    last_error_code: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        self._lock = asyncio.Lock()

    @property
    def healthy(self) -> bool:
        if self.last_success_at is None:
            return False
        if self.last_error_at and self.last_error_at >= self.last_success_at:
            return False
        maximum_age = max(5.0, self.settings.expiry_poll_seconds * 4)
        return (utc_now() - self.last_success_at).total_seconds() <= maximum_age

    def _failed(self, code: str) -> None:
        self.last_error_code = code
        self.last_error_at = utc_now()

    def _succeeded(self) -> None:
        self.last_success_at = utc_now()
        self.last_error_code = None

    def _safe_audit(
        self,
        action: str,
        *,
        incident_id: str | None = None,
        event_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        try:
            self.database.audit(
                "expiry_service",
                action,
                incident_id=incident_id,
                event_id=event_id,
                details=details or {},
            )
        except Exception:
            self._failed("EXPIRY_AUDIT_FAILED")

    async def _revoke_observations(
        self, observations: list[FirewallReceipt], fallback: FirewallReceipt
    ) -> None:
        targets = observations or [fallback]
        for receipt in targets:
            await self.firewall.revoke(receipt)

    async def restore_active_rules(self) -> None:
        """Reconcile DB intent against every physical adapter-owned observation."""

        async with self._lock:
            try:
                groups = group_managed_grants(await self.firewall.list_managed_grants())
            except FirewallReconciliationError:
                self._failed("MALFORMED_MANAGED_FIREWALL_RULE")
                raise

            active_rows = self.database.list_desired_rules()
            cleanup_rows = self.database.list_rules_requiring_cleanup()
            pending_rows = self.database.list_pending_rules()
            all_rows = {
                row["rule_id"]: row
                for row in [*active_rows, *cleanup_rows, *pending_rows]
            }
            failures = 0

            # Any valid adapter-owned rule absent from persistent intent is an orphan.
            for rule_id, observations in groups.items():
                if rule_id in all_rows:
                    continue
                try:
                    for observation in observations:
                        await self.firewall.revoke(observation)
                    self._safe_audit(
                        "ORPHAN_MANAGED_RULE_REVOKED",
                        details={"rule_id": rule_id, "observations": len(observations)},
                    )
                except Exception:
                    failures += 1
                    self._safe_audit(
                        "ORPHAN_MANAGED_RULE_REVOCATION_FAILED",
                        details={"rule_id": rule_id},
                    )

            for row in all_rows.values():
                rule_id = row["rule_id"]
                observations = groups.get(rule_id, [])
                try:
                    expected = _receipt_from_rule(row)
                    incident = self.database.get_incident(row["incident_id"])
                    temporary_action = (
                        DecisionAction.ALLOW_TEMPORARY
                        if row["action"] == RuleAction.ALLOW.value
                        else DecisionAction.BLOCK_TEMPORARY
                    )
                    authorization = self.policies.revalidate_temporary_action(
                        (incident or {}).get("evidence_json") or {},
                        temporary_action,
                        configured_maximum_ttl=self.settings.max_ttl_seconds,
                    )
                    desired = (
                        row["status"] == "ACTIVE"
                        and incident is not None
                        and incident["state"] == IncidentState.ENFORCED.value
                        and parse_timestamp(row["expires_at"]) > utc_now()
                        and authorization.authorized
                    )
                    if not desired:
                        await self._revoke_observations(observations, expected)
                        self.database.mark_rule_revoked(rule_id)
                        if (
                            row["status"] == "ACTIVE"
                            and incident is not None
                            and incident["state"] == IncidentState.ENFORCED.value
                        ):
                            revoked_result = EnforcementResult(
                                schema_version="enforcement-result-v1",
                                decision_id=row["decision_id"],
                                event_id=incident["primary_event_id"],
                                incident_id=row["incident_id"],
                                status=EnforcementStatus.REVOKED,
                                reason_code=EnforcementReasonCode.RULE_REVOKED,
                                firewall_rule_id=rule_id,
                                expires_at=parse_timestamp(row["expires_at"]),
                                detail="The temporary rule was not eligible for restoration",
                            )
                            self.database.transition_incident(
                                row["incident_id"],
                                {IncidentState.ENFORCED.value},
                                IncidentState.REVOKED.value,
                                enforcement_json=revoked_result.model_dump(mode="json"),
                            )
                        self._safe_audit(
                            "UNDESIRED_MANAGED_RULE_REVOKED",
                            incident_id=row["incident_id"],
                            event_id=(incident["primary_event_id"] if incident else None),
                            details={"rule_id": rule_id, "previous_status": row["status"]},
                        )
                        continue

                    exact_match = (
                        len(observations) == 1
                        and expected.semantically_matches(observations[0])
                    )
                    if exact_match:
                        continue
                    if observations:
                        await self._revoke_observations(observations, expected)
                    scope = FlowScope.model_validate(row["scope_json"])
                    grant = ValidatedFlowGrant(
                        scope=scope,
                        action=RuleAction(row["action"]),
                        expires_at=parse_timestamp(row["expires_at"]),
                        rule_id=rule_id,
                    )
                    restored = await self.firewall.install_exact_grant(grant)
                    expected.require_semantic_match(restored)
                    self._safe_audit(
                        "MANAGED_RULE_RESTORED",
                        incident_id=row["incident_id"],
                        event_id=incident["primary_event_id"],
                        details={"rule_id": rule_id},
                    )
                except Exception:
                    failures += 1
                    try:
                        self.database.mark_rule_cleanup_required(
                            rule_id,
                            "STARTUP_RECONCILIATION_FAILED",
                            receipt=(
                                _receipt_to_dict(observations[0])
                                if observations
                                else None
                            ),
                        )
                    except Exception:
                        pass
                    self._safe_audit(
                        "STARTUP_RECONCILIATION_FAILED",
                        incident_id=row["incident_id"],
                        details={"rule_id": rule_id},
                    )

            if failures:
                self._failed("STARTUP_RECONCILIATION_FAILED")
                raise FirewallError("One or more managed firewall rules could not be reconciled")
            self._succeeded()

    async def expire_once(self) -> int:
        async with self._lock:
            failures = 0
            try:
                expired_incidents = self.database.expire_context_requests()
            except Exception:
                expired_incidents = []
                failures += 1
            for incident_id in expired_incidents:
                incident = self.database.get_incident(incident_id)
                self._safe_audit(
                    "CONTEXT_REQUEST_EXPIRED",
                    incident_id=incident_id,
                    event_id=incident["primary_event_id"] if incident else None,
                )

            listing_safe = True
            try:
                groups = group_managed_grants(await self.firewall.list_managed_grants())
            except Exception:
                groups = {}
                listing_safe = False
                failures += 1
                self._failed("FIREWALL_LIST_FAILED")

            rows_by_id = {
                row["rule_id"]: row
                for row in [
                    *self.database.list_expired_rules(),
                    *self.database.list_rules_requiring_cleanup(),
                    *self.database.list_pending_rules(),
                ]
            }
            count = 0
            for row in rows_by_id.values():
                incident: dict[str, Any] | None = None
                try:
                    receipt = _receipt_from_rule(row)
                    observations = groups.get(row["rule_id"], [])
                    await self._revoke_observations(observations, receipt)
                    if not listing_safe:
                        raise FirewallReconciliationError(
                            "Cannot prove all managed observations were removed"
                        )
                    self.database.mark_rule_revoked(row["rule_id"])
                    incident = self.database.get_incident(row["incident_id"])
                    if incident and incident["state"] == IncidentState.ENFORCED.value:
                        result = EnforcementResult(
                            schema_version="enforcement-result-v1",
                            decision_id=row["decision_id"],
                            event_id=incident["primary_event_id"],
                            incident_id=row["incident_id"],
                            status=EnforcementStatus.REVOKED,
                            reason_code=EnforcementReasonCode.RULE_REVOKED,
                            firewall_rule_id=row["rule_id"],
                            expires_at=parse_timestamp(row["expires_at"]),
                            detail="The temporary rule expired and was revoked",
                        )
                        self.database.transition_incident(
                            row["incident_id"],
                            {IncidentState.ENFORCED.value},
                            IncidentState.REVOKED.value,
                            enforcement_json=result.model_dump(mode="json"),
                        )
                    self._safe_audit(
                        "TEMPORARY_RULE_REVOKED",
                        incident_id=row["incident_id"],
                        event_id=(incident["primary_event_id"] if incident else None),
                        details={"rule_id": row["rule_id"]},
                    )
                    count += 1
                except Exception:
                    failures += 1
                    try:
                        self.database.mark_rule_cleanup_required(
                            row["rule_id"], "REVOCATION_FAILED"
                        )
                    except Exception:
                        pass
                    self._safe_audit(
                        "TEMPORARY_RULE_REVOCATION_FAILED",
                        incident_id=row["incident_id"],
                        event_id=(incident["primary_event_id"] if incident else None),
                        details={"rule_id": row["rule_id"]},
                    )

            if failures:
                self._failed("EXPIRY_CYCLE_DEGRADED")
            else:
                self._succeeded()
            return count

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self.expire_once()
            except Exception:
                self._failed("EXPIRY_WORKER_EXCEPTION")
                self._safe_audit(
                    "EXPIRY_WORKER_EXCEPTION",
                    details={"will_retry": True},
                )
            try:
                await asyncio.wait_for(
                    stop_event.wait(), timeout=self.settings.expiry_poll_seconds
                )
            except TimeoutError:
                pass
