from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

TEMPORARY_ACTION_EXCEPTIONS = {
    "ALLOW_TEMPORARY": "temporary_exact_service_flow",
    "BLOCK_TEMPORARY": "temporary_exact_service_block",
}
SAFE_CONTEXT_ACTIONS = ("KEEP_CURRENT_POLICY", "REQUEST_MORE_INFORMATION")
POLICY_HASH_ALGORITHM = "sha256"


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TemporaryActionAuthorization:
    """Decision-time result for one temporary network action.

    ``reason_code`` is stable and safe to persist. ``maximum_ttl_seconds`` comes
    from the currently loaded local policy, never from model or chat text.
    """

    authorized: bool
    reason_code: str
    action: str
    rule_id: str | None
    policy_version: str
    maximum_ttl_seconds: int | None = None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _enum_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


class PolicyLoader:
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.firewall_policies = self._load_json("firewall_policies.json")
        self.known_hosts = self._load_json("known_hosts.json")
        self.blocked_sources = self._load_json("blocked_sources.json")
        self.agent_policy = self._load_yaml("agent_policy.yaml")
        self._validate_authorization_config()
        self.policy_hash = self._calculate_policy_hash()
        schema_version = str(self.agent_policy.get("schema_version") or "agent-policy-v1")
        self.policy_version = f"{schema_version}:{self.policy_hash[:16]}"

    def _load_json(self, name: str) -> dict[str, Any]:
        path = self.config_dir / name
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyError(f"Could not load {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise PolicyError(f"Expected an object in {path}")
        return value

    def _load_yaml(self, name: str) -> dict[str, Any]:
        path = self.config_dir / name
        try:
            with path.open("r", encoding="utf-8") as handle:
                value = yaml.safe_load(handle)
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"Could not load {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise PolicyError(f"Expected a mapping in {path}")
        return value

    def _validate_authorization_config(self) -> None:
        default = self.firewall_policies.get("DEFAULT")
        if not isinstance(default, Mapping):
            raise PolicyError("firewall_policies.json requires a DEFAULT policy")

        permitted_exceptions = set(TEMPORARY_ACTION_EXCEPTIONS.values()) | {None}
        for configured_id, raw_policy in self.firewall_policies.items():
            if not isinstance(raw_policy, Mapping):
                raise PolicyError(f"Policy {configured_id!r} must be an object")
            if raw_policy.get("rule_id") != configured_id:
                raise PolicyError(f"Policy {configured_id!r} has a mismatched rule_id")
            allowed_exception = raw_policy.get("allowed_exception")
            if allowed_exception not in permitted_exceptions:
                raise PolicyError(
                    f"Policy {configured_id!r} has unsupported allowed_exception"
                )
            if configured_id == "DEFAULT" and allowed_exception is not None:
                raise PolicyError("DEFAULT must not authorize a temporary exception")
            maximum_ttl = _positive_int(raw_policy.get("maximum_ttl_seconds"))
            if maximum_ttl is None:
                raise PolicyError(f"Policy {configured_id!r} requires a positive maximum TTL")

        action_mapping = self.agent_policy.get("allowed_temporary_actions")
        if not isinstance(action_mapping, Mapping):
            raise PolicyError("agent_policy.yaml requires allowed_temporary_actions")
        supported_actions = set(TEMPORARY_ACTION_EXCEPTIONS) | set(SAFE_CONTEXT_ACTIONS)
        for event_type, actions in action_mapping.items():
            if not isinstance(event_type, str) or not isinstance(actions, list):
                raise PolicyError("allowed_temporary_actions entries must be action lists")
            normalized = [_enum_value(action).strip().upper() for action in actions]
            if len(normalized) != len(set(normalized)):
                raise PolicyError(f"Event type {event_type!r} contains duplicate actions")
            unsupported = set(normalized) - supported_actions
            if unsupported:
                raise PolicyError(f"Event type {event_type!r} contains unsupported actions")

    def _calculate_policy_hash(self) -> str:
        authorization_config = {
            "agent_policy": self.agent_policy,
            "firewall_policies": self.firewall_policies,
        }
        encoded = json.dumps(
            authorization_config,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def policy_snapshot(self) -> dict[str, str]:
        """Return stable, non-secret policy identity for evidence and audit records."""

        return {
            "version": self.policy_version,
            "hash": self.policy_hash,
            "hash_algorithm": POLICY_HASH_ALGORITHM,
        }

    def _event_rule_id(self, evidence: Mapping[str, Any]) -> str | None:
        event = _mapping(evidence.get("normalized_event"))
        policy_metadata = _mapping(event.get("policy_metadata"))
        value = policy_metadata.get("rule_id") or event.get("rule_id")
        if value is None:
            return None
        rendered = _enum_value(value).strip()
        return rendered or None

    def _known_local_policy(
        self, evidence: Mapping[str, Any]
    ) -> tuple[str, Mapping[str, Any]] | None:
        rule_id = self._event_rule_id(evidence)
        if rule_id is None or rule_id == "DEFAULT":
            return None
        local_policy = self.firewall_policies.get(rule_id)
        if not isinstance(local_policy, Mapping):
            return None

        matched_policy = _mapping(evidence.get("matched_policy"))
        snapshot = _mapping(evidence.get("policy_snapshot"))
        if matched_policy.get("rule_id") != rule_id:
            return None
        if snapshot.get("matched_rule_id") != rule_id:
            return None
        if snapshot.get("known_local_policy") is not True:
            return None
        if snapshot.get("version") != self.policy_version:
            return None
        if snapshot.get("hash") != self.policy_hash:
            return None
        if snapshot.get("hash_algorithm") != POLICY_HASH_ALGORITHM:
            return None
        return rule_id, local_policy

    def _event_eligibility_reason(self, evidence: Mapping[str, Any]) -> str | None:
        event = _mapping(evidence.get("normalized_event"))
        if event.get("schema_version") != "network-event-v1":
            return "EVENT_SCHEMA_NOT_ENFORCEABLE"
        flow = _mapping(event.get("flow"))
        if _enum_value(flow.get("direction")).lower() != "forward":
            return "EVENT_DIRECTION_NOT_FORWARD"
        if _enum_value(flow.get("protocol")).lower() not in {"tcp", "udp"}:
            return "EVENT_PROTOCOL_NOT_ENFORCEABLE"

        source_ip = flow.get("source_ip")
        destination_ip = flow.get("destination_ip")
        try:
            source = ipaddress.ip_address(str(source_ip))
            destination = ipaddress.ip_address(str(destination_ip))
        except ValueError:
            return "EVENT_FLOW_INCOMPLETE"
        if source.version != 4 or destination.version != 4:
            return "EVENT_IP_VERSION_NOT_ENFORCEABLE"

        destination_port = flow.get("destination_port")
        if (
            isinstance(destination_port, bool)
            or not isinstance(destination_port, int)
            or not 1 <= destination_port <= 65_535
        ):
            return "EVENT_FLOW_INCOMPLETE"
        return None

    def revalidate_temporary_action(
        self,
        evidence: Mapping[str, Any],
        action: Any,
        *,
        configured_maximum_ttl: int | None = None,
    ) -> TemporaryActionAuthorization:
        """Revalidate a temporary action against current local policy and evidence.

        This method is intended to be called both when constructing allowed chat
        responses and again immediately before deterministic enforcement.
        """

        action_value = _enum_value(action).strip().upper()
        required_exception = TEMPORARY_ACTION_EXCEPTIONS.get(action_value)
        rule_id = self._event_rule_id(evidence)
        if required_exception is None:
            return TemporaryActionAuthorization(
                False,
                "ACTION_NOT_TEMPORARY",
                action_value,
                rule_id,
                self.policy_version,
            )

        snapshot = _mapping(evidence.get("policy_snapshot"))
        if (
            snapshot.get("version") != self.policy_version
            or snapshot.get("hash") != self.policy_hash
            or snapshot.get("hash_algorithm") != POLICY_HASH_ALGORITHM
        ):
            return TemporaryActionAuthorization(
                False,
                "POLICY_SNAPSHOT_MISMATCH",
                action_value,
                rule_id,
                self.policy_version,
            )

        known_policy = self._known_local_policy(evidence)
        if known_policy is None:
            return TemporaryActionAuthorization(
                False,
                "UNKNOWN_OR_DEFAULT_POLICY",
                action_value,
                rule_id,
                self.policy_version,
            )
        rule_id, local_policy = known_policy

        event = _mapping(evidence.get("normalized_event"))
        event_type = _enum_value(event.get("event_type"))
        action_mapping = _mapping(self.agent_policy.get("allowed_temporary_actions"))
        configured_actions = action_mapping.get(event_type, SAFE_CONTEXT_ACTIONS)
        normalized_actions = {
            _enum_value(configured_action).strip().upper()
            for configured_action in configured_actions
        }
        if action_value not in normalized_actions:
            return TemporaryActionAuthorization(
                False,
                "ACTION_NOT_ALLOWED_FOR_EVENT_TYPE",
                action_value,
                rule_id,
                self.policy_version,
            )

        if local_policy.get("allowed_exception") != required_exception:
            return TemporaryActionAuthorization(
                False,
                "TEMPORARY_ACTION_NOT_ALLOWED",
                action_value,
                rule_id,
                self.policy_version,
            )

        eligibility_failure = self._event_eligibility_reason(evidence)
        if eligibility_failure is not None:
            return TemporaryActionAuthorization(
                False,
                eligibility_failure,
                action_value,
                rule_id,
                self.policy_version,
            )

        policy_ttl = _positive_int(local_policy.get("maximum_ttl_seconds"))
        if policy_ttl is None:  # Configuration validation makes this defensive only.
            return TemporaryActionAuthorization(
                False,
                "POLICY_TTL_INVALID",
                action_value,
                rule_id,
                self.policy_version,
            )
        if configured_maximum_ttl is not None:
            configured_ttl = _positive_int(configured_maximum_ttl)
            if configured_ttl is None:
                return TemporaryActionAuthorization(
                    False,
                    "CONFIGURED_TTL_INVALID",
                    action_value,
                    rule_id,
                    self.policy_version,
                )
            policy_ttl = min(policy_ttl, configured_ttl)

        return TemporaryActionAuthorization(
            True,
            "AUTHORIZED_BY_LOCAL_POLICY",
            action_value,
            rule_id,
            self.policy_version,
            maximum_ttl_seconds=policy_ttl,
        )

    def is_temporary_action_authorized(
        self,
        evidence: Mapping[str, Any],
        action: Any,
    ) -> bool:
        return self.revalidate_temporary_action(evidence, action).authorized

    def build_evidence(self, event: Any) -> dict[str, Any]:
        event_data = (
            event.model_dump(mode="json", by_alias=False)
            if hasattr(event, "model_dump")
            else dict(event)
        )
        flow = event_data.get("flow") or {}
        policy_metadata = event_data.get("policy_metadata") or {}
        rule_id = policy_metadata.get("rule_id") or event_data.get("rule_id") or "DEFAULT"
        known_local_policy = rule_id != "DEFAULT" and rule_id in self.firewall_policies
        if known_local_policy:
            matched_policy = dict(self.firewall_policies[rule_id])
        else:
            matched_policy = dict(self.firewall_policies["DEFAULT"])
            matched_policy["rule_id"] = rule_id
            matched_policy["allowed_exception"] = None
        source_ip = flow.get("source_ip")
        destination_ip = flow.get("destination_ip")
        source_host = self.known_hosts.get(str(source_ip)) if source_ip else None
        destination_host = self.known_hosts.get(str(destination_ip)) if destination_ip else None
        blocked_source = self.blocked_sources.get(str(source_ip)) if source_ip else None

        unknowns: list[str] = []
        if not source_host:
            unknowns.append("source host identity and owner")
        if not destination_host:
            unknowns.append("destination host identity and owner")
        if not event_data.get("rule_id") and not event_data.get("reason"):
            unknowns.append("the policy or detector reason for this event")
        if not known_local_policy:
            unknowns.append("a known local policy authorizing any temporary action")
        unknowns.extend(
            [
                "whether this activity is expected by the organization",
                "whether a human has authorized a temporary network change",
            ]
        )

        policy_snapshot: dict[str, Any] = self.policy_snapshot()
        policy_snapshot.update(
            {
                "matched_rule_id": rule_id,
                "known_local_policy": known_local_policy,
            }
        )
        return {
            "evidence_schema_version": "network-evidence-v1",
            "normalized_event": event_data,
            # A flattened read-only view helps the deterministic mock reasoner while
            # retaining the canonical nested event as the source of truth.
            "event": {**event_data, **flow, "rule_id": rule_id},
            "matched_policy": matched_policy,
            "policy_snapshot": policy_snapshot,
            "source_host_context": source_host,
            "destination_host_context": destination_host,
            "blocked_source_context": blocked_source,
            "explicit_unknowns": list(dict.fromkeys(unknowns)),
            "safety_boundary": {
                "llm_can_change_firewall": False,
                "all_changes_require_structured_external_decision": True,
                "all_changes_are_exact_scope_and_temporary": True,
                "temporary_actions_require_known_local_policy": True,
            },
        }

    def allowed_decisions(
        self,
        event_type: Any,
        has_complete_scope: bool,
        *,
        evidence: Mapping[str, Any] | None = None,
    ) -> list[str]:
        """Return chat choices, filtering every temporary action fail closed.

        Callers must provide the same immutable evidence stored for the incident.
        Omitting it intentionally removes all temporary actions.
        """

        mapping = self.agent_policy.get("allowed_temporary_actions", {})
        event_type_value = _enum_value(event_type)
        configured = mapping.get(event_type_value, SAFE_CONTEXT_ACTIONS)
        actions = list(configured) if isinstance(configured, list) else list(SAFE_CONTEXT_ACTIONS)
        permitted: list[str] = []
        for action in actions:
            action_value = _enum_value(action).strip().upper()
            if action_value not in TEMPORARY_ACTION_EXCEPTIONS:
                permitted.append(action_value)
                continue
            if not has_complete_scope or evidence is None:
                continue
            if self.revalidate_temporary_action(evidence, action_value).authorized:
                permitted.append(action_value)
        return permitted

    def maximum_ttl(self, evidence: Mapping[str, Any], configured_maximum: int) -> int:
        """Return a local-policy TTL without trusting the evidence payload's value."""

        configured_value = _positive_int(configured_maximum)
        if configured_value is None:
            raise PolicyError("configured maximum TTL must be positive")

        known_policy = self._known_local_policy(evidence)
        policy_value: int | None = None
        if known_policy is not None:
            policy_value = _positive_int(known_policy[1].get("maximum_ttl_seconds"))
        if policy_value is None:
            policy_value = _positive_int(
                self.agent_policy.get("default_maximum_ttl_seconds")
            )
        return min(policy_value or configured_value, configured_value)


__all__ = [
    "POLICY_HASH_ALGORITHM",
    "PolicyError",
    "PolicyLoader",
    "SAFE_CONTEXT_ACTIONS",
    "TEMPORARY_ACTION_EXCEPTIONS",
    "TemporaryActionAuthorization",
]
