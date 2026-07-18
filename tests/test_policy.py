from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from app.policy import PolicyLoader

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _event(
    *,
    rule_id: str = "BLOCK_VPN_SOURCE",
    event_type: str = "FIREWALL_DROP",
    direction: str = "forward",
    source_ip: str = "10.0.2.1",
    destination_ip: str = "10.0.3.10",
) -> dict:
    return {
        "schema_version": "network-event-v1",
        "event_id": "policy-test-event",
        "event_type": event_type,
        "flow": {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": 51842,
            "destination_port": 443,
            "protocol": "tcp",
            "direction": direction,
        },
        "reason": "Test event",
        "policy_metadata": {"rule_id": rule_id},
    }


def test_known_policy_authorizes_only_its_declared_exception() -> None:
    policies = PolicyLoader(PROJECT_ROOT / "config")
    evidence = policies.build_evidence(_event())

    allow = policies.revalidate_temporary_action(
        evidence, "ALLOW_TEMPORARY", configured_maximum_ttl=300
    )
    block = policies.revalidate_temporary_action(evidence, "BLOCK_TEMPORARY")

    assert allow.authorized is True
    assert allow.reason_code == "AUTHORIZED_BY_LOCAL_POLICY"
    assert allow.rule_id == "BLOCK_VPN_SOURCE"
    assert allow.maximum_ttl_seconds == 300
    assert block.authorized is False
    assert block.reason_code == "ACTION_NOT_ALLOWED_FOR_EVENT_TYPE"
    assert policies.allowed_decisions(
        "FIREWALL_DROP", True, evidence=evidence
    ) == ["ALLOW_TEMPORARY", "KEEP_CURRENT_POLICY", "REQUEST_MORE_INFORMATION"]


def test_missing_evidence_and_unknown_or_default_rules_fail_closed() -> None:
    policies = PolicyLoader(PROJECT_ROOT / "config")

    assert policies.allowed_decisions("FIREWALL_DROP", True) == [
        "KEEP_CURRENT_POLICY",
        "REQUEST_MORE_INFORMATION",
    ]
    for rule_id in ("UNRECOGNIZED_RULE", "DEFAULT"):
        evidence = policies.build_evidence(_event(rule_id=rule_id))
        authorization = policies.revalidate_temporary_action(
            evidence, "ALLOW_TEMPORARY"
        )
        assert authorization.authorized is False
        assert authorization.reason_code == "UNKNOWN_OR_DEFAULT_POLICY"
        assert evidence["matched_policy"]["allowed_exception"] is None
        assert policies.allowed_decisions(
            "FIREWALL_DROP", True, evidence=evidence
        ) == ["KEEP_CURRENT_POLICY", "REQUEST_MORE_INFORMATION"]


def test_block_requires_block_policy_and_ipv4_forward_flow() -> None:
    policies = PolicyLoader(PROJECT_ROOT / "config")
    block_event = _event(
        rule_id="ZEEK_SUSPICIOUS_CONNECTION",
        event_type="ALERT",
    )
    evidence = policies.build_evidence(block_event)

    assert policies.revalidate_temporary_action(
        evidence, "BLOCK_TEMPORARY"
    ).authorized
    assert not policies.revalidate_temporary_action(
        evidence, "ALLOW_TEMPORARY"
    ).authorized

    wrong_event_type = policies.build_evidence(
        _event(rule_id="BLOCK_VPN_SOURCE", event_type="ALERT")
    )
    wrong_event_result = policies.revalidate_temporary_action(
        wrong_event_type, "ALLOW_TEMPORARY"
    )
    assert wrong_event_result.reason_code == "ACTION_NOT_ALLOWED_FOR_EVENT_TYPE"

    input_evidence = policies.build_evidence(_event(direction="input"))
    input_result = policies.revalidate_temporary_action(
        input_evidence, "ALLOW_TEMPORARY"
    )
    assert input_result.reason_code == "EVENT_DIRECTION_NOT_FORWARD"

    ipv6_evidence = policies.build_evidence(
        _event(source_ip="2001:db8::1", destination_ip="2001:db8::2")
    )
    ipv6_result = policies.revalidate_temporary_action(
        ipv6_evidence, "ALLOW_TEMPORARY"
    )
    assert ipv6_result.reason_code == "EVENT_IP_VERSION_NOT_ENFORCEABLE"


def test_policy_snapshot_is_stable_and_revalidated() -> None:
    first = PolicyLoader(PROJECT_ROOT / "config")
    second = PolicyLoader(PROJECT_ROOT / "config")
    evidence = first.build_evidence(_event())

    assert first.policy_hash == second.policy_hash
    assert first.policy_version == second.policy_version
    assert len(first.policy_hash) == 64

    tampered = deepcopy(evidence)
    tampered["policy_snapshot"]["hash"] = "0" * 64
    result = first.revalidate_temporary_action(tampered, "ALLOW_TEMPORARY")
    assert result.authorized is False
    assert result.reason_code == "POLICY_SNAPSHOT_MISMATCH"


def test_maximum_ttl_comes_from_current_local_policy_not_evidence() -> None:
    policies = PolicyLoader(PROJECT_ROOT / "config")
    evidence = policies.build_evidence(_event())
    evidence["matched_policy"]["maximum_ttl_seconds"] = 86_400

    assert policies.maximum_ttl(evidence, 500) == 500
