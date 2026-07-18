"""Dry-run iptables adapter that constructs, but never executes, fixed argv."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from ipaddress import IPv4Address
from typing import Final

from app.schemas import RuleAction

from .base import (
    ExactServiceScope,
    FirewallAdapter,
    FirewallReceipt,
    FirewallSafetyError,
    RevocationResult,
    ValidatedFlowGrant,
    is_managed_rule_id,
    normalize_action,
    utc_now,
)

ALLOW_CHAIN: Final[str] = "CONTEXT_ALLOW"
BLOCK_CHAIN: Final[str] = "CONTEXT_BLOCK"
MANAGED_CHAINS: Final[frozenset[str]] = frozenset({ALLOW_CHAIN, BLOCK_CHAIN})


def chain_and_target(action: RuleAction) -> tuple[str, str]:
    normalized = normalize_action(action)
    if normalized == RuleAction.ALLOW:
        return ALLOW_CHAIN, "ACCEPT"
    return BLOCK_CHAIN, "DROP"


def _validate_iptables_scope(
    scope: ExactServiceScope, *, require_forward_interfaces: bool = False
) -> None:
    # The v1 executor intentionally fails closed for IPv6.  Supporting it
    # requires a separate ip6tables/nftables adapter and contract.
    if not isinstance(scope.source_ip, IPv4Address) or not isinstance(
        scope.destination_ip, IPv4Address
    ):
        raise FirewallSafetyError("the iptables v1 adapter supports IPv4 only")
    if require_forward_interfaces:
        if scope.direction != "forward":
            raise FirewallSafetyError(
                "the real iptables adapter accepts forward-scoped grants only"
            )
        if scope.interface_in is None or scope.interface_out is None:
            raise FirewallSafetyError(
                "the real iptables adapter requires ingress and egress interfaces"
            )


def _rule_tail(
    scope: ExactServiceScope,
    action: RuleAction,
    rule_id: str,
    *,
    require_forward_interfaces: bool = False,
) -> tuple[str, ...]:
    _validate_iptables_scope(
        scope, require_forward_interfaces=require_forward_interfaces
    )
    if not is_managed_rule_id(rule_id):
        raise FirewallSafetyError("refusing a non-managed firewall rule ID")
    _chain, target = chain_and_target(action)
    interface_argv: tuple[str, ...] = ()
    if scope.interface_in is not None and scope.interface_out is not None:
        interface_argv = (
            "-i",
            scope.interface_in,
            "-o",
            scope.interface_out,
        )
    return (
        *interface_argv,
        "-s",
        str(scope.source_ip),
        "-d",
        str(scope.destination_ip),
        "-p",
        scope.protocol,
        "--dport",
        str(scope.destination_port),
        "-m",
        "comment",
        "--comment",
        rule_id,
        "-j",
        target,
    )


def build_install_argv(
    scope: ExactServiceScope,
    action: RuleAction,
    rule_id: str,
    *,
    executable: str = "iptables",
    require_forward_interfaces: bool = False,
) -> tuple[str, ...]:
    chain, _target = chain_and_target(action)
    return (
        executable,
        "-w",
        "5",
        "-I",
        chain,
        "1",
        *_rule_tail(
            scope,
            action,
            rule_id,
            require_forward_interfaces=require_forward_interfaces,
        ),
    )


def build_check_argv(
    scope: ExactServiceScope,
    action: RuleAction,
    rule_id: str,
    *,
    executable: str = "iptables",
    require_forward_interfaces: bool = False,
) -> tuple[str, ...]:
    chain, _target = chain_and_target(action)
    return (
        executable,
        "-w",
        "5",
        "-C",
        chain,
        *_rule_tail(
            scope,
            action,
            rule_id,
            require_forward_interfaces=require_forward_interfaces,
        ),
    )


def build_delete_argv(
    scope: ExactServiceScope,
    action: RuleAction,
    rule_id: str,
    *,
    executable: str = "iptables",
    require_forward_interfaces: bool = False,
) -> tuple[str, ...]:
    chain, _target = chain_and_target(action)
    return (
        executable,
        "-w",
        "5",
        "-D",
        chain,
        *_rule_tail(
            scope,
            action,
            rule_id,
            require_forward_interfaces=require_forward_interfaces,
        ),
    )


class DryRunIptablesFirewall(FirewallAdapter):
    """Audit fixed iptables argv without invoking any operating-system tool."""

    def __init__(self, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._clock = clock
        self._rules: dict[str, FirewallReceipt] = {}
        self._lock = asyncio.Lock()

    async def install_exact_grant(
        self, grant: ValidatedFlowGrant
    ) -> FirewallReceipt:
        now = self._clock()
        if grant.expires_at <= now:
            raise FirewallSafetyError("refusing to install an expired grant")
        action = normalize_action(grant.action)
        chain, _target = chain_and_target(action)
        install_argv = build_install_argv(
            grant.exact_scope, action, grant.rule_id
        )
        delete_argv = build_delete_argv(grant.exact_scope, action, grant.rule_id)
        receipt = FirewallReceipt(
            rule_id=grant.rule_id,
            exact_scope=grant.exact_scope,
            action=action,
            chain=chain,
            expires_at=grant.expires_at,
            installed_at=now,
            adapter="dry_run_iptables",
            install_argv=install_argv,
            delete_argv=delete_argv,
        )
        async with self._lock:
            existing = self._rules.get(receipt.rule_id)
            if existing is not None:
                existing.require_semantic_match(receipt)
                return existing
            self._rules[receipt.rule_id] = receipt
        return receipt

    async def revoke(self, receipt: FirewallReceipt) -> RevocationResult:
        async with self._lock:
            existing = self._rules.get(receipt.rule_id)
            if existing is None:
                return RevocationResult(
                    rule_id=receipt.rule_id,
                    revoked=False,
                    already_absent=True,
                    revoked_at=self._clock(),
                )
            existing.require_semantic_match(receipt)
            del self._rules[receipt.rule_id]
        return RevocationResult(
            rule_id=receipt.rule_id,
            revoked=True,
            already_absent=False,
            revoked_at=self._clock(),
        )

    async def list_managed_grants(self) -> list[FirewallReceipt]:
        async with self._lock:
            return sorted(self._rules.values(), key=lambda receipt: receipt.rule_id)
