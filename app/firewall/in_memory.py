"""In-process firewall used by the safe local demo and unit tests."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime

from app.schemas import FlowScope, RuleAction

from .base import (
    ExactServiceScope,
    FirewallAdapter,
    FirewallReceipt,
    FirewallSafetyError,
    RevocationResult,
    ValidatedFlowGrant,
    normalize_action,
    utc_now,
)


class InMemoryFirewall(FirewallAdapter):
    """Exact-match allow/block set with deterministic BLOCK precedence."""

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
        chain = "CONTEXT_ALLOW" if action == RuleAction.ALLOW else "CONTEXT_BLOCK"
        receipt = FirewallReceipt(
            rule_id=grant.rule_id,
            exact_scope=grant.exact_scope,
            action=action,
            chain=chain,
            expires_at=grant.expires_at,
            installed_at=now,
            adapter="in_memory",
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

    async def check_flow(self, scope: FlowScope) -> bool:
        """Return whether this exact service scope is currently allowed.

        Rules are evaluated as an immutable snapshot.  Expired entries never
        authorize traffic even if the expiry worker has not removed them yet.
        Any matching BLOCK wins over every matching ALLOW.
        """

        exact_scope = ExactServiceScope.from_flow_scope(scope)
        now = self._clock()
        async with self._lock:
            matching_actions = {
                receipt.action
                for receipt in self._rules.values()
                if receipt.exact_scope == exact_scope and receipt.expires_at > now
            }
        if RuleAction.BLOCK in matching_actions:
            return False
        return RuleAction.ALLOW in matching_actions
