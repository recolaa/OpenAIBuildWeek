"""Linux-only, fail-closed iptables executor for the isolated lab.

There is intentionally no method that accepts arbitrary argv.  Every command
is rebuilt from an immutable exact scope and an application-generated rule ID.
"""

from __future__ import annotations

import asyncio
import os
import platform
import shlex
import subprocess
from collections.abc import Callable
from datetime import datetime
from ipaddress import ip_interface
from pathlib import Path
from typing import Final

from app.schemas import RuleAction

from .base import (
    ExactServiceScope,
    FirewallAdapter,
    FirewallDisabledError,
    FirewallExecutionError,
    FirewallReceipt,
    FirewallReconciliationError,
    FirewallSafetyError,
    RevocationResult,
    ValidatedFlowGrant,
    expiry_from_managed_rule_id,
    is_managed_rule_id,
    normalize_action,
    utc_now,
)
from .dry_run_iptables import (
    ALLOW_CHAIN,
    BLOCK_CHAIN,
    MANAGED_CHAINS,
    build_check_argv,
    build_delete_argv,
    build_install_argv,
    chain_and_target,
)

IPTABLES_PATH: Final[str] = "/usr/sbin/iptables"
_SUBPROCESS_TIMEOUT_SECONDS: Final[int] = 10
_MAX_DUPLICATES_TO_REMOVE: Final[int] = 32
_OWNED_RULE_PREFIX: Final[str] = "ibr-"
_MINIMAL_ENV: Final[dict[str, str]] = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LC_ALL": "C",
}


class IptablesFirewall(FirewallAdapter):
    """Restricted real executor; disabled unless explicitly opted in."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._enabled = enabled
        self._clock = clock
        self._lock = asyncio.Lock()
        self._known_receipts: dict[str, FirewallReceipt] = {}

        if enabled:
            self._assert_platform_and_binary()

    def _assert_platform_and_binary(self) -> None:
        if platform.system() != "Linux":
            raise FirewallSafetyError(
                "the real iptables adapter may run only on Linux"
            )
        executable = Path(IPTABLES_PATH)
        if not executable.is_absolute() or not executable.is_file():
            raise FirewallSafetyError(
                f"required iptables executable is missing: {IPTABLES_PATH}"
            )
        if not os.access(executable, os.X_OK):
            raise FirewallSafetyError(
                f"iptables executable is not executable: {IPTABLES_PATH}"
            )

    def _ensure_enabled(self) -> None:
        if not self._enabled:
            raise FirewallDisabledError(
                "real firewall execution requires enabled=True"
            )
        self._assert_platform_and_binary()

    async def _run(
        self, argv: tuple[str, ...], *, check: bool
    ) -> subprocess.CompletedProcess[str]:
        self._ensure_enabled()
        try:
            completed = await asyncio.to_thread(
                subprocess.run,
                list(argv),
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_SECONDS,
                env=_MINIMAL_ENV,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise FirewallExecutionError("restricted iptables execution failed") from exc
        if check and completed.returncode != 0:
            detail = (completed.stderr or "").strip()[:500]
            raise FirewallExecutionError(
                f"iptables returned {completed.returncode}: {detail}"
            )
        return completed

    async def _rule_exists(self, receipt: FirewallReceipt) -> bool:
        argv = build_check_argv(
            receipt.exact_scope,
            receipt.action,
            receipt.rule_id,
            executable=IPTABLES_PATH,
        )
        completed = await self._run(argv, check=False)
        if completed.returncode == 0:
            return True
        if completed.returncode == 1:
            return False
        detail = (completed.stderr or "").strip()[:500]
        raise FirewallExecutionError(
            f"iptables rule check returned {completed.returncode}: {detail}"
        )

    async def verify_parent_chain_topology(self) -> None:
        """Fail unless ``FORWARD`` gives managed blocks conservative precedence.

        This check is read-only.  It deliberately accepts only exact,
        unconditional jumps so a conditional or earlier second jump cannot
        bypass the expected ordering.
        """

        self._ensure_enabled()
        completed = await self._run(
            (IPTABLES_PATH, "-w", "5", "-S", "FORWARD"), check=True
        )
        forward_rules: list[tuple[str, ...]] = []
        for line in completed.stdout.splitlines():
            try:
                tokens = tuple(shlex.split(line, posix=True))
            except ValueError as exc:
                raise FirewallReconciliationError(
                    "could not parse the parent FORWARD chain"
                ) from exc
            if not tokens or tokens[0] == "-P":
                continue
            if len(tokens) >= 2 and tokens[:2] == ("-A", "FORWARD"):
                forward_rules.append(tokens)
                continue
            raise FirewallReconciliationError(
                "unexpected output while inspecting the parent FORWARD chain"
            )

        def jump_targets(tokens: tuple[str, ...]) -> list[str]:
            targets: list[str] = []
            for index, token in enumerate(tokens[:-1]):
                if token in {"-j", "--jump", "-g", "--goto"}:
                    targets.append(tokens[index + 1])
            return targets

        positions: dict[str, list[int]] = {
            BLOCK_CHAIN: [],
            ALLOW_CHAIN: [],
        }
        accept_positions: list[int] = []
        for index, tokens in enumerate(forward_rules):
            targets = jump_targets(tokens)
            for managed_chain in positions:
                if managed_chain in targets:
                    positions[managed_chain].append(index)
            if "ACCEPT" in targets:
                accept_positions.append(index)

        expected_jumps = {
            BLOCK_CHAIN: ("-A", "FORWARD", "-j", BLOCK_CHAIN),
            ALLOW_CHAIN: ("-A", "FORWARD", "-j", ALLOW_CHAIN),
        }
        for managed_chain, expected_tokens in expected_jumps.items():
            managed_positions = positions[managed_chain]
            if len(managed_positions) != 1:
                raise FirewallReconciliationError(
                    f"FORWARD must contain exactly one jump to {managed_chain}"
                )
            if forward_rules[managed_positions[0]] != expected_tokens:
                raise FirewallReconciliationError(
                    f"FORWARD jump to {managed_chain} must be unconditional"
                )

        block_position = positions[BLOCK_CHAIN][0]
        allow_position = positions[ALLOW_CHAIN][0]
        if block_position >= allow_position:
            raise FirewallReconciliationError(
                "CONTEXT_BLOCK must precede CONTEXT_ALLOW in FORWARD"
            )
        if any(block_position >= accept_position for accept_position in accept_positions):
            raise FirewallReconciliationError(
                "CONTEXT_BLOCK must precede every ACCEPT rule in FORWARD"
            )

    async def install_exact_grant(
        self, grant: ValidatedFlowGrant
    ) -> FirewallReceipt:
        self._ensure_enabled()
        now = self._clock()
        if grant.expires_at <= now:
            raise FirewallSafetyError("refusing to install an expired grant")
        action = normalize_action(grant.action)
        chain, _target = chain_and_target(action)
        receipt = FirewallReceipt(
            rule_id=grant.rule_id,
            exact_scope=grant.exact_scope,
            action=action,
            chain=chain,
            expires_at=grant.expires_at,
            installed_at=now,
            adapter="iptables",
            install_argv=build_install_argv(
                grant.exact_scope,
                action,
                grant.rule_id,
                executable=IPTABLES_PATH,
                require_forward_interfaces=True,
            ),
            delete_argv=build_delete_argv(
                grant.exact_scope,
                action,
                grant.rule_id,
                executable=IPTABLES_PATH,
                require_forward_interfaces=True,
            ),
        )

        async with self._lock:
            known = self._known_receipts.get(receipt.rule_id)
            if known is not None:
                known.require_semantic_match(receipt)
            if not await self._rule_exists(receipt):
                await self._run(receipt.install_argv, check=True)
                if not await self._rule_exists(receipt):
                    raise FirewallExecutionError(
                        "iptables did not contain the rule after a successful insert"
                    )
            self._known_receipts[receipt.rule_id] = receipt
        return receipt

    async def revoke(self, receipt: FirewallReceipt) -> RevocationResult:
        self._ensure_enabled()
        expected_chain, _target = chain_and_target(receipt.action)
        if receipt.chain != expected_chain or receipt.chain not in MANAGED_CHAINS:
            raise FirewallSafetyError(
                "refusing to revoke a receipt outside dedicated managed chains"
            )
        # Never execute argv carried on a receipt; rebuild the fixed command.
        delete_argv = build_delete_argv(
            receipt.exact_scope,
            receipt.action,
            receipt.rule_id,
            executable=IPTABLES_PATH,
        )

        removed = 0
        async with self._lock:
            while await self._rule_exists(receipt):
                if removed >= _MAX_DUPLICATES_TO_REMOVE:
                    raise FirewallExecutionError(
                        "too many duplicate managed rules; refusing unbounded cleanup"
                    )
                await self._run(delete_argv, check=True)
                removed += 1
            self._known_receipts.pop(receipt.rule_id, None)
        return RevocationResult(
            rule_id=receipt.rule_id,
            revoked=removed > 0,
            already_absent=removed == 0,
            revoked_at=self._clock(),
        )

    @staticmethod
    def _one_token_after(tokens: list[str], flag: str, *, rule_id: str) -> str:
        positions = [index for index, token in enumerate(tokens) if token == flag]
        if len(positions) != 1 or positions[0] + 1 >= len(tokens):
            raise FirewallReconciliationError(
                f"managed rule {rule_id} must contain exactly one {flag} value"
            )
        return tokens[positions[0] + 1]

    def _parse_managed_rule(
        self, line: str, *, chain: str
    ) -> FirewallReceipt | None:
        """Parse one physical ``iptables -S`` line without losing semantics.

        Dedicated chains are application-owned.  A rule in one of those chains
        is therefore either one exact rule generated by our fixed argv builder
        or a reconciliation error; it is never silently skipped.
        """

        try:
            tokens = shlex.split(line, posix=True)
        except ValueError as exc:
            if line.strip():
                raise FirewallReconciliationError(
                    f"could not parse output for dedicated chain {chain}"
                ) from exc
            return None
        if not tokens:
            return None
        if tokens == ["-N", chain]:
            return None
        if len(tokens) < 3 or tokens[0] != "-A" or tokens[1] != chain:
            raise FirewallReconciliationError(
                f"unexpected output while inspecting dedicated chain {chain}"
            )

        comment_positions = [
            index for index, token in enumerate(tokens) if token == "--comment"
        ]
        if len(comment_positions) != 1 or comment_positions[0] + 1 >= len(tokens):
            raise FirewallReconciliationError(
                f"rule in dedicated chain {chain} lacks one managed comment"
            )
        rule_id = tokens[comment_positions[0] + 1]
        if not rule_id.startswith(_OWNED_RULE_PREFIX):
            raise FirewallReconciliationError(
                f"unowned rule found in dedicated chain {chain}"
            )
        if not is_managed_rule_id(rule_id):
            raise FirewallReconciliationError(
                f"malformed owned-prefix rule found in dedicated chain {chain}"
            )

        source = self._one_token_after(tokens, "-s", rule_id=rule_id)
        destination = self._one_token_after(tokens, "-d", rule_id=rule_id)
        protocol = self._one_token_after(tokens, "-p", rule_id=rule_id)
        destination_port = self._one_token_after(
            tokens, "--dport", rule_id=rule_id
        )
        target = self._one_token_after(tokens, "-j", rule_id=rule_id)

        input_positions = [index for index, token in enumerate(tokens) if token == "-i"]
        output_positions = [index for index, token in enumerate(tokens) if token == "-o"]
        if len(input_positions) > 1 or len(output_positions) > 1:
            raise FirewallReconciliationError(
                f"managed rule {rule_id} repeats an interface constraint"
            )
        if bool(input_positions) != bool(output_positions):
            raise FirewallReconciliationError(
                f"managed rule {rule_id} has only one interface constraint"
            )
        interface_in = (
            self._one_token_after(tokens, "-i", rule_id=rule_id)
            if input_positions
            else None
        )
        interface_out = (
            self._one_token_after(tokens, "-o", rule_id=rule_id)
            if output_positions
            else None
        )

        action = RuleAction.ALLOW if chain == ALLOW_CHAIN else RuleAction.BLOCK
        _expected_chain, expected_target = chain_and_target(action)
        if target != expected_target:
            raise FirewallReconciliationError(
                f"managed rule {rule_id} has the wrong target for {chain}"
            )
        try:
            source_interface = ip_interface(source)
            destination_interface = ip_interface(destination)
            if (
                source_interface.network.prefixlen
                != source_interface.network.max_prefixlen
                or destination_interface.network.prefixlen
                != destination_interface.network.max_prefixlen
            ):
                raise FirewallReconciliationError(
                    f"managed rule {rule_id} widens a host address to a network"
                )
            exact_scope = ExactServiceScope(
                source_ip=source_interface.ip,
                destination_ip=destination_interface.ip,
                destination_port=int(destination_port),
                protocol=protocol,
                direction="forward",
                interface_in=interface_in,
                interface_out=interface_out,
            )
            if exact_scope.source_ip.version != 4:
                raise FirewallReconciliationError(
                    f"managed rule {rule_id} is not an IPv4 iptables rule"
                )
            expires_at = expiry_from_managed_rule_id(rule_id)
        except FirewallReconciliationError:
            raise
        except (TypeError, ValueError) as exc:
            raise FirewallReconciliationError(
                f"managed rule {rule_id} contains an invalid exact scope"
            ) from exc

        interface_tokens: tuple[str, ...] = ()
        if interface_in is not None and interface_out is not None:
            interface_tokens = ("-i", interface_in, "-o", interface_out)
        common_prefix = (
            "-A",
            chain,
            *interface_tokens,
            "-s",
            source,
            "-d",
            destination,
            "-p",
            protocol,
        )
        common_suffix = (
            "--dport",
            destination_port,
            "-m",
            "comment",
            "--comment",
            rule_id,
            "-j",
            target,
        )
        allowed_forms = {
            (*common_prefix, *common_suffix),
            (*common_prefix, "-m", protocol, *common_suffix),
        }
        if tuple(tokens) not in allowed_forms:
            raise FirewallReconciliationError(
                f"managed rule {rule_id} contains unexpected or reordered arguments"
            )

        observed = FirewallReceipt(
            rule_id=rule_id,
            exact_scope=exact_scope,
            action=action,
            chain=chain,
            expires_at=expires_at,
            installed_at=None,
            adapter="iptables_reconciled",
            delete_argv=build_delete_argv(
                exact_scope,
                action,
                rule_id,
                executable=IPTABLES_PATH,
            ),
        )
        known = self._known_receipts.get(rule_id)
        if known is not None:
            known.require_semantic_match(observed)
            return known
        return observed

    async def list_managed_grants(self) -> list[FirewallReceipt]:
        self._ensure_enabled()
        observed: list[FirewallReceipt] = []
        async with self._lock:
            for chain in (BLOCK_CHAIN, ALLOW_CHAIN):
                completed = await self._run(
                    (IPTABLES_PATH, "-w", "5", "-S", chain), check=True
                )
                for line in completed.stdout.splitlines():
                    receipt = self._parse_managed_rule(line, chain=chain)
                    if receipt is not None:
                        # Physical duplicates are intentionally preserved.  The
                        # reconciliation service must group, compare, and revoke
                        # extras instead of losing them in a dict comprehension.
                        observed.append(receipt)
        return sorted(
            observed,
            key=lambda receipt: (
                receipt.rule_id,
                receipt.chain,
                str(receipt.exact_scope.source_ip),
                str(receipt.exact_scope.destination_ip),
                receipt.exact_scope.destination_port,
                receipt.exact_scope.protocol,
            ),
        )
