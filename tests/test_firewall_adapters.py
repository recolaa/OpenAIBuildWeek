from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.firewall import (
    ExactServiceScope,
    FirewallReceipt,
    FirewallReconciliationError,
    FirewallSafetyError,
    IptablesFirewall,
    group_managed_grants,
)
from app.firewall.dry_run_iptables import (
    ALLOW_CHAIN,
    BLOCK_CHAIN,
    build_delete_argv,
    build_install_argv,
)
from app.firewall.iptables import IPTABLES_PATH
from app.schemas import RuleAction

NOW = datetime(2030, 1, 1, tzinfo=UTC)
EXPIRES_AT = NOW + timedelta(minutes=5)
RULE_ID = f"ibr-{int(EXPIRES_AT.timestamp())}-{'a' * 32}"


def exact_scope(
    *,
    port: int = 443,
    direction: str | None = "forward",
    interface_in: str | None = "eth0",
    interface_out: str | None = "eth1",
) -> ExactServiceScope:
    return ExactServiceScope(
        source_ip="10.0.2.1",
        destination_ip="10.0.3.10",
        destination_port=port,
        protocol="tcp",
        direction=direction,
        interface_in=interface_in,
        interface_out=interface_out,
    )


def receipt(
    *,
    scope: ExactServiceScope | None = None,
    adapter: str = "expected",
    installed_at: datetime | None = NOW,
    delete_argv: tuple[str, ...] = (),
) -> FirewallReceipt:
    return FirewallReceipt(
        rule_id=RULE_ID,
        exact_scope=scope or exact_scope(),
        action=RuleAction.ALLOW,
        chain=ALLOW_CHAIN,
        expires_at=EXPIRES_AT,
        installed_at=installed_at,
        adapter=adapter,
        delete_argv=delete_argv,
    )


def allow_line(
    *,
    rule_id: str = RULE_ID,
    source: str = "10.0.2.1/32",
    target: str = "ACCEPT",
    extra: str = "",
    interfaces: str = "-i eth0 -o eth1 ",
) -> str:
    return (
        f"-A {ALLOW_CHAIN} {interfaces}-s {source} -d 10.0.3.10/32 "
        f"-p tcp -m tcp --dport 443 {extra}-m comment "
        f"--comment {rule_id} -j {target}"
    )


def test_receipt_semantic_comparison_ignores_evidence_only_fields() -> None:
    expected = receipt()
    observed = receipt(
        adapter="iptables_reconciled",
        installed_at=None,
        delete_argv=("audit-only",),
    )

    assert expected.semantically_matches(observed)
    expected.require_semantic_match(observed)

    widened = receipt(scope=exact_scope(port=22), adapter="iptables_reconciled")
    assert not expected.semantically_matches(widened)
    with pytest.raises(FirewallReconciliationError):
        expected.require_semantic_match(widened)


def test_grouping_preserves_physical_duplicate_rule_ids() -> None:
    duplicate = receipt(adapter="iptables_reconciled", installed_at=None)

    grouped = group_managed_grants([duplicate, duplicate])

    assert grouped == {RULE_ID: (duplicate, duplicate)}


def test_fixed_argv_includes_interfaces_and_no_command_string() -> None:
    argv = build_install_argv(
        exact_scope(),
        RuleAction.ALLOW,
        RULE_ID,
        executable=IPTABLES_PATH,
        require_forward_interfaces=True,
    )

    assert argv == (
        IPTABLES_PATH,
        "-w",
        "5",
        "-I",
        ALLOW_CHAIN,
        "1",
        "-i",
        "eth0",
        "-o",
        "eth1",
        "-s",
        "10.0.2.1",
        "-d",
        "10.0.3.10",
        "-p",
        "tcp",
        "--dport",
        "443",
        "-m",
        "comment",
        "--comment",
        RULE_ID,
        "-j",
        "ACCEPT",
    )
    assert all("shell" not in argument.lower() for argument in argv)


@pytest.mark.parametrize(
    "scope",
    [
        exact_scope(direction="input"),
        exact_scope(direction=None),
        exact_scope(direction="forward", interface_in=None, interface_out=None),
    ],
)
def test_real_argv_requires_forward_direction_and_both_interfaces(
    scope: ExactServiceScope,
) -> None:
    with pytest.raises(FirewallSafetyError):
        build_install_argv(
            scope,
            RuleAction.ALLOW,
            RULE_ID,
            executable=IPTABLES_PATH,
            require_forward_interfaces=True,
        )


def test_strict_parser_accepts_only_canonical_exact_rule() -> None:
    adapter = IptablesFirewall(enabled=False)

    parsed = adapter._parse_managed_rule(allow_line(), chain=ALLOW_CHAIN)

    assert parsed is not None
    assert parsed.rule_id == RULE_ID
    assert parsed.exact_scope == exact_scope()
    assert parsed.install_argv == ()
    assert parsed.delete_argv == build_delete_argv(
        exact_scope(), RuleAction.ALLOW, RULE_ID, executable=IPTABLES_PATH
    )


def test_strict_parser_keeps_legacy_interface_less_rule_visible() -> None:
    adapter = IptablesFirewall(enabled=False)

    parsed = adapter._parse_managed_rule(
        allow_line(interfaces=""), chain=ALLOW_CHAIN
    )

    assert parsed is not None
    assert parsed.exact_scope.direction == "forward"
    assert parsed.exact_scope.interface_in is None
    assert parsed.exact_scope.interface_out is None


@pytest.mark.parametrize(
    "line",
    [
        allow_line(source="10.0.2.0/24"),
        allow_line(target="DROP"),
        allow_line(extra="! --sport 12345 "),
        allow_line(rule_id="ibr-not-a-valid-managed-id"),
        allow_line(rule_id="owned-by-someone-else"),
        f"-A {ALLOW_CHAIN} -s 10.0.2.1/32 -d 10.0.3.10/32 -j ACCEPT",
    ],
)
def test_strict_parser_fails_closed_for_malformed_or_unowned_rules(line: str) -> None:
    adapter = IptablesFirewall(enabled=False)

    with pytest.raises(FirewallReconciliationError):
        adapter._parse_managed_rule(line, chain=ALLOW_CHAIN)


class ListingOnlyIptables(IptablesFirewall):
    """Test double that never reaches subprocess or the host firewall."""

    def __init__(self, outputs: dict[str, str]) -> None:
        super().__init__(enabled=False)
        self.outputs = outputs
        self.observed_argv: list[tuple[str, ...]] = []

    def _ensure_enabled(self) -> None:
        return None

    async def _run(
        self, argv: tuple[str, ...], *, check: bool
    ) -> subprocess.CompletedProcess[str]:
        assert argv[:4] == (IPTABLES_PATH, "-w", "5", "-S")
        self.observed_argv.append(argv)
        chain = argv[4]
        return subprocess.CompletedProcess(
            args=list(argv), returncode=0, stdout=self.outputs[chain], stderr=""
        )


async def test_listing_preserves_duplicate_physical_rules() -> None:
    line = allow_line()
    adapter = ListingOnlyIptables(
        {
            BLOCK_CHAIN: f"-N {BLOCK_CHAIN}\n",
            ALLOW_CHAIN: f"-N {ALLOW_CHAIN}\n{line}\n{line}\n",
        }
    )

    live = await adapter.list_managed_grants()

    assert len(live) == 2
    assert len(group_managed_grants(live)[RULE_ID]) == 2


async def test_listing_surfaces_malformed_owned_chain_state() -> None:
    adapter = ListingOnlyIptables(
        {
            BLOCK_CHAIN: f"-N {BLOCK_CHAIN}\n",
            ALLOW_CHAIN: (
                f"-N {ALLOW_CHAIN}\n"
                f"-A {ALLOW_CHAIN} -s 0.0.0.0/0 -j ACCEPT\n"
            ),
        }
    )

    with pytest.raises(FirewallReconciliationError):
        await adapter.list_managed_grants()


async def test_parent_topology_verifier_accepts_safe_conservative_order() -> None:
    adapter = ListingOnlyIptables(
        {
            "FORWARD": (
                "-P FORWARD DROP\n"
                f"-A FORWARD -j {BLOCK_CHAIN}\n"
                f"-A FORWARD -j {ALLOW_CHAIN}\n"
                "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            )
        }
    )

    await adapter.verify_parent_chain_topology()

    assert adapter.observed_argv == [
        (IPTABLES_PATH, "-w", "5", "-S", "FORWARD")
    ]


@pytest.mark.parametrize(
    "rules",
    [
        # Missing block jump.
        f"-A FORWARD -j {ALLOW_CHAIN}\n",
        # Duplicate block jump.
        (
            f"-A FORWARD -j {BLOCK_CHAIN}\n"
            f"-A FORWARD -j {BLOCK_CHAIN}\n"
            f"-A FORWARD -j {ALLOW_CHAIN}\n"
        ),
        # Conditional block jump.
        (
            f"-A FORWARD -i eth0 -j {BLOCK_CHAIN}\n"
            f"-A FORWARD -j {ALLOW_CHAIN}\n"
        ),
        # Allow precedes block.
        (
            f"-A FORWARD -j {ALLOW_CHAIN}\n"
            f"-A FORWARD -j {BLOCK_CHAIN}\n"
        ),
        # An ACCEPT bypasses the block chain.
        (
            "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n"
            f"-A FORWARD -j {BLOCK_CHAIN}\n"
            f"-A FORWARD -j {ALLOW_CHAIN}\n"
        ),
        # A second conditional allow jump is forbidden.
        (
            f"-A FORWARD -j {BLOCK_CHAIN}\n"
            f"-A FORWARD -j {ALLOW_CHAIN}\n"
            f"-A FORWARD -i eth0 -j {ALLOW_CHAIN}\n"
        ),
    ],
)
async def test_parent_topology_verifier_fails_closed(rules: str) -> None:
    adapter = ListingOnlyIptables({"FORWARD": f"-P FORWARD DROP\n{rules}"})

    with pytest.raises(FirewallReconciliationError):
        await adapter.verify_parent_chain_topology()


async def test_revoke_rebuilds_fixed_delete_argv_and_ignores_receipt_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = IptablesFirewall(enabled=False, clock=lambda: NOW)
    observed_commands: list[tuple[str, ...]] = []
    existence = iter([True, False])

    monkeypatch.setattr(adapter, "_ensure_enabled", lambda: None)

    async def fake_exists(_receipt: FirewallReceipt) -> bool:
        return next(existence)

    async def fake_run(
        argv: tuple[str, ...], *, check: bool
    ) -> subprocess.CompletedProcess[str]:
        observed_commands.append(argv)
        return subprocess.CompletedProcess(list(argv), 0, stdout="", stderr="")

    monkeypatch.setattr(adapter, "_rule_exists", fake_exists)
    monkeypatch.setattr(adapter, "_run", fake_run)
    untrusted_audit_argv = ("powershell", "-Command", "Remove-Everything")

    result = await adapter.revoke(receipt(delete_argv=untrusted_audit_argv))

    assert result.revoked
    assert observed_commands == [
        build_delete_argv(
            exact_scope(), RuleAction.ALLOW, RULE_ID, executable=IPTABLES_PATH
        )
    ]
    assert not set(untrusted_audit_argv).intersection(observed_commands[0])


async def test_real_install_fails_before_execution_without_direction_or_interfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = IptablesFirewall(enabled=False, clock=lambda: NOW)
    monkeypatch.setattr(adapter, "_ensure_enabled", lambda: None)
    grant = SimpleNamespace(
        rule_id=RULE_ID,
        exact_scope=exact_scope(
            direction=None, interface_in=None, interface_out=None
        ),
        action=RuleAction.ALLOW,
        expires_at=EXPIRES_AT,
    )

    with pytest.raises(FirewallSafetyError):
        await adapter.install_exact_grant(grant)
