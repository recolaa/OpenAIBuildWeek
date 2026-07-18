"""Typed firewall boundary used by the deterministic authorization service.

The classes in this module deliberately contain no generic command field.  A
``ValidatedFlowGrant`` is a narrow capability: one source address, one
destination address, one destination port, one protocol, one action, and one
expiry.  Adapters consume the canonical snapshot rather than re-reading a
possibly mutable Pydantic model.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Final
from uuid import uuid4

from app.schemas import FlowScope, RuleAction

IPAddress = IPv4Address | IPv6Address

_MANAGED_RULE_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"^ibr-(?P<expiry>[0-9]{10,12})-(?P<nonce>[0-9a-f]{32})$"
)
_ALLOWED_PROTOCOLS: Final[frozenset[str]] = frozenset({"tcp", "udp"})
_ALLOWED_DIRECTIONS: Final[frozenset[str]] = frozenset(
    {"forward", "input", "output", "unknown"}
)
_INTERFACE_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


class FirewallError(RuntimeError):
    """Base class for firewall boundary failures."""


class FirewallSafetyError(FirewallError):
    """Raised when a request violates a fail-closed safety invariant."""


class FirewallDisabledError(FirewallSafetyError):
    """Raised when the real executor has not been explicitly enabled."""


class FirewallExecutionError(FirewallError):
    """Raised when the restricted operating-system command fails."""


class FirewallReconciliationError(FirewallSafetyError):
    """Raised when live managed-chain state cannot be represented safely."""


def utc_now() -> datetime:
    """Return an aware UTC timestamp (kept injectable by adapters)."""

    return datetime.now(UTC)


def _aware_utc(value: datetime, *, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field_name} must be a timezone-aware datetime")
    return value.astimezone(UTC).replace(microsecond=0)


def _enum_value(value: object) -> object:
    return value.value if isinstance(value, Enum) else value


def normalize_action(value: RuleAction) -> RuleAction:
    """Return a schema ``RuleAction`` while accepting enum string values."""

    raw = str(_enum_value(value)).upper()
    if raw not in {"ALLOW", "BLOCK"}:
        raise ValueError("action must be ALLOW or BLOCK")
    try:
        return RuleAction(raw)
    except ValueError:
        # Some schema enums use lower-case wire values while retaining the
        # requested ALLOW/BLOCK member names.
        return RuleAction[raw]


@dataclass(frozen=True, slots=True)
class ExactServiceScope:
    """Canonical, deeply immutable representation of a service-flow scope."""

    source_ip: IPAddress
    destination_ip: IPAddress
    destination_port: int
    protocol: str
    direction: str | None = None
    interface_in: str | None = None
    interface_out: str | None = None

    def __post_init__(self) -> None:
        source = ip_address(str(self.source_ip))
        destination = ip_address(str(self.destination_ip))
        if source.version != destination.version:
            raise ValueError("source_ip and destination_ip must use one address family")
        if isinstance(self.destination_port, bool) or not isinstance(
            self.destination_port, int
        ):
            raise ValueError("destination_port must be an integer")
        if not 1 <= self.destination_port <= 65535:
            raise ValueError("destination_port must be in the range 1..65535")
        protocol = str(_enum_value(self.protocol)).lower()
        if protocol not in _ALLOWED_PROTOCOLS:
            raise ValueError("protocol must be tcp or udp")

        direction_value = _enum_value(self.direction)
        direction = None if direction_value is None else str(direction_value).lower()
        if direction is not None and direction not in _ALLOWED_DIRECTIONS:
            raise ValueError("direction is not a supported traffic direction")
        normalized_interfaces: dict[str, str | None] = {}
        for field_name, interface_value in (
            ("interface_in", self.interface_in),
            ("interface_out", self.interface_out),
        ):
            raw_interface = _enum_value(interface_value)
            interface = None if raw_interface is None else str(raw_interface)
            if interface is not None and _INTERFACE_RE.fullmatch(interface) is None:
                raise ValueError(
                    f"{field_name} must be a character-restricted Linux interface name"
                )
            normalized_interfaces[field_name] = interface
        if (normalized_interfaces["interface_in"] is None) != (
            normalized_interfaces["interface_out"] is None
        ):
            raise ValueError("interface_in and interface_out must be supplied together")

        object.__setattr__(self, "source_ip", source)
        object.__setattr__(self, "destination_ip", destination)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "direction", direction)
        object.__setattr__(self, "interface_in", normalized_interfaces["interface_in"])
        object.__setattr__(self, "interface_out", normalized_interfaces["interface_out"])

    @classmethod
    def from_flow_scope(cls, scope: FlowScope) -> ExactServiceScope:
        """Snapshot a validated external model into immutable primitives."""

        return cls(
            source_ip=scope.source_ip,
            destination_ip=scope.destination_ip,
            destination_port=scope.destination_port,
            protocol=scope.protocol,
            direction=getattr(scope, "direction", None),
            interface_in=getattr(scope, "interface_in", None),
            interface_out=getattr(scope, "interface_out", None),
        )


def generate_managed_rule_id(expires_at: datetime) -> str:
    """Generate a character-restricted ID containing no external text.

    The expiry component is intentionally included so a real adapter can
    reconstruct a conservative receipt while listing rules after a restart.
    """

    expiry = _aware_utc(expires_at, field_name="expires_at")
    return f"ibr-{int(expiry.timestamp())}-{uuid4().hex}"


def is_managed_rule_id(value: str) -> bool:
    return isinstance(value, str) and _MANAGED_RULE_ID_RE.fullmatch(value) is not None


def expiry_from_managed_rule_id(value: str) -> datetime:
    match = _MANAGED_RULE_ID_RE.fullmatch(value)
    if match is None:
        raise ValueError("not an IntentBridge-managed rule ID")
    return datetime.fromtimestamp(int(match.group("expiry")), tz=UTC)


@dataclass(frozen=True, slots=True)
class ValidatedFlowGrant:
    """A deterministic validator's sole input to a firewall adapter.

    ``rule_id`` should normally be omitted.  Supplying it is supported only so
    a persisted, already-validated grant can be reconstructed idempotently.
    The strict format and embedded-expiry check prevent arbitrary identifiers.
    """

    scope: FlowScope
    action: RuleAction
    expires_at: datetime
    rule_id: str | None = None
    exact_scope: ExactServiceScope = field(init=False, repr=False)

    def __post_init__(self) -> None:
        exact_scope = ExactServiceScope.from_flow_scope(self.scope)
        action = normalize_action(self.action)
        expires_at = _aware_utc(self.expires_at, field_name="expires_at")
        rule_id = self.rule_id or generate_managed_rule_id(expires_at)
        if not is_managed_rule_id(rule_id):
            raise ValueError("rule_id must be an application-generated managed ID")
        if expiry_from_managed_rule_id(rule_id) != expires_at:
            raise ValueError("rule_id expiry does not match grant expiry")

        object.__setattr__(self, "exact_scope", exact_scope)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "rule_id", rule_id)


@dataclass(frozen=True, slots=True)
class FirewallReceipt:
    """Immutable evidence describing one adapter-owned rule."""

    rule_id: str
    exact_scope: ExactServiceScope
    action: RuleAction
    chain: str
    expires_at: datetime
    installed_at: datetime | None
    adapter: str
    install_argv: tuple[str, ...] = ()
    delete_argv: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not is_managed_rule_id(self.rule_id):
            raise ValueError("receipt rule_id is not application-managed")
        expires_at = _aware_utc(self.expires_at, field_name="expires_at")
        installed_at = (
            None
            if self.installed_at is None
            else _aware_utc(self.installed_at, field_name="installed_at")
        )
        if expiry_from_managed_rule_id(self.rule_id) != expires_at:
            raise ValueError("receipt expiry does not match its rule_id")
        object.__setattr__(self, "action", normalize_action(self.action))
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "installed_at", installed_at)
        object.__setattr__(self, "install_argv", tuple(self.install_argv))
        object.__setattr__(self, "delete_argv", tuple(self.delete_argv))

    @property
    def semantic_key(
        self,
    ) -> tuple[str, ExactServiceScope, RuleAction, str, datetime]:
        """Return the complete rule identity used during reconciliation.

        Adapter metadata, observation time, and recorded argv are evidence, not
        firewall semantics, and are deliberately excluded.
        """

        return (
            self.rule_id,
            self.exact_scope,
            self.action,
            self.chain,
            self.expires_at,
        )

    def semantically_matches(self, other: object) -> bool:
        """Compare every security-relevant field of two receipts."""

        return isinstance(other, FirewallReceipt) and self.semantic_key == other.semantic_key

    def require_semantic_match(self, other: FirewallReceipt) -> None:
        """Raise a fail-closed error instead of accepting an ID-only match."""

        if not self.semantically_matches(other):
            raise FirewallReconciliationError(
                f"managed rule {self.rule_id} differs from the expected semantics"
            )


@dataclass(frozen=True, slots=True)
class RevocationResult:
    """Idempotent revocation outcome."""

    rule_id: str
    revoked: bool
    already_absent: bool
    revoked_at: datetime

    def __post_init__(self) -> None:
        if not is_managed_rule_id(self.rule_id):
            raise ValueError("revocation rule_id is not application-managed")
        object.__setattr__(
            self,
            "revoked_at",
            _aware_utc(self.revoked_at, field_name="revoked_at"),
        )


def group_managed_grants(
    receipts: Iterable[FirewallReceipt],
) -> dict[str, tuple[FirewallReceipt, ...]]:
    """Group physical observations without collapsing duplicate rule IDs."""

    grouped: dict[str, list[FirewallReceipt]] = {}
    for receipt in receipts:
        grouped.setdefault(receipt.rule_id, []).append(receipt)
    return {rule_id: tuple(group) for rule_id, group in grouped.items()}


class FirewallAdapter(ABC):
    """Restricted async interface; intentionally has no raw-command method."""

    @abstractmethod
    async def install_exact_grant(
        self, grant: ValidatedFlowGrant
    ) -> FirewallReceipt:
        """Ensure exactly one rule for ``grant`` and return its receipt."""

    @abstractmethod
    async def revoke(self, receipt: FirewallReceipt) -> RevocationResult:
        """Remove every exact duplicate of an owned rule, idempotently."""

    @abstractmethod
    async def list_managed_grants(self) -> list[FirewallReceipt]:
        """List physical rules in dedicated chains, preserving duplicates.

        Implementations raise ``FirewallReconciliationError`` rather than
        silently omitting a malformed or unowned rule from a dedicated chain.
        """
