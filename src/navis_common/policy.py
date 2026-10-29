"""Ordered policy evaluation for a deliberately limited normalized subset."""

from dataclasses import dataclass
from enum import Enum

from .address import AddressRange


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    source: AddressRange
    destination: AddressRange
    protocol: str
    destination_port: int
    action: Action

    def __post_init__(self) -> None:
        if not 0 <= self.destination_port <= 65535:
            raise ValueError("port must be between 0 and 65535")


@dataclass(frozen=True)
class MatchResult:
    action: Action
    rule_id: str | None
    reason: str


def evaluate_rules(rules: list[PolicyRule], *, source: str, destination: str,
                   protocol: str, destination_port: int, default: Action) -> MatchResult:
    """Evaluate supplied rules in order; caller establishes scope and completeness."""
    if not 0 <= destination_port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    # Validate both addresses even if there are no rules.
    from ipaddress import ip_address
    ip_address(source)
    ip_address(destination)
    for rule in rules:
        if (rule.source.contains(source) and rule.destination.contains(destination)
                and rule.protocol.lower() == protocol.lower() and rule.destination_port == destination_port):
            return MatchResult(rule.action, rule.rule_id, "first matching rule")
    return MatchResult(default, None, "no matching rule; supplied default applied")
