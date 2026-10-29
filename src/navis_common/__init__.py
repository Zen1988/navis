"""Shared, deterministic primitives for connectivity analysis."""

from .address import AddressRange, parse_address_selector
from .mac import mac_addresses_equal, normalize_mac
from .device import DeviceEvidence, DeviceMatch, match_device
from .policy import Action, MatchResult, PolicyRule, evaluate_rules

__all__ = ["AddressRange", "parse_address_selector", "mac_addresses_equal", "normalize_mac", "DeviceEvidence", "DeviceMatch", "match_device", "Action", "MatchResult", "PolicyRule", "evaluate_rules"]
