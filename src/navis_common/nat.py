"""Evaluate a restricted, deterministic NAT rule set."""
from dataclasses import dataclass, replace
from ipaddress import ip_address
from .policy_selectors import evaluate_rule


@dataclass(frozen=True)
class Packet:
    source: str
    destination: str
    protocol: str
    destination_port: int | None = None
    source_port: int | None = None


def reverse_session_packet(original: Packet, translated: Packet) -> tuple[Packet, Packet]:
    """Return reply packets on the translated and original sides of one NAT session.

    These are modeled session endpoints, not proof that a device retains state.
    """
    if original.protocol.lower() != translated.protocol.lower():
        raise ValueError("protocol translation is unsupported")
    translated_reply = Packet(translated.destination, translated.source, translated.protocol,
                              translated.source_port, translated.destination_port)
    original_reply = Packet(original.destination, original.source, original.protocol,
                            original.source_port, original.destination_port)
    return translated_reply, original_reply


def evaluate_nat(rules, packet, *, complete):
    """Return packet and evidence; unsupported behavior always remains unknown.

    Input rules must already be scoped and ordered by the platform adapter.
    """
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        match = evaluate_rule(rule["selectors"], packet.source, packet.destination,
                              packet.protocol, packet.destination_port)
        if match is False:
            continue
        if match is None or not rule.get("selectors_complete", False):
            return packet, {"status": "unknown", "rule_id": rule["rule_id"], "reason": "NAT match is incomplete"}
        kind = rule["kind"]
        translation = rule.get("translation", {})
        if kind == "no_nat" and not translation:
            return packet, {"status": "unchanged", "rule_id": rule["rule_id"], "reason": "NAT exemption"}
        if kind == "combined":
            if not translation or set(translation) - {"source", "destination"}:
                return packet, {"status": "unknown", "rule_id": rule["rule_id"], "reason": "unsupported combined translation"}
            current = packet
            for side in ("source", "destination"):
                if side in translation:
                    component = {**rule, "kind": side, "translation": translation[side],
                                 "selectors": [{"role": role, "kind": "any"} for role in ("source", "destination", "service")]}
                    current, result = evaluate_nat([component], current, complete=True)
                    if result["status"] != "translated":
                        return packet, {"status": "unknown", "rule_id": rule["rule_id"], "reason": "unsupported combined translation"}
            return current, {"status": "translated", "rule_id": rule["rule_id"], "reason": "matching combined NAT rule"}
        if kind not in ("source", "destination") or not isinstance(translation, dict) or set(translation) - {"address", "port"} or not translation:
            return packet, {"status": "unknown", "rule_id": rule["rule_id"], "reason": "unsupported translation"}
        changes = {}
        if "address" in translation:
            address = ip_address(translation["address"])
            existing = ip_address(packet.source if kind == "source" else packet.destination)
            if address.version != existing.version:
                return packet, {"status": "unknown", "rule_id": rule["rule_id"], "reason": "address family translation unsupported"}
            changes[kind] = str(address)
        if "port" in translation:
            port = translation["port"]
            if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535 or packet.protocol.lower() not in ("tcp", "udp"):
                return packet, {"status": "unknown", "rule_id": rule["rule_id"], "reason": "unsupported translated port"}
            changes[kind + "_port"] = port
        return replace(packet, **changes), {"status": "translated", "rule_id": rule["rule_id"], "reason": "matching NAT rule"}
    return packet, {"status": "unchanged" if complete else "unknown", "rule_id": None,
                    "reason": "no matching NAT rule" if complete else "NAT coverage incomplete"}
