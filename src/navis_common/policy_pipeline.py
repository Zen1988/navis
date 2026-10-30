"""Evaluate original-address policy with separately resolved pre/post NAT zones."""
from .nat import evaluate_nat
from .policy_selectors import evaluate_policy

ORIGINAL_ADDRESS_STAGE = "original_addresses_pre_nat_zones_then_post_nat_zone_policy"


def evaluate_original_address_pipeline(packet, nat_rules, policy_rules, lookup_zone, *, source_zone,
                                       nat_complete, policy_complete, default="unknown", application=None):
    """Use routing evidence to resolve NAT-match and security-match zone contexts.

    lookup_zone(destination) returns a resolved zone and optional egress interface.
    Callers establish rule completeness/order; configuration alone does not.
    This models a forward packet, not a session or dynamic NAT allocation.
    """
    original = lookup_zone(packet.destination)
    if original.get("status") != "resolved":
        return {"decision": "unknown", "reason": "pre-NAT routing/zone unresolved", "packet": packet}
    if any(rule.get("processing_stage", ORIGINAL_ADDRESS_STAGE) != ORIGINAL_ADDRESS_STAGE for rule in nat_rules):
        return {"decision": "unknown", "reason": "mixed or unsupported NAT stages", "packet": packet}
    rules = [{**rule, "kind": rule.get("translation_kind", rule.get("kind"))} for rule in nat_rules]
    translated, nat = evaluate_nat(rules, packet, complete=nat_complete, source_zone=source_zone,
                                   destination_zone=original.get("zone"), interface=original.get("interface"))
    if nat["status"] not in ("translated", "unchanged"):
        return {"decision": "unknown", "reason": "NAT unresolved", "nat": nat, "packet": packet}
    after = lookup_zone(translated.destination)
    if after.get("status") != "resolved":
        return {"decision": "unknown", "reason": "post-NAT routing/zone unresolved", "nat": nat, "packet": packet}
    result = evaluate_policy(policy_rules, default, packet.source, packet.destination, packet.protocol,
        packet.destination_port, complete=policy_complete, source_port=packet.source_port,
        source_zone=source_zone, destination_zone=after.get("zone"), interface=after.get("interface"), application=application)
    return {**result, "packet": translated, "nat": nat, "nat_destination_zone": original.get("zone"),
            "policy_destination_zone": after.get("zone"), "policy_address_basis": "original"}
