"""Evaluate a limited, explicit normalized policy subset with uncertainty."""
from ipaddress import ip_address, ip_network


def evaluate_rule(selectors, source, destination, protocol, destination_port, *, source_zone=None, destination_zone=None, interface=None):
    """Return True, False, or None when selectors cannot be evaluated."""
    if not selectors:
        return None
    roles = {}
    for selector in selectors:
        role, kind, value = selector["role"], selector["kind"], selector.get("value")
        matched = None
        if kind == "any":
            matched = True
        elif kind == "address" and role in ("source", "destination"):
            address = ip_address(source if role == "source" else destination)
            network = ip_network(value, strict=False)
            matched = address.version == network.version and address in network
        elif kind == "service" and role == "service" and destination_port is not None:
            matched = protocol.lower() == value["protocol"].lower() and value["start"] <= destination_port <= value["end"]
        elif kind == "zone" and role in ("source_zone", "destination_zone"):
            actual = source_zone if role == "source_zone" else destination_zone
            matched = actual == value if actual is not None else None
        elif kind == "interface" and role == "interface":
            matched = interface == value if interface is not None else None
        if matched is not None and selector.get("negated"):
            matched = not matched
        roles.setdefault(role, []).append((matched, bool(selector.get("negated"))))
    # Repeated selectors of the same role are alternatives; different roles intersect.
    if not {"source", "destination", "service"} <= roles.keys():
        return None
    unknown = False
    for entries in roles.values():
        positives = [match for match, negated in entries if not negated]
        negatives = [match for match, negated in entries if negated]
        # Exclusions must all pass; positive entries are alternatives.
        if False in negatives:
            return False
        if None in negatives:
            unknown = True
        if positives:
            if True in positives:
                continue
            if None in positives:
                unknown = True
            else:
                return False
    return None if unknown else True


def evaluate_policy(rules, default, source, destination, protocol, destination_port, *, complete, source_zone=None, destination_zone=None, interface=None):
    """First-match policy: never skip an earlier rule whose match is uncertain."""
    for rule in rules:
        if not rule["enabled"]:
            continue
        matched = evaluate_rule(rule["selectors"], source, destination, protocol, destination_port, source_zone=source_zone, destination_zone=destination_zone, interface=interface)
        if matched is False:
            continue
        if matched is None or not rule.get("selectors_complete", False):
            return {"decision": "unknown", "rule_id": rule["rule_id"], "reason": "rule conditions incomplete"}
        if rule["action"] not in ("allow", "deny"):
            return {"decision": "unknown", "rule_id": rule["rule_id"], "reason": "unsupported action"}
        return {"decision": rule["action"], "rule_id": rule["rule_id"], "reason": "matched rule"}
    if complete and default in ("allow", "deny"):
        return {"decision": default, "rule_id": None, "reason": "rule set default"}
    return {"decision": "unknown", "rule_id": None, "reason": "policy coverage or default unknown"}
