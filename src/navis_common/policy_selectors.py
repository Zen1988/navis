"""Evaluate a limited, explicit normalized policy subset with uncertainty."""
from ipaddress import ip_address, ip_network


def evaluate_rule(selectors, source, destination, protocol, destination_port, *, source_zone=None, destination_zone=None, interface=None, source_port=None, tcp_flags=None):
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
        elif kind == "service" and role == "service":
            checks = [protocol.lower() == value["protocol"].lower()]
            start = value.get("destination_port_start", value.get("start"))
            end = value.get("destination_port_end", value.get("end"))
            checks.append(start <= destination_port <= end if destination_port is not None and start is not None and end is not None else None)
            if "source_port_start" in value:
                source_any = value["source_port_start"] == 0 and value["source_port_end"] == 65535
                checks.append(True if source_any else value["source_port_start"] <= source_port <= value["source_port_end"] if source_port is not None else None)
            for key in ("tcp_flags_all", "tcp_flags_any"):
                required = set(value.get(key, []))
                if required:
                    actual = {flag.lower() for flag in tcp_flags} if tcp_flags is not None else None
                    checks.append(None if actual is None else required <= actual if key == "tcp_flags_all" else bool(required & actual))
            matched = False if False in checks else None if None in checks else True
        elif kind == "zone" and role in ("source_zone", "destination_zone"):
            actual = source_zone if role == "source_zone" else destination_zone
            matched = actual == value if actual is not None else None
        elif kind == "interface" and role == "interface":
            matched = interface == value if interface is not None else None
        if matched is not None and selector.get("negated"):
            matched = not matched
        roles.setdefault(role, []).append((matched, bool(selector.get("negated"))))
    # Repeated selectors of the same role are alternatives; different roles intersect.
    # A missing role is unknown, but a definite mismatch elsewhere still excludes the rule.
    unknown = not {"source", "destination", "service"} <= roles.keys()
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


def evaluate_application(condition, application, protocol, destination_port):
    """Match explicit application identity and paired native default services.

    Identity must be supplied by the caller/evidence; transport ports cannot
    establish App-ID. None denotes unknown identity or definition coverage.
    """
    if not condition:
        return True
    if not condition.get("complete", False):
        return None
    names = condition.get("applications")
    if application is None:
        return True if condition.get("any_application") and not condition.get("application_default") else None
    if names is not None and application not in names:
        return False
    if not condition.get("any_application") and names is None:
        return None
    if not condition.get("application_default"):
        return True
    services = [s for s in condition.get("default_services", []) if s["application"] == application]
    if not services or application in condition.get("incomplete_applications", []):
        return None
    same_protocol = [s for s in services if s["protocol"].lower() == protocol.lower()]
    if not same_protocol:
        return False
    if destination_port is None:
        return None
    return any(s["start"] <= destination_port <= s["end"] for s in same_protocol)


def evaluate_workload(condition, source, destination, vif_external_id, traffic_direction):
    """Require the actual enforcement NIC; an IP match does not establish it."""
    if not condition:
        return True
    if not condition.get("complete", False):
        return None
    family = condition.get("ip_protocol")
    if family in ("IPV4", "IPV6"):
        version = 4 if family == "IPV4" else 6
        if ip_address(source).version != version or ip_address(destination).version != version:
            return False
    if vif_external_id is None:
        return None
    if vif_external_id != condition["vif_external_id"]:
        return False
    direction = condition["direction"]
    if direction == "IN_OUT":
        return True
    return None if traffic_direction is None else traffic_direction == direction


def evaluate_policy(rules, default, source, destination, protocol, destination_port, *, complete, source_zone=None, destination_zone=None, interface=None, source_port=None, tcp_flags=None, application=None, vif_external_id=None, traffic_direction=None, ingress_interface=None, egress_interface=None, _depth=0):
    """First-match policy: never skip an earlier rule whose match is uncertain."""
    if _depth >= 32:
        return {"decision": "unknown", "rule_id": None, "reason": "inline policy depth limit reached"}
    attachment_checks = []
    for rule in rules:
        if not rule["enabled"]:
            continue
        matched = evaluate_rule(rule["selectors"], source, destination, protocol, destination_port, source_zone=source_zone, destination_zone=destination_zone, interface=interface, source_port=source_port, tcp_flags=tcp_flags)
        details = rule.get("details", {})
        app_match = evaluate_application(details.get("application_condition"), application, protocol, destination_port)
        relation = details.get("zone_relation", "universal")
        zone_match = True
        if relation != "universal":
            zone_match = None if source_zone is None or destination_zone is None else (source_zone == destination_zone) if relation == "intrazone" else (source_zone != destination_zone) if relation == "interzone" else None
        workload_match = evaluate_workload(details.get("workload_condition"), source, destination, vif_external_id, traffic_direction)
        attachment = details.get('interface_condition')
        interface_match = True
        if attachment:
            actual = ingress_interface if attachment.get('direction') == 'in' else egress_interface if attachment.get('direction') == 'out' else None
            interface_match = None if actual is None else actual == attachment.get('native_id')
            if attachment.get('ip_version') != ip_address(source).version or ip_address(source).version != ip_address(destination).version:
                interface_match = False
            attachment_checks.append(interface_match)
        checks = (matched, app_match, zone_match, workload_match, interface_match)
        matched = False if False in checks else None if None in checks else True
        if matched is False:
            continue
        if matched is None or not rule.get("selectors_complete", details.get("selectors_complete", False)):
            return {"decision": "unknown", "rule_id": rule["rule_id"], "reason": "rule conditions incomplete"}
        if "inline_rules" in details:
            result = evaluate_policy(details["inline_rules"], details.get("inline_default", "unknown"),
                source, destination, protocol, destination_port, complete=details.get("inline_complete", False),
                source_zone=source_zone, destination_zone=destination_zone, interface=interface,
                source_port=source_port, tcp_flags=tcp_flags, application=application,
                vif_external_id=vif_external_id, traffic_direction=traffic_direction,
                ingress_interface=ingress_interface, egress_interface=egress_interface, _depth=_depth + 1)
            return {**result, "parent_rule_id": rule["rule_id"],
                    "rule_path": [rule["rule_id"], *result.get("rule_path", [result["rule_id"]])]}
        if rule["action"] not in ("allow", "deny"):
            return {"decision": "unknown", "rule_id": rule["rule_id"], "reason": "unsupported action"}
        return {"decision": rule["action"], "rule_id": rule["rule_id"], "reason": "matched rule"}
    if complete and default in ("allow", "deny"):
        if attachment_checks and True not in attachment_checks:
            return {"decision": "unknown", "rule_id": None, "reason": "interface ACL attachment is not established for this traversal"}
        return {"decision": default, "rule_id": None, "reason": "rule set default"}
    return {"decision": "unknown", "rule_id": None, "reason": "policy coverage or default unknown"}


def evaluate_ordered_layers(layers, source, destination, protocol, destination_port, **context):
    """Every ordered layer must allow; an Accept advances to the next layer."""
    results = []
    if not layers:
        return {"decision": "unknown", "layers": [], "reason": "ordered layers unavailable"}
    for layer in layers:
        result = evaluate_policy(layer["rules"], layer.get("default_action", "unknown"), source, destination,
            protocol, destination_port, complete=layer.get("complete", False), **context)
        results.append(result)
        if result["decision"] != "allow":
            return {**result, "layers": results}
    return {"decision": "allow", "layers": results, "reason": "all ordered layers allow"}
