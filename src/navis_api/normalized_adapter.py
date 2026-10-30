"""Built-in, deliberately narrow Navis normalized JSON v1 adapter.

This module does not accept native vendor configuration. A collector must
provide already interpreted values and retain the native input separately.
"""
from ipaddress import ip_address, ip_network
from navis_common.mac import normalize_mac


def validate_policy_details(details, _depth=0):
    if 'interface_condition' in details:
        condition = details['interface_condition']
        if not isinstance(condition, dict) or set(condition) != {'native_id', 'direction', 'ip_version'} or not isinstance(condition['native_id'], str) or not condition['native_id'].strip() or condition['direction'] not in ('in','out') or type(condition['ip_version']) is not int or condition['ip_version'] not in (4,6):
            raise ValueError('invalid interface ACL attachment condition')
    if _depth >= 32:
        raise ValueError("inline policy depth limit exceeded")
    if "workload_condition" in details:
        condition = details["workload_condition"]
        if not isinstance(condition, dict) or set(condition) != {"vif_external_id", "direction", "ip_protocol", "complete"}:
            raise ValueError("invalid workload condition")
        if not isinstance(condition["vif_external_id"], str) or not condition["vif_external_id"] or not isinstance(condition["complete"], bool):
            raise ValueError("invalid workload identity/completeness")
        if condition["direction"] not in ("IN", "OUT", "IN_OUT", "UNKNOWN") or condition["ip_protocol"] not in ("IPV4", "IPV6", "IPV4_IPV6", "UNKNOWN"):
            raise ValueError("invalid workload direction/IP family")
    if "inline_rules" in details:
        if not isinstance(details["inline_rules"], list) or details.get("inline_default", "unknown") not in ("allow", "deny", "unknown") or not isinstance(details.get("inline_complete", False), bool):
            raise ValueError("invalid inline policy")
        for rule in details["inline_rules"]:
            if not isinstance(rule, dict) or not isinstance(rule.get("rule_id"), str) or not isinstance(rule.get("enabled"), bool) or rule.get("action") not in ("allow", "deny", "unknown"):
                raise ValueError("invalid inline rule")
            validate_selectors(rule.get("selectors"), allow_empty=True)
            child_details = rule.get("details", {})
            if not isinstance(child_details, dict):
                raise ValueError("invalid inline rule details")
            validate_policy_details(child_details, _depth + 1)
    if "zone_relation" in details and details["zone_relation"] not in ("universal", "intrazone", "interzone", "unknown"):
        raise ValueError("invalid policy zone relation")
    condition = details.get("application_condition")
    if condition is None:
        return
    required = {"applications", "any_application", "application_default", "default_services", "complete"}
    if not isinstance(condition, dict) or not required <= set(condition) or set(condition) - (required | {"incomplete_applications"}):
        raise ValueError("invalid application condition")
    if any(not isinstance(condition[k], bool) for k in ("any_application", "application_default", "complete")):
        raise ValueError("invalid application condition flags")
    for key in ("applications", "incomplete_applications"):
        names = condition.get(key)
        if key == "applications" and names is None:
            continue
        if names is not None and (not isinstance(names, list) or any(not isinstance(n, str) or not n.strip() for n in names)):
            raise ValueError("invalid application names")
    if not isinstance(condition["default_services"], list):
        raise ValueError("invalid application default services")
    for service in condition["default_services"]:
        if not isinstance(service, dict) or set(service) != {"application", "protocol", "start", "end"}:
            raise ValueError("invalid application default service")
        if not isinstance(service["application"], str) or not service["application"].strip() or service["protocol"] not in ("tcp", "udp"):
            raise ValueError("invalid application default identity/protocol")
        start, end = service["start"], service["end"]
        if any(not isinstance(x, int) or isinstance(x, bool) for x in (start, end)) or not 0 <= start <= end <= 65535:
            raise ValueError("invalid application default ports")


def validate_selectors(selectors, *, allow_empty=False):
    if not isinstance(selectors, list) or (not selectors and not allow_empty):
        raise ValueError("selectors must be a nonempty list; use explicit any selectors")
    roles = {"source", "destination", "service", "source_zone", "destination_zone", "interface"}
    for selector in selectors:
        if not isinstance(selector, dict) or set(selector) != {"role", "kind", "value", "negated"}:
            raise ValueError("selector requires role, kind, value and negated")
        role, kind, value = selector["role"], selector["kind"], selector["value"]
        if role not in roles or not isinstance(selector["negated"], bool):
            raise ValueError("invalid selector role or negation")
        if kind == "any":
            if value is not None or selector["negated"]:
                raise ValueError("any requires null value and cannot be negated")
        elif kind == "address" and role in ("source", "destination"):
            if not isinstance(value, str):
                raise ValueError("address must be a CIDR or host")
            ip_network(value, strict=False)
        elif kind == "service" and role == "service":
            required = {"protocol", "destination_port_start", "destination_port_end"}
            optional = {"source_port_start", "source_port_end", "tcp_flags_all", "tcp_flags_any"}
            if not isinstance(value, dict) or not required <= set(value) or set(value) - (required | optional):
                raise ValueError("invalid service selector")
            start, end = value["destination_port_start"], value["destination_port_end"]
            if not isinstance(value["protocol"], str) or not value["protocol"].strip() or any(not isinstance(x, int) or isinstance(x, bool) for x in (start, end)) or not 0 <= start <= end <= 65535:
                raise ValueError("invalid protocol or port range")
            if ("source_port_start" in value) != ("source_port_end" in value):
                raise ValueError("source port range requires both bounds")
            if "source_port_start" in value:
                start, end = value["source_port_start"], value["source_port_end"]
                if any(not isinstance(x, int) or isinstance(x, bool) for x in (start, end)) or not 0 <= start <= end <= 65535:
                    raise ValueError("invalid source port range")
            for key in ("tcp_flags_all", "tcp_flags_any"):
                if key in value and (value["protocol"].lower() != "tcp" or not isinstance(value[key], list)
                                     or any(flag not in ("syn", "ack", "rst", "fin", "psh", "urg", "ece", "cwr") for flag in value[key])):
                    raise ValueError("invalid TCP flags")
        elif kind == "zone" and role in ("source_zone", "destination_zone") or kind == "interface" and role == "interface":
            if not isinstance(value, str) or not value.strip():
                raise ValueError("zone or interface must be named")
        else:
            raise ValueError("unsupported selector")
    return selectors


def normalize(data_type, payload):
    if data_type not in ("mac", "route", "policy", "interface", "neighbor", "nat", "security_zone"):
        raise ValueError("unsupported data type")
    if set(payload) != {"entries"} or not isinstance(payload["entries"], list):
        raise ValueError("payload must contain only an entries array")
    output = []
    for item in payload["entries"]:
        if not isinstance(item, dict):
            raise ValueError("entries must be objects")
        if data_type == "security_zone":
            if set(item) != {"enforcement_point", "zone", "interfaces"} or not all(isinstance(item[x], str) and item[x].strip() for x in ("enforcement_point", "zone")) or not isinstance(item["interfaces"], list) or any(not isinstance(x, str) or not x.strip() for x in item["interfaces"]):
                raise ValueError("security zone requires enforcement_point, zone and interface IDs")
            output.append(item.copy())
        elif data_type == "interface":
            required = {"name", "kind", "addresses"}
            allowed = required | {"native_id", "parent", "vrf", "operational_state", "vlans", "config"}
            if not required <= set(item) or set(item) - allowed or not isinstance(item["name"], str) or not item["name"].strip() or not isinstance(item["kind"], str) or not item["kind"].strip() or not isinstance(item["addresses"], list):
                raise ValueError("interface requires name, kind and addresses")
            for field in ("native_id", "parent", "vrf", "operational_state"):
                if field in item and item[field] is not None and (not isinstance(item[field], str) or not item[field].strip()):
                    raise ValueError("invalid interface " + field)
            if "config" in item and not isinstance(item["config"], dict):
                raise ValueError("interface config must be an object")
            if "vlans" in item and (not isinstance(item["vlans"], list) or any(not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 4094 for v in item["vlans"])):
                raise ValueError("invalid interface VLANs")
            from ipaddress import ip_interface
            output.append({**item, "addresses": [str(ip_interface(a)) for a in item["addresses"]]})
        elif data_type == "neighbor":
            if set(item) != {"interface", "vrf", "ip", "mac", "state"} or not all(isinstance(item[x], str) and item[x].strip() for x in ("interface", "vrf", "state")):
                raise ValueError("neighbor requires interface, vrf, ip, mac and state")
            output.append({**item, "ip": str(ip_address(item["ip"])), "mac": normalize_mac(item["mac"])})
        elif data_type == "nat":
            required = {"enforcement_point", "rule_set", "processing_stage", "rule_id", "position", "enabled", "translation_kind", "translation", "selectors"}
            if not required <= set(item) or set(item) - (required | {"details"}) or any(not isinstance(item[x], str) or not item[x].strip() for x in ("enforcement_point", "rule_set", "processing_stage", "rule_id", "translation_kind")) or not isinstance(item["translation"], dict) or not isinstance(item["position"], int) or isinstance(item["position"], bool) or item["position"] < 0 or not isinstance(item["enabled"], bool):
                raise ValueError("invalid NAT entry")
            if "details" in item and not isinstance(item["details"], dict):
                raise ValueError("NAT details must be an object")
            validate_selectors(item["selectors"], allow_empty=True)
            output.append(item.copy())
        elif data_type == "mac":
            if set(item) != {"interface", "mac", "vlan"}:
                raise ValueError("MAC entry requires interface, mac and vlan")
            if not isinstance(item["interface"], str) or not item["interface"].strip():
                raise ValueError("invalid interface")
            if not isinstance(item["vlan"], int) or isinstance(item["vlan"], bool) or not 1 <= item["vlan"] <= 4094:
                raise ValueError("invalid VLAN")
            output.append({**item, "mac": normalize_mac(item["mac"])})
        elif data_type == "route":
            required = {"vrf", "destination", "next_hop", "interface"}
            if not required <= set(item) or set(item) - (required | {"route_type", "details"}):
                raise ValueError("route requires vrf, destination, next_hop and interface")
            if not isinstance(item["vrf"], str) or not item["vrf"].strip() or item["interface"] is not None and (not isinstance(item["interface"], str) or not item["interface"].strip()):
                raise ValueError("invalid route context or interface")
            kind = item.get("route_type", "forward")
            if kind not in ("forward", "connected", "discard") or "details" in item and not isinstance(item["details"], dict):
                raise ValueError("invalid route type or details")
            if kind == "forward" and item["interface"] is None and item["next_hop"] is None:
                raise ValueError("forward route requires interface or next hop")
            if kind == "connected" and item["interface"] is None or kind == "discard" and (item["next_hop"] is not None or item["interface"] is not None):
                raise ValueError("invalid connected/discard route egress")
            prefix = ip_network(item["destination"], strict=True)
            hop = ip_address(item["next_hop"]) if item["next_hop"] is not None else None
            if hop is not None and prefix.version != hop.version:
                raise ValueError("route and next hop must use the same IP version")
            output.append({**item, "destination": str(prefix), "next_hop": str(hop) if hop is not None else None})
        elif data_type == "policy":
            required = {"enforcement_point", "rule_set", "default_action", "rule_id", "position", "action", "enabled", "selectors"}
            if not required <= set(item) or set(item) - (required | {"details"}) or any(not isinstance(item[x], str) or not item[x].strip() for x in ("enforcement_point", "rule_set", "rule_id")):
                raise ValueError("invalid policy entry")
            if "details" in item and not isinstance(item["details"], dict):
                raise ValueError("policy details must be an object")
            validate_policy_details(item.get("details", {}))
            if item["default_action"] not in ("allow", "deny", "unknown") or item["action"] not in ("allow", "deny", "unknown"):
                raise ValueError("invalid policy action")
            if not isinstance(item["position"], int) or isinstance(item["position"], bool) or item["position"] < 0 or not isinstance(item["enabled"], bool):
                raise ValueError("invalid policy position or enabled flag")
            validate_selectors(item["selectors"], allow_empty=True)
            output.append(item.copy())
        else:
            raise ValueError("unsupported data type")
    return output
