"""Built-in, deliberately narrow Navis normalized JSON v1 adapter.

This module does not accept native vendor configuration. A collector must
provide already interpreted values and retain the native input separately.
"""
from ipaddress import ip_address, ip_network
from navis_common.mac import normalize_mac


def validate_selectors(selectors):
    if not isinstance(selectors, list) or not selectors:
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
            if not isinstance(value, dict) or set(value) != {"protocol", "destination_port_start", "destination_port_end"}:
                raise ValueError("invalid service selector")
            start, end = value["destination_port_start"], value["destination_port_end"]
            if not isinstance(value["protocol"], str) or not value["protocol"].strip() or any(not isinstance(x, int) or isinstance(x, bool) for x in (start, end)) or not 0 <= start <= end <= 65535:
                raise ValueError("invalid protocol or port range")
        elif kind == "zone" and role in ("source_zone", "destination_zone") or kind == "interface" and role == "interface":
            if not isinstance(value, str) or not value.strip():
                raise ValueError("zone or interface must be named")
        else:
            raise ValueError("unsupported selector")
    return selectors


def normalize(data_type, payload):
    if data_type not in ("mac", "route", "policy", "interface", "neighbor", "nat"):
        raise ValueError("unsupported data type")
    if set(payload) != {"entries"} or not isinstance(payload["entries"], list):
        raise ValueError("payload must contain only an entries array")
    output = []
    for item in payload["entries"]:
        if not isinstance(item, dict):
            raise ValueError("entries must be objects")
        if data_type == "interface":
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
            if set(item) != required or any(not isinstance(item[x], str) or not item[x].strip() for x in ("enforcement_point", "rule_set", "processing_stage", "rule_id", "translation_kind")) or not isinstance(item["translation"], dict) or not isinstance(item["position"], int) or isinstance(item["position"], bool) or item["position"] < 0 or not isinstance(item["enabled"], bool):
                raise ValueError("invalid NAT entry")
            validate_selectors(item["selectors"])
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
            if set(item) != {"vrf", "destination", "next_hop", "interface"}:
                raise ValueError("route requires vrf, destination, next_hop and interface")
            if not all(isinstance(item[x], str) and item[x].strip() for x in ("vrf", "interface")):
                raise ValueError("invalid route context or interface")
            prefix = ip_network(item["destination"], strict=True)
            hop = ip_address(item["next_hop"])
            if prefix.version != hop.version:
                raise ValueError("route and next hop must use the same IP version")
            output.append({**item, "destination": str(prefix), "next_hop": str(hop)})
        elif data_type == "policy":
            required = {"enforcement_point", "rule_set", "default_action", "rule_id", "position", "action", "enabled", "selectors"}
            if set(item) != required or any(not isinstance(item[x], str) or not item[x].strip() for x in ("enforcement_point", "rule_set", "rule_id")):
                raise ValueError("invalid policy entry")
            if item["default_action"] not in ("allow", "deny", "unknown") or item["action"] not in ("allow", "deny", "unknown"):
                raise ValueError("invalid policy action")
            if not isinstance(item["position"], int) or isinstance(item["position"], bool) or item["position"] < 0 or not isinstance(item["enabled"], bool):
                raise ValueError("invalid policy position or enabled flag")
            validate_selectors(item["selectors"])
            output.append(item.copy())
        else:
            raise ValueError("unsupported data type")
    return output
