"""Translate scoped interfaces, configured static routes and active RIB evidence."""
from ipaddress import ip_address, ip_interface, ip_network
import xml.etree.ElementTree as ET

from .paloalto_xml import result_element


def translate_routing(device, scope, zones, *, routes_xml=None):
    owned = {n.text.strip() for n in scope.findall("import/network/interface/member") if n.text}
    owned.update(i for zone in zones for i in zone["interfaces"])
    routers = {}
    for router in device.findall("network/virtual-router/entry"):
        name = router.get("name")
        members = {n.text.strip() for n in router.findall("interface/member") if n.text}
        if members & owned:
            if not name or name in routers:
                raise ValueError("duplicate/missing virtual router")
            routers[name] = router
    interface_routers = {name: [vr for vr, router in routers.items()
        if any(n.text == name for n in router.findall("interface/member"))] for name in owned}
    interfaces, findings, candidates = [], [], []
    network = device.find("network/interface")
    if network is not None:
        def collect(node, family=None, parent=None):
            if node.tag in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"):
                family = node.tag
            name = node.get("name") if node.tag == "entry" else None
            current_parent = parent
            if name in owned:
                values = []
                for path in ("layer3/ip/entry", "ip/entry", "ipv6/address/entry", "layer3/ipv6/address/entry"):
                    for address in node.findall(path):
                        try:
                            values.append(str(ip_interface(address.get("name"))))
                        except (ValueError, TypeError):
                            findings.append({"interface": name, "reason": "address object, DHCP or invalid interface address requires resolution"})
                vrs = interface_routers.get(name, [])
                item = {"name": name, "native_id": name, "kind": "subinterface" if parent else family or "unknown",
                        "addresses": sorted(set(values)), "config": {"origin": "paloalto_config", "evidence": "configured_unverified"}}
                if len(vrs) == 1:
                    item["vrf"] = vrs[0]
                else:
                    findings.append({"interface": name, "reason": "virtual-router association missing or ambiguous"})
                if parent in owned:
                    item["parent"] = parent
                tag = node.findtext("tag")
                if tag and tag.isdigit() and 1 <= int(tag) <= 4094:
                    item["vlans"] = [int(tag)]
                interfaces.append(item)
                current_parent = name
            elif name:
                current_parent = name
            for child in node:
                collect(child, family, current_parent)
        collect(network)
    seen_interfaces = [i["native_id"] for i in interfaces]
    if len(set(seen_interfaces)) != len(seen_interfaces):
        raise ValueError("duplicate configured interface")

    def route_entry(vr, entry, evidence):
        record = {"vrf": vr, "native_id": entry.get("name"), "native_xml": ET.tostring(entry, encoding="unicode"),
                  "evidence": evidence, "unresolved": []}
        try:
            destination = str(ip_network(entry.findtext("destination"), strict=False))
            interface = entry.findtext("interface") or None
            hop_node = entry.find("nexthop")
            discard = hop_node is not None and hop_node.find("discard") is not None
            next_hop = entry.findtext("nexthop/ip-address") or entry.findtext("nexthop/ipv6-address")
            if evidence == "active_rib":
                next_hop = entry.findtext("nexthop") or entry.findtext("next-hop")
                if next_hop in ("0.0.0.0", "::", "0.0.0.0/0"):
                    next_hop = None
                flags = entry.findtext("flags", "")
                kind = "connected" if "C" in flags or "H" in flags else "forward"
            else:
                kind = "discard" if discard else "forward"
                if entry.find("path-monitor") is not None:
                    record["unresolved"].append("static-route path monitoring requires operational state")
            if next_hop:
                next_hop = str(ip_address(next_hop))
                if ip_address(next_hop).version != ip_network(destination).version:
                    raise ValueError("next-hop address family mismatch")
            if interface is not None and interface not in owned:
                raise ValueError("route egress belongs outside selected VSYS")
            if kind == "forward" and next_hop is None and interface is None:
                raise ValueError("recursive next-VR or missing route egress")
            if evidence == "configured_static" and hop_node is not None and any(c.tag not in ("ip-address", "ipv6-address", "discard", "none") for c in hop_node):
                raise ValueError("unsupported next-hop type")
            record["normalized"] = {"vrf": vr, "destination": destination, "next_hop": next_hop,
                "interface": interface, "route_type": kind,
                "details": {"origin": "paloalto_route", "native_id": entry.get("name"), "evidence": evidence,
                            "flags": entry.findtext("flags"), "native_xml": record["native_xml"]}}
        except (ValueError, TypeError) as error:
            record["unresolved"].append(str(error))
        candidates.append(record)
    for vr, router in routers.items():
        for family in ("ip", "ipv6"):
            for entry in router.findall("routing-table/" + family + "/static-route/entry"):
                route_entry(vr, entry, "configured_static")
    static_count = len(candidates)
    if routes_xml is not None:
        result = result_element(routes_xml, "")
        def operational(node, vr=None, parent=None):
            if node.tag == "entry" and parent == "virtual-router":
                vr = node.get("name")
            vr = node.findtext("virtual-router") or vr
            if node.find("destination") is not None:
                flags = node.findtext("flags", "")
                if not flags.startswith("A"):
                    return
                if vr not in routers:
                    findings.append({"route": node.findtext("destination"), "reason": "active route virtual router missing or outside selected VSYS"})
                else:
                    route_entry(vr, node, "active_rib")
                return
            for child in node:
                operational(child, vr, node.tag)
        operational(result)
    selected = candidates[static_count:] if routes_xml is not None else candidates
    # Configuration and active RIB are useful evidence but are not proof of an
    # installed FIB. Partial submission coverage prevents that promotion.
    routes = [r["normalized"] for r in selected if "normalized" in r and not r["unresolved"]]
    findings.extend({"route": r["native_id"], "reason": reason} for r in candidates for reason in r["unresolved"])
    return interfaces, routes, candidates, findings
