"""Collector-side translation of APIC physical-interface pages.

Native objects are also converted into a typed evidence inventory. This is not
an effective forwarding or policy model.
"""
import re
from collections import defaultdict
from ipaddress import ip_address, ip_interface, ip_network

CLASS_GROUPS = {
    "fabricNode": "device", "l1PhysIf": "interface", "ethpmPhysIf": "interface_state",
    "fvTenant": "tenant", "fvCtx": "routing_context", "fvBD": "bridge_domain",
    "fvSubnet": "subnet", "fvAp": "application", "fvAEPg": "endpoint_group",
    "fvRsBd": "relationship", "fvRsCtx": "relationship", "fvRsPathAtt": "relationship",
    "fvRsProv": "relationship", "fvRsCons": "relationship", "vzBrCP": "contract",
    "vzSubj": "contract_subject", "vzRsSubjFiltAtt": "relationship", "vzFilter": "filter",
    "vzInTerm": "contract_term", "vzOutTerm": "contract_term", "vzRsFiltAtt": "relationship",
    "vzProvLbl": "contract_label", "vzConsLbl": "contract_label",
    "vzProvSubjLbl": "contract_label", "vzConsSubjLbl": "contract_label", "vzException": "contract_exception",
    "vzEntry": "filter_entry", "fvCEp": "endpoint", "fvIp": "endpoint_ip",
    "fvRsCEpToPathEp": "relationship", "l3extOut": "external_network",
    "l3extInstP": "external_endpoint_group", "l3extSubnet": "external_subnet",
    "l3extRsEctx": "relationship", "l3extRsProv": "relationship", "l3extRsCons": "relationship",
    "l3extLNodeP": "external_node_profile", "l3extLIfP": "external_interface_profile",
    "l3extRsNodeL3OutAtt": "relationship", "l3extRsPathL3OutAtt": "relationship",
    "uribv4Route": "route", "uribv4Nexthop": "route_next_hop",
    "uribv6Route": "route", "uribv6Nexthop": "route_next_hop",
    "lldpAdjEp": "adjacency", "cdpAdjEp": "adjacency",
}

_DN = re.compile(r"^(topology/pod-[^/]+/node-[^/]+/sys/(?:intf/)?phys-\[([^\]]+)\])(?:/phys)?$")


def label_match(provider_labels, consumer_labels, match_type):
    """Compare explicit label sets using Cisco's published match table.

    None means the inputs were not established, as distinct from an empty set.
    This is label evidence only, not an effective policy decision.
    """
    if provider_labels is None or consumer_labels is None or not isinstance(match_type, str):
        return None
    if any(not isinstance(x, str) or not x for x in (*provider_labels, *consumer_labels)):
        return None
    provider, consumer = set(provider_labels), set(consumer_labels)
    mode = match_type.lower()
    if mode not in ("all", "atleastone", "atmostone", "none"):
        return None
    if not provider and not consumer:
        return True
    if mode == "none":
        return bool(provider) and not (provider & consumer)
    if not provider or not consumer:
        return False
    if mode == "all":
        return consumer <= provider
    count = len(provider & consumer)
    return count >= 1 if mode == "atleastone" else count == 1


def _objects(pages, name):
    if not isinstance(pages, list):
        raise ValueError(name + " must be an array of pages")
    for page in pages:
        if not isinstance(page, list):
            raise ValueError(name + " page must be an array")
        for obj in page:
            if not isinstance(obj, dict) or name not in obj or not isinstance(obj[name], dict):
                raise ValueError("unexpected " + name + " object")
            attrs = obj[name].get("attributes")
            if not isinstance(attrs, dict):
                raise ValueError("missing " + name + " attributes")
            yield attrs


def translate_inventory(metadata, class_pages):
    """Index every supported collector class, preserving native attributes.

    Only explicit APIC tDn relationships and unambiguous DN ancestry are
    represented; neither implies effective policy or physical connectivity.
    """
    if not isinstance(metadata, dict) or not metadata.get("fabric_id") or not metadata.get("collected_at"):
        raise ValueError("fabric_id and collected_at are required")
    if not isinstance(class_pages, dict) or set(class_pages) - set(CLASS_GROUPS):
        raise ValueError("unexpected ACI class")
    objects = {}
    for cls, pages in class_pages.items():
        for attributes in _objects(pages, cls):
            dn = attributes.get("dn")
            if not isinstance(dn, str) or not dn.strip():
                raise ValueError(cls + " object requires a DN")
            if dn in objects:
                raise ValueError("duplicate APIC DN: " + dn)
            objects[dn] = {"dn": dn, "class": cls, "kind": CLASS_GROUPS[cls],
                           "attributes": dict(attributes)}
    relationships = []
    unresolved = []
    for dn, obj in objects.items():
        parents = [candidate for candidate in objects if dn.startswith(candidate + "/")]
        if parents:
            relationships.append({"kind": "contains", "source": max(parents, key=len), "target": dn})
        target = obj["attributes"].get("tDn")
        if target:
            if not isinstance(target, str):
                raise ValueError("invalid target DN for " + dn)
            edge = {"kind": obj["class"], "source": dn, "target": target,
                    "resolved": target in objects}
            relationships.append(edge)
            if target not in objects:
                unresolved.append({"source": dn, "target": target, "reason": "target not collected"})
    return {"fabric_id": metadata["fabric_id"], "collected_at": metadata["collected_at"],
            "coverage": "partial", "missing_classes": sorted(set(CLASS_GROUPS) - set(class_pages)),
            "objects": sorted(objects.values(), key=lambda x: x["dn"]),
            "relationships": relationships, "unresolved": unresolved}


def translate_semantics(inventory):
    """Translate observed routes and contracts as incomplete, non-enforcing evidence."""
    objects = inventory["objects"]
    by_dn = {item["dn"]: item for item in objects}
    children = defaultdict(list)
    for edge in inventory["relationships"]:
        if edge["kind"] == "contains":
            children[edge["source"]].append(by_dn[edge["target"]])

    findings = list(inventory["unresolved"])
    routes = []
    contracts = []
    bridge_domains = []
    endpoint_groups = []
    external_networks = []
    devices = []
    adjacencies = []

    def target_of(relation, target_class, name_field):
        attrs = relation["attributes"]
        target = attrs.get("tDn")
        if target:
            return target if target in by_dn and by_dn[target]["class"] == target_class else None
        name = attrs.get(name_field)
        tenant = re.match(r"^(uni/tn-[^/]+)(?:/|$)", relation["dn"])
        if not tenant or not isinstance(name, str) or not name or ":" in name:
            return None
        candidates = [obj["dn"] for obj in objects if obj["class"] == target_class
                      and obj["dn"].startswith(tenant.group(1) + "/")
                      and obj["attributes"].get("name") == name]
        # A same-name shared object could also be the actual target. Without
        # a resolved target DN the effective reference is not established.
        common = [obj for obj in objects if obj["class"] == target_class
                  and obj["dn"].startswith("uni/tn-common/")
                  and obj["attributes"].get("name") == name]
        if tenant.group(1) != "uni/tn-common" and common:
            return None
        return candidates[0] if len(candidates) == 1 else None

    def filter_entry(item):
        attrs = item["attributes"]
        protocol = attrs.get("prot")
        result = {"native_id": item["dn"], "attributes": attrs,
                  "protocol": protocol if protocol in ("tcp", "udp", "icmp", "icmpv6") else None,
                  "destination_ports": None, "source_ports": None, "status": "partial"}
        for field, key in (("d", "destination_ports"), ("s", "source_ports")):
            first, last = attrs.get(field + "FromPort"), attrs.get(field + "ToPort")
            if first == last and first in ("unspecified", "0"):
                result[key] = {"start": 0, "end": 65535}
            if isinstance(first, str) and isinstance(last, str) and first.isdigit() and last.isdigit():
                start, end = int(first), int(last)
                if 0 < start <= end <= 65535:
                    result[key] = {"start": start, "end": end}
        return result

    def resolve_one(parent_dn, relation_class, target_class, name_field):
        relations = [child for child in children[parent_dn] if child["class"] == relation_class]
        if len(relations) != 1:
            findings.append({"source": parent_dn, "reason": relation_class + " missing or ambiguous"})
            return None
        target = target_of(relations[0], target_class, name_field)
        if target is None:
            findings.append({"source": relations[0]["dn"], "reason": target_class + " target unresolved or ambiguous"})
        return target

    def parsed_address(value, source, with_prefix=False):
        try:
            return str(ip_interface(value) if with_prefix else ip_address(value))
        except (ValueError, TypeError):
            findings.append({"source": source, "reason": "invalid or missing IP address"})
            return None

    for obj in objects:
        dn = obj["dn"]
        if obj["kind"] == "device":
            attrs = obj["attributes"]
            devices.append({"native_id": dn, "node_id": attrs.get("id"), "name": attrs.get("name"),
                            "role": attrs.get("role"), "model": attrs.get("model"),
                            "serial": attrs.get("serial"), "management_address": attrs.get("address"),
                            "status": "observed_unverified"})
        elif obj["kind"] == "adjacency":
            adjacencies.append({"native_id": dn, "protocol": "lldp" if obj["class"] == "lldpAdjEp" else "cdp",
                                "attributes": obj["attributes"], "status": "observed_unverified"})
        elif obj["kind"] == "external_network":
            groups, node_profiles = [], []
            for group in children[dn]:
                if group["kind"] == "external_node_profile":
                    nodes, interfaces = [], []
                    for member in children[group["dn"]]:
                        if member["class"] == "l3extRsNodeL3OutAtt":
                            nodes.append({"native_id": member["dn"], "target": member["attributes"].get("tDn"),
                                          "router_id": member["attributes"].get("rtrId")})
                        if member["kind"] == "external_interface_profile":
                            interfaces.extend({"native_id": path["dn"], "target": path["attributes"].get("tDn"),
                                               "address": path["attributes"].get("addr"),
                                               "encapsulation": path["attributes"].get("encap"),
                                               "interface_type": path["attributes"].get("ifInstT")}
                                              for path in children[member["dn"]]
                                              if path["class"] == "l3extRsPathL3OutAtt")
                    node_profiles.append({"native_id": group["dn"], "nodes": nodes, "interfaces": interfaces})
                    continue
                if group["kind"] != "external_endpoint_group":
                    continue
                prefixes = []
                for subnet in children[group["dn"]]:
                    if subnet["kind"] != "external_subnet":
                        continue
                    value = subnet["attributes"].get("ip")
                    try:
                        prefix = str(ip_network(value, strict=False))
                    except (ValueError, TypeError):
                        prefix = None
                        findings.append({"source": subnet["dn"], "reason": "invalid external subnet"})
                    prefixes.append({"native_id": subnet["dn"], "prefix": prefix,
                                     "scope": subnet["attributes"].get("scope"),
                                     "aggregate": subnet["attributes"].get("aggregate")})
                groups.append({"native_id": group["dn"], "name": group["attributes"].get("name"),
                               "subnets": prefixes, "status": "partial"})
            external_networks.append({"native_id": dn, "name": obj["attributes"].get("name"),
                                      "vrf": resolve_one(dn, "l3extRsEctx", "fvCtx", "tnFvCtxName"),
                                      "external_epgs": groups, "node_profiles": node_profiles, "status": "partial"})
        elif obj["kind"] == "bridge_domain":
            subnets = []
            for child in children[dn]:
                if child["kind"] == "subnet":
                    subnets.append({"native_id": child["dn"],
                                    "gateway": parsed_address(child["attributes"].get("ip"), child["dn"], True),
                                    "scope": child["attributes"].get("scope")})
            bridge_domains.append({"native_id": dn, "name": obj["attributes"].get("name"),
                                   "vrf": resolve_one(dn, "fvRsCtx", "fvCtx", "tnFvCtxName"),
                                   "subnets": subnets, "status": "partial"})
        elif obj["kind"] == "endpoint_group":
            endpoints, paths = [], []
            for child in children[dn]:
                if child["kind"] == "endpoint":
                    attrs = child["attributes"]
                    ips = []
                    primary = attrs.get("ip")
                    if primary and primary not in ("0.0.0.0", "::", "unknown"):
                        address = parsed_address(primary, child["dn"])
                        if address:
                            ips.append(address)
                    for ip_obj in children[child["dn"]]:
                        if ip_obj["kind"] == "endpoint_ip":
                            address = parsed_address(ip_obj["attributes"].get("addr"), ip_obj["dn"])
                            if address:
                                ips.append(address)
                    attachments = [{"native_id": path["dn"], "target": path["attributes"].get("tDn")}
                                   for path in children[child["dn"]] if path["class"] == "fvRsCEpToPathEp"]
                    endpoints.append({"native_id": child["dn"], "mac": attrs.get("mac"),
                                      "addresses": ips, "learned_attachments": attachments,
                                      "status": "observed_unverified"})
                elif child["class"] == "fvRsPathAtt":
                    paths.append({"native_id": child["dn"], "target": child["attributes"].get("tDn"),
                                  "encapsulation": child["attributes"].get("encap"),
                                  "status": "configured_unverified"})
            endpoint_groups.append({"native_id": dn, "name": obj["attributes"].get("name"),
                                    "bridge_domain": resolve_one(dn, "fvRsBd", "fvBD", "tnFvBDName"),
                                    "endpoints": endpoints, "configured_paths": paths, "status": "partial"})
    for obj in objects:
        attrs, dn = obj["attributes"], obj["dn"]
        if obj["kind"] == "route":
            node_match = re.match(r"^(topology/pod-[^/]+/node-[^/]+)(?:/|$)", dn)
            candidate = {"native_id": dn, "node": node_match.group(1) if node_match else None,
                         "destination": None, "next_hops": [], "attributes": attrs,
                         "status": "unverified", "source_class": obj["class"]}
            try:
                candidate["destination"] = str(ip_network(attrs.get("prefix", ""), strict=False))
            except (ValueError, TypeError):
                findings.append({"source": dn, "reason": "missing or invalid route prefix"})
            for child in children[dn]:
                if child["kind"] != "route_next_hop":
                    continue
                hop = child["attributes"]
                next_hop = {"native_id": child["dn"], "address": None,
                            "interface": hop.get("if"), "vrf": hop.get("vrf"),
                            "protocol_owner": hop.get("owner")}
                try:
                    next_hop["address"] = str(ip_address(hop.get("addr", "")))
                except (ValueError, TypeError):
                    findings.append({"source": child["dn"], "reason": "missing or non-IP next hop"})
                if candidate["destination"] and next_hop["address"] and ip_network(candidate["destination"]).version != ip_address(next_hop["address"]).version:
                    findings.append({"source": child["dn"], "reason": "next hop and route address families differ"})
                candidate["next_hops"].append(next_hop)
            if not candidate["next_hops"]:
                findings.append({"source": dn, "reason": "no collected next hop; route type unresolved"})
            routes.append(candidate)
        elif obj["kind"] == "contract":
            contract = {"native_id": dn, "scope": attrs.get("scope"), "subjects": [], "attachments": [],
                        "exceptions": [c["attributes"] for c in children[dn] if c["kind"] == "contract_exception"],
                        "providers": [], "consumers": [], "status": "unverified"}
            for subject in children[dn]:
                if subject["kind"] != "contract_subject":
                    continue
                subject_data = {"native_id": subject["dn"], "attributes": subject["attributes"],
                                "reverse_filter_ports": subject["attributes"].get("revFltPorts"),
                                "bidirectional": "yes" if any(c["class"] == "vzRsSubjFiltAtt" for c in children[subject["dn"]])
                                and not any(c["class"] in ("vzInTerm", "vzOutTerm") for c in children[subject["dn"]]) else "no",
                                "labels": [{"class": c["class"], "attributes": c["attributes"]}
                                           for c in children[subject["dn"]] if c["kind"] == "contract_label"],
                                "exceptions": [c["attributes"] for c in children[subject["dn"]] if c["kind"] == "contract_exception"],
                                "filters": []}
                relations = [(c, "subject") for c in children[subject["dn"]] if c["class"] == "vzRsSubjFiltAtt"]
                for term in children[subject["dn"]]:
                    if term["class"] in ("vzInTerm", "vzOutTerm"):
                        relations.extend((c, term["class"]) for c in children[term["dn"]] if c["class"] == "vzRsFiltAtt")
                for relation, direction in relations:
                    target = target_of(relation, "vzFilter", "tnVzFilterName")
                    filter_obj = by_dn.get(target)
                    entry = {"relation": relation["dn"], "target": target, "direction": direction,
                             "action": relation["attributes"].get("action"),
                             "priority_override": relation["attributes"].get("priorityOverride"), "entries": []}
                    if filter_obj and filter_obj["kind"] == "filter":
                        entry["entries"] = [filter_entry(item) for item in children[target]
                                            if item["kind"] == "filter_entry"]
                    else:
                        findings.append({"source": relation["dn"], "reason": "filter target unresolved"})
                    subject_data["filters"].append(entry)
                contract["subjects"].append(subject_data)
            for relation in objects:
                if relation["class"] not in ("fvRsProv", "fvRsCons", "l3extRsProv", "l3extRsCons") or target_of(relation, "vzBrCP", "tnVzBrCPName") != dn:
                    continue
                parent_edges = [edge for edge in inventory["relationships"]
                                if edge["kind"] == "contains" and edge["target"] == relation["dn"]]
                parent = by_dn.get(parent_edges[0]["source"]) if parent_edges else None
                if not parent or parent["kind"] not in ("endpoint_group", "external_endpoint_group"):
                    findings.append({"source": relation["dn"], "reason": "EPG attachment unresolved"})
                    continue
                contract["providers" if relation["class"] in ("fvRsProv", "l3extRsProv") else "consumers"].append(parent["dn"])
                contract["attachments"].append({"native_id": relation["dn"], "epg": parent["dn"],
                                                "class": relation["class"],
                                                "match_type": relation["attributes"].get("matchT"),
                                                "labels": [{"class": c["class"], "attributes": c["attributes"]}
                                                           for c in children[relation["dn"]] if c["kind"] == "contract_label"]})
            contracts.append(contract)
    for relation in objects:
        if relation["class"] in ("fvRsProv", "fvRsCons", "l3extRsProv", "l3extRsCons") and target_of(relation, "vzBrCP", "tnVzBrCPName") is None:
            findings.append({"source": relation["dn"], "reason": "contract target unresolved or ambiguous"})
    policy_candidates = []
    for contract in contracts:
        if not contract["consumers"] or not contract["providers"]:
            findings.append({"source": contract["native_id"], "reason": "contract consumer or provider unresolved"})
        for consumer in contract["consumers"]:
            for provider in contract["providers"]:
                provider_attachment = next((a for a in contract["attachments"] if a["epg"] == provider and a["class"] in ("fvRsProv", "l3extRsProv")), None)
                consumer_attachment = next((a for a in contract["attachments"] if a["epg"] == consumer and a["class"] in ("fvRsCons", "l3extRsCons")), None)
                label_classes = {"vzProvLbl", "vzConsLbl", "vzProvSubjLbl", "vzConsSubjLbl"}
                labels_collected = not (label_classes & set(inventory["missing_classes"]))
                def labels(attachment, cls):
                    if not attachment or not labels_collected:
                        return None
                    return [label["attributes"].get("name") for label in attachment["labels"] if label["class"] == cls]
                epg_match = label_match(labels(provider_attachment, "vzProvLbl"),
                                        labels(consumer_attachment, "vzConsLbl"),
                                        provider_attachment.get("match_type") if provider_attachment else None)
                for subject in contract["subjects"]:
                    def subject_labels(cls):
                        if not labels_collected:
                            return None
                        return [label["attributes"].get("name") for label in subject["labels"] if label["class"] == cls]
                    provider_subject_match = label_match(subject_labels("vzProvSubjLbl"),
                                                         labels(provider_attachment, "vzProvSubjLbl"),
                                                         subject["attributes"].get("provMatchT"))
                    consumer_subject_match = label_match(subject_labels("vzConsSubjLbl"),
                                                         labels(consumer_attachment, "vzConsSubjLbl"),
                                                         subject["attributes"].get("consMatchT"))
                    unresolved = ["contract scope and effective enforcement unverified",
                                  "direction and priority are not evaluated"]
                    if contract["exceptions"] or subject["exceptions"] or "vzException" in inventory["missing_classes"]:
                        unresolved.append("contract exceptions not evaluated or not collected")
                    if None in (epg_match, provider_subject_match, consumer_subject_match):
                        unresolved.append("label matching evidence incomplete")
                    for flt in subject["filters"]:
                        if not flt["entries"]:
                            findings.append({"source": flt["relation"], "reason": "no resolved filter entries for candidate"})
                        for entry in flt["entries"]:
                            if len(policy_candidates) >= 100000:
                                raise ValueError("ACI policy candidate limit exceeded")
                            action = {"permit": "allow", "deny": "deny"}.get(flt["action"])
                            candidate_unresolved = list(unresolved)
                            if action is None:
                                candidate_unresolved.append("filter action unresolved")
                            if entry["protocol"] is None:
                                candidate_unresolved.append("filter protocol unresolved or unsupported")
                            policy_candidates.append({"contract": contract["native_id"],
                                                      "subject": subject["native_id"],
                                                      "consumer_epg": consumer, "provider_epg": provider,
                                                      "source_epg": consumer, "destination_epg": provider,
                                                      "endpoint_roles": "contract_roles_not_packet_direction",
                                                      "filter": flt["target"], "filter_relation": flt["relation"],
                                                      "filter_entry": entry["native_id"],
                                                      "filter_attributes": entry["attributes"],
                                                      "protocol": entry["protocol"],
                                                      "source_ports": entry["source_ports"],
                                                      "destination_ports": entry["destination_ports"],
                                                      "native_action": flt["action"],
                                                      "candidate_action": action,
                                                      "native_direction": flt["direction"],
                                                      "bidirectional": subject["bidirectional"],
                                                      "reverse_filter_ports": subject["reverse_filter_ports"],
                                                      "priority_override": flt["priority_override"],
                                                      "epg_label_match": epg_match,
                                                      "provider_subject_label_match": provider_subject_match,
                                                      "consumer_subject_label_match": consumer_subject_match,
                                                      "label_evidence": "partial",
                                                      "status": "unverified",
                                                      "unresolved": candidate_unresolved})
    directional_rules = []
    for candidate in policy_candidates:
        directional_rules.extend(translate_directions(candidate))
    address_groups = []
    for group in endpoint_groups:
        members = sorted({str(ip_network(address, strict=False))
                          for endpoint in group["endpoints"] for address in endpoint["addresses"]})
        address_groups.append({"native_id": group["native_id"], "name": group["name"],
                               "kind": "internal_epg", "members": members,
                               "membership_source": "observed_endpoints", "complete": False,
                               "bridge_domain": group["bridge_domain"]})
    for network in external_networks:
        for group in network["external_epgs"]:
            members = sorted({subnet["prefix"] for subnet in group["subnets"]
                              if subnet["prefix"] and "import-security" in
                              [s.strip() for s in (subnet.get("scope") or "").split(",")]})
            address_groups.append({"native_id": group["native_id"], "name": group["name"],
                                   "kind": "external_epg", "members": members,
                                   "membership_source": "external_security_prefixes", "complete": False,
                                   "vrf": network["vrf"]})
    return {"coverage": "partial", "routes": routes, "contracts": contracts,
            "address_groups": address_groups,
            "bridge_domains": bridge_domains, "endpoint_groups": endpoint_groups,
            "external_networks": external_networks, "devices": devices, "adjacencies": adjacencies,
            "policy_candidates": policy_candidates,
            "directional_rules": directional_rules,
            "findings": findings,
            "limitations": ["URIB observations are not verified installed forwarding entries",
                            "contract scope, effective priority, enforcement and complete endpoint membership are not evaluated"]}


def translate_directions(candidate):
    """Expand APIC subject attachments or independent directional terminals.

    Every result is stateless. APIC's stateful flag adds an ACK condition on
    provider-to-consumer TCP traffic; it never grants session-based return access.
    Unknown settings remain unresolved rather than inventing port conditions.
    """
    native = candidate["native_direction"]
    directions = []
    if native == "vzInTerm":
        directions = [("consumer_to_provider", False)]
    elif native == "vzOutTerm":
        directions = [("provider_to_consumer", False)]
    elif native == "subject" and candidate.get("bidirectional") == "yes":
        directions = [("consumer_to_provider", False),
                      ("provider_to_consumer", candidate.get("reverse_filter_ports") == "yes")]
    if not directions:
        directions = [("unknown", False)]
    result = []
    for direction, swap in directions:
        reverse = direction == "provider_to_consumer"
        unresolved = [reason for reason in candidate["unresolved"]
                      if reason != "direction and priority are not evaluated"]
        unresolved.append("effective priority is not evaluated")
        if direction == "unknown":
            unresolved.append("subject direction settings missing or inconsistent")
        ports_known = not (native == "subject" and reverse and
                           candidate.get("reverse_filter_ports") not in ("yes", "no"))
        if not ports_known:
            unresolved.append("reverse filter port setting unresolved")
        attrs = candidate["filter_attributes"]
        flags = attrs.get("tcpRules")
        stateful = attrs.get("stateful")
        conditions = {"native_tcp_rules": flags, "native_stateful": stateful,
                      "required_tcp_flags": ["ack"] if reverse and stateful == "yes" and candidate["protocol"] == "tcp" else []}
        if candidate["protocol"] == "tcp" and stateful not in ("yes", "no"):
            unresolved.append("TCP stateful flag condition unresolved")
        if candidate["protocol"] == "tcp" and flags not in ("", "unspecified", "syn", "ack", "rst", "fin", "est"):
            unresolved.append("native TCP flag condition requires evaluation")
        source_ports = candidate["destination_ports"] if swap else candidate["source_ports"]
        destination_ports = candidate["source_ports"] if swap else candidate["destination_ports"]
        if not ports_known or direction == "unknown":
            source_ports = destination_ports = None
        if candidate["protocol"] in ("tcp", "udp") and (source_ports is None or destination_ports is None):
            unresolved.append("transport port range unresolved or unsupported")
        result.append({**candidate, "packet_direction": direction,
                       "source_epg": candidate["provider_epg"] if reverse else candidate["consumer_epg"],
                       "destination_epg": candidate["consumer_epg"] if reverse else candidate["provider_epg"],
                       "source_ports": source_ports, "destination_ports": destination_ports,
                       "ports_reversed": swap if ports_known else None,
                       "statefulness": "stateless", "tcp_conditions": conditions,
                       "unresolved": unresolved})
    return result


def fabric_evidence_submission(inventory, namespace, fabric_external_id):
    """Build a raw-only topology submission for a pre-mapped fabric identity."""
    if not isinstance(namespace, str) or not namespace.strip():
        raise ValueError("source namespace is required")
    if not isinstance(fabric_external_id, str) or not fabric_external_id.strip():
        raise ValueError("explicit fabric external ID is required")
    if not inventory.get("fabric_id") or not inventory.get("collected_at"):
        raise ValueError("fabric metadata is required")
    return {"source": {"namespace": namespace, "external_device_id": fabric_external_id},
            "adapter": {"name": "navis", "input_format": "normalized-json", "format_version": "1"},
            "data_type": "topology", "collected_at": inventory["collected_at"],
            "completeness": "partial",
            "payload": {"kind": "aci_fabric_evidence", "version": 1,
                        "inventory": inventory, "semantics": translate_semantics(inventory)}}


def normalized_policy_submission(inventory, namespace, fabric_external_id):
    """Convert contract candidates to incomplete normalized policy entries.

    The derived selectors are partial observations. Native direction and port
    reversal are translated; membership, precedence and enforcement remain
    unverified. The worker explicitly marks
    selectors incomplete. Positions are storage order, not ACI precedence.
    """
    import hashlib
    import json
    # Reuse the identity and metadata validation for fabric-scoped submissions.
    fabric_evidence_submission(inventory, namespace, fabric_external_id)
    semantics = translate_semantics(inventory)
    candidates = semantics["directional_rules"]
    keyed = {}
    for candidate in candidates:
        identity = [candidate.get(k) for k in ("contract", "subject", "filter_relation",
                    "filter_entry", "consumer_epg", "provider_epg", "native_direction", "packet_direction")]
        key = hashlib.sha256(json.dumps(identity, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        if key in keyed:
            raise ValueError("duplicate ACI policy candidate identity")
        keyed[key] = candidate
    group_addresses = {group["native_id"]: group["members"] for group in semantics["address_groups"]}
    entries = []
    for position, (key, candidate) in enumerate(sorted(keyed.items()), 1):
        rule_id = "aci-candidate:" + key
        selectors = []
        # Packet direction comes from native attachments, independently of
        # effective enforcement, scope and precedence (which remain unverified).
        if candidate["packet_direction"] != "unknown":
            for role, group in (("source", candidate["source_epg"]), ("destination", candidate["destination_epg"])):
                for prefix in group_addresses.get(group, []):
                    selectors.append({"role": role, "kind": "address", "value": prefix, "negated": False})
            ports = candidate.get("destination_ports")
            if candidate.get("protocol") in ("tcp", "udp") and ports:
                service = {
                    "protocol": candidate["protocol"], "destination_port_start": ports["start"],
                    "destination_port_end": ports["end"]}
                source_ports = candidate["source_ports"]
                if source_ports:
                    service.update(source_port_start=source_ports["start"], source_port_end=source_ports["end"])
                conditions = candidate["tcp_conditions"]
                if conditions["required_tcp_flags"]:
                    service["tcp_flags_all"] = conditions["required_tcp_flags"]
                flags = conditions["native_tcp_rules"]
                native_flags = {"syn": ["syn"], "ack": ["ack"], "rst": ["rst"],
                                "fin": ["fin"], "est": ["ack", "rst"]}
                if candidate["protocol"] == "tcp" and isinstance(flags, str) and flags in native_flags:
                    service["tcp_flags_any"] = native_flags[flags]
                selectors.append({"role": "service", "kind": "service", "value": service, "negated": False})
        entries.append({"enforcement_point": "aci-fabric:" + inventory["fabric_id"],
                        "rule_set": "aci-contract-candidates", "default_action": "unknown",
                        "rule_id": rule_id, "position": position,
                        "action": candidate.get("candidate_action") or "unknown", "enabled": True,
                        "selectors": selectors, "details": {"origin": "aci_contract_candidate",
                        "statefulness": "stateless", "selectors_complete": False,
                        "effective_enforcement": "unknown", "position_semantics": "storage_only",
                        "selector_source": "aci_observations" if selectors else "unresolved",
                        "candidate": candidate}})
    return {"source": {"namespace": namespace, "external_device_id": fabric_external_id},
            "adapter": {"name": "navis", "input_format": "normalized-json", "format_version": "1"},
            "data_type": "policy", "collected_at": inventory["collected_at"],
            "completeness": "partial", "payload": {"entries": entries}}


def adapt_interfaces(metadata, physical_pages, operational_pages, namespace, identities):
    """Return per-device ingestion requests; identities map pod/node DN to caller ID."""
    if not isinstance(metadata, dict) or not metadata.get("fabric_id") or not metadata.get("collected_at"):
        raise ValueError("fabric_id and collected_at are required")
    if not isinstance(namespace, str) or not namespace.strip() or not isinstance(identities, dict):
        raise ValueError("namespace and explicit node identities are required")
    operational = {}
    for attrs in _objects(operational_pages, "ethpmPhysIf"):
        dn = attrs.get("dn", "")
        match = _DN.fullmatch(dn) if isinstance(dn, str) else None
        if not match or not dn.endswith('/phys'):
            raise ValueError("unrecognized operational interface DN")
        if match.group(1) in operational:
            raise ValueError("duplicate operational interface")
        operational[match.group(1)] = attrs.get("operSt")
    grouped = defaultdict(list)
    seen = set()
    for attrs in _objects(physical_pages, "l1PhysIf"):
        dn, interface = attrs.get("dn"), attrs.get("id")
        match = _DN.fullmatch(dn) if isinstance(dn, str) else None
        if not match or dn.endswith('/phys') or interface != match.group(2):
            raise ValueError("invalid physical interface identity")
        node = dn.split('/sys/', 1)[0]
        external_id = identities.get(node)
        if not isinstance(external_id, str) or not external_id.strip():
            raise ValueError("missing explicit external ID for " + node)
        if dn in seen:
            raise ValueError("duplicate physical interface")
        seen.add(dn)
        entry = {"name": interface, "native_id": interface, "kind": "physical", "addresses": [],
                 "config": {"aci_dn": dn, "aci_fabric_id": metadata["fabric_id"],
                            "admin_state": attrs.get("adminSt")}}
        state = operational.get(dn)
        if state in ("up", "down"):
            entry["operational_state"] = state
        grouped[external_id].append(entry)
    if len(set(identities.values())) != len(identities):
        raise ValueError("external IDs must uniquely identify nodes in this fabric")
    return [{"source": {"namespace": namespace, "external_device_id": external},
             "adapter": {"name": "navis", "input_format": "normalized-json", "format_version": "1"},
             "data_type": "interface", "collected_at": metadata["collected_at"],
             "completeness": "partial", "payload": {"entries": entries}}
            for external, entries in sorted(grouped.items())]
