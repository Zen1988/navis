"""Translate selected PAN-OS running XML into partial Navis policy submissions.

Caller selects one firewall device entry and VSYS. Native inherited evidence,
application definitions, NAT stages and route contexts remain explicit.
"""
from ipaddress import ip_address, ip_network, summarize_address_range
import xml.etree.ElementTree as ET
import json

from .paloalto_xml import result_element, inherited_scopes, ordered_rules, default_security_rules, target_match
from .paloalto_applications import application_condition, catalog_objects
from .paloalto_nat import translate_nat
from .paloalto_routing import translate_routing


def _bounded(values):
    result = []
    for value in values:
        if len(result) >= 10000:
            raise ValueError("selector expansion limit exceeded")
        result.append(value)
    return result


def _members(parent, path):
    return [(node.text or "").strip() for node in parent.findall(path + "/member")]


def _index(scope, paths):
    result = {}
    for path in paths:
        for node in scope.findall(path + "/entry"):
            name = node.get("name")
            if not name or name in result:
                raise ValueError("missing or duplicate object name in scope")
            result[name] = node
    return result


def _ports(text):
    if not isinstance(text, str) or not text.strip():
        raise ValueError("port range missing")
    ranges = []
    for part in text.split(","):
        bounds = part.strip().split("-")
        if len(bounds) not in (1, 2) or any(not b.isdigit() for b in bounds):
            raise ValueError("unsupported port expression")
        start, end = int(bounds[0]), int(bounds[-1])
        if not 0 <= start <= end <= 65535:
            raise ValueError("invalid port range")
        ranges.append((start, end))
    return ranges


def translate_config(xml, metadata, *, device_entry, vsys, pushed_xml=None, panorama_xml=None,
                     hierarchy_xml=None, applications_xml=None, routes_xml=None):
    """Read a full /config response, retaining local rule order and uncertainty."""
    if not isinstance(metadata, dict) or any(not isinstance(metadata.get(k), str) or not metadata[k].strip()
                                              for k in ("serial", "collected_at")):
        raise ValueError("serial and collected_at are required")
    if not isinstance(device_entry, str) or not device_entry or not isinstance(vsys, str) or not vsys:
        raise ValueError("explicit device entry and VSYS are required")
    config = result_element(xml, "config")
    devices = [node for node in config.findall("devices/entry") if node.get("name") == device_entry]
    if len(devices) != 1:
        raise ValueError("device entry missing or ambiguous")
    scopes = [node for node in devices[0].findall("vsys/entry") if node.get("name") == vsys]
    if len(scopes) != 1:
        raise ValueError("VSYS missing or ambiguous")
    scope = scopes[0]
    shared = config.find("shared")
    shared = shared if shared is not None else ET.Element("shared")
    ancestors, inheritance = inherited_scopes(config, scope, metadata["serial"], vsys,
        pushed_xml=pushed_xml, panorama_xml=panorama_xml, hierarchy_xml=hierarchy_xml)
    object_scopes = [shared, *(s for _, s in ancestors), scope]
    def objects(paths):
        values, ambiguous = {}, set()
        for source in object_scopes:
            for name, node in _index(source, paths).items():
                if name in values and ET.tostring(values[name]) != ET.tostring(node):
                    ambiguous.add(name)
                values[name] = node
        return values, ambiguous
    addresses, ambiguous_addresses = objects(("address", "address-group"))
    services, ambiguous_services = objects(("service", "service-group"))
    applications, ambiguous_applications = objects(("application", "application-group", "application-filter"))
    application_filters = {n.get("name") for s in object_scopes for n in s.findall("application-filter/entry")}
    catalog = {**catalog_objects(applications_xml), **applications}
    findings = []
    point = "paloalto:" + metadata["serial"] + ":" + vsys

    def resolve_address(name, chain=()):
        if name in ambiguous_addresses:
            raise ValueError("shared/local address collision: " + name)
        if len(chain) >= 64:
            raise ValueError("address group depth limit exceeded")
        if name in chain:
            raise ValueError("cyclic address group: " + name)
        node = addresses.get(name)
        if node is None:
            return [str(ip_network(name, strict=False))]
        if node.find("static") is not None:
            members = _members(node, "static")
            if not members:
                raise ValueError("empty static address group: " + name)
            return _bounded(prefix for member in members for prefix in resolve_address(member, (*chain, name)))
        if node.find("ip-netmask") is not None:
            return [str(ip_network(node.findtext("ip-netmask"), strict=False))]
        if node.find("ip-range") is not None:
            bounds = (node.findtext("ip-range") or "").split("-")
            if len(bounds) != 2:
                raise ValueError("invalid IP range: " + name)
            start, end = (ip_address(x.strip()) for x in bounds)
            return [str(prefix) for prefix in summarize_address_range(start, end)]
        raise ValueError("unresolved address object (dynamic, FQDN or unsupported): " + name)

    def resolve_service(name, chain=()):
        if name in ambiguous_services:
            raise ValueError("shared/local service collision: " + name)
        if len(chain) >= 64:
            raise ValueError("service group depth limit exceeded")
        if name in chain:
            raise ValueError("cyclic service group: " + name)
        node = services.get(name)
        if node is None:
            raise ValueError("unresolved service: " + name)
        if node.find("members") is not None:
            members = _members(node, "members")
            if not members:
                raise ValueError("empty service group: " + name)
            return _bounded(value for member in members for value in resolve_service(member, (*chain, name)))
        protocols = list(node.find("protocol")) if node.find("protocol") is not None else []
        if len(protocols) != 1 or protocols[0].tag not in ("tcp", "udp"):
            raise ValueError("unsupported service protocol: " + name)
        protocol = protocols[0]
        source = _ports(protocol.findtext("source-port")) if protocol.find("source-port") is not None else [(0, 65535)]
        return _bounded({"protocol": protocol.tag, "source_port_start": s, "source_port_end": e,
                 "destination_port_start": d, "destination_port_end": f}
                for s, e in source for d, f in _ports(protocol.findtext("port")))

    def selectors_for(rule, nat=False):
        unresolved, selectors = [], []
        def select(role, kind, value, negated=False):
            selectors.append({"role": role, "kind": kind, "value": value, "negated": negated})

        for path, role in (("source", "source"), ("destination", "destination"),
                           ("from", "source_zone"), ("to", "destination_zone"), ("service", "service")):
            members = _members(rule, path)
            if nat and path == "service":
                members = [(rule.findtext("service") or "").strip()]
            negate = rule.findtext("negate-" + path, "no")
            if negate not in ("yes", "no"):
                unresolved.append("invalid negation: " + path)
                continue
            if not members or any(not member for member in members) or "any" in members and len(members) != 1:
                unresolved.append("missing or ambiguous selector: " + path)
                continue
            if members == ["any"]:
                if negate == "yes":
                    unresolved.append("negated any: " + path)
                else:
                    select(role, "any", None)
                continue
            if not nat and path == "service" and members == ["application-default"]:
                # Application/port pairing is evaluated together from rule
                # details; a standalone port union would lose that pairing.
                select(role, "any", None)
                continue
            try:
                values = []
                for member in members:
                    if role in ("source", "destination"):
                        values.extend(resolve_address(member))
                    elif role == "service":
                        values.extend(resolve_service(member))
                    else:
                        values.append(member)
                    if len(values) > 10000:
                        raise ValueError("selector expansion limit exceeded")
                for value in values:
                    select(role, "address" if role in ("source", "destination") else "service" if role == "service" else "zone", value, negate == "yes")
            except (ValueError, TypeError) as error:
                # Drop the entire role if any alternative is unresolved. Keeping
                # only resolved alternatives could incorrectly skip an earlier rule.
                unresolved.append(path + ": " + str(error))
        return selectors, unresolved

    entries = []
    for rule, origin, phase in ordered_rules(ancestors, scope, "security") + default_security_rules(ancestors, scope):
        name = rule.get("name")
        targeted = target_match(rule, metadata["serial"], vsys)
        if targeted is False:
            continue
        selectors, unresolved = selectors_for(rule)
        app_condition, app_findings = application_condition(rule, applications, catalog, _ports, application_filters)
        if ambiguous_applications:
            # An inherited application group may indirectly reference a
            # colliding definition; retain uncertainty for the entire rule.
            app_findings.append("application object precedence unresolved")
            app_condition["complete"] = False
        unresolved.extend(app_findings)
        for path in ("source-user", "category", "source-hip", "destination-hip"):
            values = _members(rule, path)
            if values != ["any"]:
                # Optional absent user/URL/HIP fields have no additional match.
                if values:
                    unresolved.append("unsupported or missing condition: " + path)
        rule_type = rule.findtext("rule-type", "universal")
        if rule_type not in ("universal", "intrazone", "interzone"):
            unresolved.append("unsupported zone relation")
        if rule.findtext("schedule"):
            unresolved.append("schedule requires evaluation")
        if targeted is None:
            unresolved.append("device targeting requires evaluation")
        # Retain other match extensions without assuming an unfamiliar field
        # is harmless. Non-match metadata listed here is preserved in native XML.
        known = {"from", "to", "source", "destination", "service", "negate-source", "negate-destination",
                 "application", "source-user", "category", "source-hip", "destination-hip", "rule-type",
                 "schedule", "target", "action", "disabled", "description", "tag", "log-start", "log-end",
                 "log-setting", "profile-setting", "option", "group-tag"}
        for child in rule:
            if child.tag not in known:
                unresolved.append("unsupported rule field: " + child.tag)
        action = {"allow": "allow", "deny": "deny", "drop": "deny", "reset-client": "deny",
                  "reset-server": "deny", "reset-both": "deny"}.get(rule.findtext("action"), "unknown")
        if action == "unknown":
            unresolved.append("unsupported or missing action")
        disabled = rule.findtext("disabled", "no")
        if disabled not in ("yes", "no"):
            unresolved.append("invalid disabled state")
        rule_id = name if origin == "local" else json.dumps([origin, phase, name], separators=(",", ":"))
        entries.append({"enforcement_point": point, "rule_set": ("effective-security:" if ancestors else "local-security:") + vsys,
                        "default_action": "unknown", "rule_id": rule_id, "position": len(entries) + 1,
                        "action": action, "enabled": disabled != "yes", "selectors": selectors,
                        "details": {"origin": "paloalto_security", "serial": metadata["serial"], "vsys": vsys,
                                    "native_uuid": rule.get("uuid"), "native_action": rule.findtext("action"),
                                    "statefulness": "stateful", "selectors_complete": False,
                                    "application_condition": app_condition, "zone_relation": rule_type if rule_type in ("universal", "intrazone", "interzone") else "unknown",
                                    "native_name": name, "scope": origin, "phase": phase,
                                    "translated_conditions_complete": not unresolved,
                                    "policy_scope": inheritance, "order_semantics": "pre_local_post_first_match",
                                    "unresolved": unresolved,
                                    ("derived_xml" if phase == "default-security-rules" else "native_xml"): ET.tostring(rule, encoding="unicode")}})
        findings.extend({"rule": name, "reason": reason} for reason in unresolved)
    zones = []
    for name, zone in _index(scope, ("zone",)).items():
        if zone.find("network/layer3") is None:
            findings.append({"zone": name, "reason": "non-layer3 zone not translated"})
            continue
        zones.append({"enforcement_point": point, "zone": name, "interfaces": _members(zone, "network/layer3")})
    nat, nat_findings = translate_nat(ordered_rules(ancestors, scope, "nat"), point, metadata, vsys, selectors_for, resolve_address)
    interfaces, routes, route_candidates, route_findings = translate_routing(devices[0], scope, zones, routes_xml=routes_xml)
    findings.extend(nat_findings)
    findings.extend(route_findings)
    return {"serial": metadata["serial"], "vsys": vsys, "collected_at": metadata["collected_at"],
            "policies": entries, "zones": zones, "nat": nat, "interfaces": interfaces, "routes": routes,
            "route_candidates": route_candidates, "findings": findings, "inheritance": inheritance,
            "coverage": "partial", "limitations": ["push deployment, object conflicts and effective coverage require validation",
                "runtime App-ID classification, dynamic objects and schedules require evidence",
                "dynamic PAT, bidirectional static NAT, advanced routing, HA and sessions require runtime evidence",
                "configured routes and active RIB entries are not verified installed FIB entries"]}


def normalized_submissions(xml, metadata, namespace, external_device_id, *, device_entry, vsys, **evidence):
    """Emit five typed envelopes; caller maps firewall serial to Navis identity."""
    if any(not isinstance(value, str) or not value.strip() for value in (namespace, external_device_id)):
        raise ValueError("namespace and explicit external device ID are required")
    semantics = translate_config(xml, metadata, device_entry=device_entry, vsys=vsys, **evidence)
    return [{"source": {"namespace": namespace, "external_device_id": external_device_id},
             "adapter": {"name": "navis", "input_format": "normalized-json", "format_version": "1"},
             "data_type": kind, "collected_at": metadata["collected_at"], "completeness": "partial",
             "payload": {"entries": semantics[key]}}
            for kind, key in (("policy", "policies"), ("security_zone", "zones"), ("nat", "nat"),
                              ("interface", "interfaces"), ("route", "routes"))]
