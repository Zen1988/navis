"""VM/vNIC-first NSX Local Manager Policy DFW translation.

Packet address membership, Applied To workload scope, and dataplane realization
are distinct evidence. No IP-only or broad-scope fallback is invented.
"""
from copy import deepcopy
import re

from .nsx_inventory import list_results, index_resources, vm_inventory
from .nsx_groups import GroupResolver

CATEGORIES = {name: index for index, name in enumerate(("Ethernet", "Emergency", "Infrastructure", "Environment", "Application"))}


def _number(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _ports(values):
    if values is None or values == []:
        return [(0, 65535)]
    if not isinstance(values, list):
        raise ValueError("NSX service ports must be an array")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("invalid port expression")
        for part in value.split(","):
            match = re.fullmatch(r"\s*(\d+)(?:\s*-\s*(\d+))?\s*", part)
            if not match:
                raise ValueError("unsupported NSX port expression")
            start, end = int(match[1]), int(match[2] or match[1])
            if not 0 <= start <= end <= 65535:
                raise ValueError("invalid NSX port range")
            result.append((start, end))
    return result


def translate_policy(metadata, collection, *, vm_external_id, vif_external_id=None):
    if not isinstance(metadata, dict) or any(not isinstance(metadata.get(k), str) or not metadata[k].strip()
        for k in ("manager_id", "domain", "collected_at")):
        raise ValueError("manager_id, domain and collected_at required")
    if metadata.get("manager_type", "local") != "local":
        raise ValueError("this adapter supports NSX Local Manager /infra scope only")
    if not isinstance(collection, dict) or not isinstance(vm_external_id, str) or not vm_external_id:
        raise ValueError("native collection and selected VM external ID required")
    domain = "/infra/domains/" + metadata["domain"]
    domains = index_resources(list_results(collection.get("domains")), "/infra/domains", "Domain")
    if domain not in domains:
        raise ValueError("selected NSX domain not collected")
    groups = index_resources(list_results(collection.get("groups")), domain + "/groups", "Group")
    policies = index_resources(list_results(collection.get("policies")), domain + "/security-policies", "SecurityPolicy")
    services = index_resources(list_results(collection.get("services")), "/infra/services", "Service")
    segments = index_resources(list_results(collection.get("segments")), "/infra/segments", "Segment")
    for path, pages in collection.get("segment_ports", {}).items():
        if path not in segments:
            raise ValueError("segment-port collection has a foreign parent")
        index_resources(list_results(pages), path + "/ports", "SegmentPort")
    for path, pages in collection.get("group_virtual_machines", {}).items():
        if path not in groups:
            raise ValueError("VM membership collection has a foreign group")
        list_results(pages)
    target, machines, vifs = vm_inventory(collection, vm_external_id, vif_external_id)
    resolver = GroupResolver(groups, collection, machines, vifs, target)
    port = target["segment_port"]
    attachment_known = port is not None and port.get("parent_path") in segments
    point = ":".join(("nsx-dfw", metadata["manager_id"], vm_external_id, target["external_id"]))
    findings = []

    def service_entry(entry, stack=()):
        if not isinstance(entry, dict):
            raise ValueError("invalid native service entry")
        if entry.get("marked_for_delete"):
            raise ValueError("service entry pending deletion")
        if entry.get("resource_type") == "NestedServiceServiceEntry":
            return resolve_service(entry.get("nested_service_path"), stack)
        if entry.get("resource_type") != "L4PortSetServiceEntry" or entry.get("l4_protocol") not in ("TCP", "UDP"):
            raise ValueError("unsupported L2/ICMP/IP-protocol/ALG service entry")
        values = []
        for start, end in _ports(entry.get("destination_ports")):
            for source_start, source_end in _ports(entry.get("source_ports")):
                values.append({"protocol": entry["l4_protocol"].lower(), "destination_port_start": start,
                    "destination_port_end": end, "source_port_start": source_start, "source_port_end": source_end})
                if len(values) > 10000:
                    raise ValueError("service expansion limit exceeded")
        return values

    def resolve_service(path, stack=()):
        if path in stack or len(stack) >= 64:
            raise ValueError("cyclic or excessively deep nested service")
        if path not in services or services[path].get("marked_for_delete"):
            raise ValueError("service not collected or pending deletion")
        entries = services[path].get("service_entries")
        if not isinstance(entries, list) or not entries:
            raise ValueError("service entries missing")
        values = []
        for entry in entries:
            values.extend(service_entry(entry, (*stack, path)))
            if len(values) > 10000:
                raise ValueError("service expansion limit exceeded")
        return values

    def scope_match(scope):
        if not isinstance(scope, list) or not scope or any(not isinstance(p, str) for p in scope):
            raise ValueError("Applied To scope missing")
        if len(scope) == 1 and scope[0].upper() == "ANY":
            return True, True
        if any(p.upper() == "ANY" for p in scope):
            raise ValueError("ANY cannot be mixed with scoped groups")
        # Resolve all alternatives: an unknown group must not be silently
        # discarded because one known alternative happens not to match.
        matches = [resolver.resolve(path, scope=True) for path in scope]
        return any(matches), False

    ordering_known = True
    active_policies = [p for p in policies.values() if not p.get("marked_for_delete")]
    seen_order = set()
    for policy in active_policies:
        order = (policy.get("category"), policy.get("sequence_number"))
        if order[0] not in CATEGORIES or not _number(order[1]) or order in seen_order:
            ordering_known = False
        seen_order.add(order)
    active_policies.sort(key=lambda p: (CATEGORIES.get(p.get("category"), 999),
        p.get("sequence_number") if _number(p.get("sequence_number")) else 0, p["path"]))
    states = {p.get("stateful") if isinstance(p.get("stateful"), bool) else None for p in active_policies}
    statefulness = "stateful" if states == {True} else "stateless" if states == {False} else "unknown"
    entries, applied, broad, unknown_scope = [], 0, 0, 0
    for policy in active_policies:
        path = policy["path"]
        if path not in collection.get("rulebases", {}):
            raise ValueError("policy rule pages not collected: " + path)
        rules = list_results(collection["rulebases"][path])
        indexed = index_resources(rules, path + "/rules", "Rule")
        if policy.get("rule_count") is not None and policy["rule_count"] != len(rules):
            raise ValueError("policy rule_count disagrees with collected rulebase")
        rule_order = [r.get("sequence_number") for r in rules]
        local_order = all(_number(n) for n in rule_order) and len(set(rule_order)) == len(rule_order)
        for rule in sorted(indexed.values(), key=lambda r: (r.get("sequence_number") if _number(r.get("sequence_number")) else 0, r["path"])):
            if rule.get("marked_for_delete"):
                continue
            unresolved, selectors = [], []
            policy_scope, rule_scope = policy.get("scope"), rule.get("scope")
            policy_any = isinstance(policy_scope, list) and len(policy_scope) == 1 and isinstance(policy_scope[0], str) and policy_scope[0].upper() == "ANY"
            rule_specific = isinstance(rule_scope, list) and rule_scope and not (len(rule_scope) == 1 and isinstance(rule_scope[0], str) and rule_scope[0].upper() == "ANY")
            scope_precedence_unknown = policy_any and rule_specific
            effective_scope = rule_scope if scope_precedence_unknown else policy_scope if policy_scope else rule_scope
            scope_applies, scope_broad = None, False
            try:
                if scope_precedence_unknown:
                    raise ValueError("broad policy versus specific rule scope needs version/effective-scope evidence; no broad fallback")
                scope_applies, scope_broad = scope_match(effective_scope)
                if scope_applies is False:
                    continue
                applied += rule.get("disabled") is not True
                broad += scope_broad and rule.get("disabled") is not True
            except (ValueError, TypeError, KeyError) as error:
                unknown_scope += rule.get("disabled") is not True
                unresolved.append("Applied To: " + str(error))
            if not attachment_known:
                unresolved.append("VM/vNIC to segment-port attachment not established")
            if not ordering_known or not local_order:
                unresolved.append("policy/rule evaluation order ambiguous")
            preference = policy.get("connectivity_preference", "NONE")
            if preference != "NONE" and not any(r.get("rule_id") == policy.get("default_rule_id") and r.get("is_default") is True for r in rules):
                unresolved.append("generated connectivity default rule not established")
            if policy.get("application_connectivity_strategy") or policy.get("connectivity_strategy") not in (None, "NONE"):
                unresolved.append("additional policy connectivity semantics unresolved")
            if policy.get("category") == "Ethernet":
                unresolved.append("L2 Ethernet category requires frame-level matching")
            for field, role, exclusion in (("source_groups", "source", "sources_excluded"),
                                            ("destination_groups", "destination", "destinations_excluded")):
                try:
                    references = rule.get(field)
                    excluded = rule.get(exclusion, False)
                    if not isinstance(excluded, bool) or not isinstance(references, list) or not references:
                        raise ValueError("missing address selectors or invalid exclusion")
                    if any(not isinstance(p, str) for p in references):
                        raise ValueError("invalid address reference")
                    if [p.upper() for p in references] == ["ANY"] and not excluded:
                        selectors.append({"role": role, "kind": "any", "value": None, "negated": False})
                    else:
                        if any(p.upper() == "ANY" for p in references):
                            raise ValueError("mixed or excluded ANY")
                        values = set().union(*(resolver.resolve(p) for p in references))
                        if not values:
                            raise ValueError("empty group membership unresolved")
                        selectors.extend({"role": role, "kind": "address", "value": value, "negated": excluded} for value in sorted(values))
                except (ValueError, TypeError, KeyError) as error:
                    unresolved.append(field + ": " + str(error))
            try:
                references = rule.get("services")
                inline = rule.get("service_entries") or []
                if not isinstance(references, list) or not isinstance(inline, list) or any(not isinstance(p, str) for p in references):
                    raise ValueError("missing/invalid services")
                if [p.upper() for p in references] == ["ANY"] and not inline:
                    selectors.append({"role": "service", "kind": "any", "value": None, "negated": False})
                else:
                    if any(p.upper() == "ANY" for p in references):
                        raise ValueError("ANY with inline services requires explicit native interpretation")
                    values = [v for reference in references for v in resolve_service(reference)]
                    values.extend(v for entry in inline for v in service_entry(entry))
                    if not values or len(values) > 10000:
                        raise ValueError("service list missing or expansion limit exceeded")
                    selectors.extend({"role": "service", "kind": "service", "value": value, "negated": False} for value in values)
            except (ValueError, TypeError, KeyError) as error:
                unresolved.append("services: " + str(error))
            direction = rule.get("direction", "IN_OUT")
            if direction not in ("IN", "OUT", "IN_OUT"):
                unresolved.append("invalid workload traffic direction")
            disabled = rule.get("disabled", False)
            if not isinstance(disabled, bool):
                unresolved.append("invalid disabled state")
            action = {"ALLOW": "allow", "DROP": "deny", "REJECT": "deny"}.get(rule.get("action"), "unknown")
            if action == "unknown":
                unresolved.append("unsupported action/jump behavior")
            if rule.get("ip_protocol", "IPV4_IPV6") not in ("IPV4", "IPV6", "IPV4_IPV6"):
                unresolved.append("unsupported IP family")
            if policy.get("scheduler_path") or rule.get("profiles") not in (None, [], ["ANY"]) or rule.get("context_profiles"):
                unresolved.append("scheduled/L7 profile conditions require additional evidence")
            known = {"id", "resource_type", "path", "parent_path", "relative_path", "display_name", "description", "sequence_number",
                "source_groups", "destination_groups", "sources_excluded", "destinations_excluded", "services", "service_entries",
                "scope", "action", "rule_id", "disabled", "direction", "ip_protocol", "logged", "tag", "tags", "profiles",
                "context_profiles", "is_default", "marked_for_delete", "unique_id", "realization_id", "overridden", "remote_path",
                "owner_id", "origin_site_id", "_links", "_schema", "_self"}
            unresolved.extend("unsupported rule field: " + key for key in rule if key not in known and not key.startswith("_"))
            details = {"origin": "nsx_policy_dfw", "manager_id": metadata["manager_id"], "domain": metadata["domain"],
                "vm_external_id": vm_external_id, "vif_external_id": target["external_id"], "policy_path": path,
                "native_rule_id": rule.get("rule_id"), "category": policy.get("category"),
                "policy_sequence": policy.get("sequence_number"), "rule_sequence": rule.get("sequence_number"),
                "native_policy_stateful": policy.get("stateful"), "statefulness": statefulness,
                "native_scope": effective_scope, "scope_applies_to_selected_vif": scope_applies, "broad_dfw_scope": scope_broad,
                "native_policy_scope": policy_scope, "native_rule_scope": rule_scope,
                "native_group_types": {p: deepcopy(groups[p].get("group_type", [])) for field in (effective_scope, rule.get("source_groups"), rule.get("destination_groups"))
                    for p in (field if isinstance(field, list) else []) if isinstance(p, str) and p in groups},
                "direction": direction, "ip_protocol": rule.get("ip_protocol", "IPV4_IPV6"),
                "workload_condition": {"vif_external_id": target["external_id"], "direction": direction if direction in ("IN", "OUT", "IN_OUT") else "UNKNOWN",
                    "ip_protocol": rule.get("ip_protocol", "IPV4_IPV6") if rule.get("ip_protocol", "IPV4_IPV6") in ("IPV4", "IPV6", "IPV4_IPV6") else "UNKNOWN",
                    "complete": attachment_known and scope_applies is True and direction in ("IN", "OUT", "IN_OUT")
                        and rule.get("ip_protocol", "IPV4_IPV6") in ("IPV4", "IPV6", "IPV4_IPV6")},
                "selectors_complete": False, "translated_conditions_complete": not unresolved,
                "enforcement_realized": "unknown", "unresolved": unresolved, "native_rule": deepcopy(rule)}
            entries.append({"enforcement_point": point, "rule_set": "dfw:" + metadata["domain"], "default_action": "unknown",
                "rule_id": rule["path"], "position": len(entries) + 1, "action": action,
                "enabled": disabled is not True, "selectors": selectors, "details": details})
            findings.extend({"rule": rule["path"], "reason": reason} for reason in unresolved)
    selected_states = {r["details"]["native_policy_stateful"] if isinstance(r["details"]["native_policy_stateful"], bool) else None for r in entries}
    selected_statefulness = "stateful" if selected_states == {True} else "stateless" if selected_states == {False} else "unknown"
    for entry in entries:
        entry["details"]["statefulness"] = selected_statefulness
    if broad:
        findings.append({"vif": target["external_id"], "reason": "broad DFW Applied To increases per-vNIC policy footprint", "rules": broad})
    capacity = {"vif_external_id": target["external_id"], "vm_external_id": vm_external_id,
                "known_applicable_enabled_rules": applied, "broad_scope_enabled_rules": broad,
                "unknown_scope_enabled_rules": unknown_scope, "realized_rule_count": None,
                "limit": None, "status": "unknown", "reason": "version-specific validated capacity and realized counts not collected"}
    interfaces = [{"name": target["native"].get("device_name") or target["external_id"], "native_id": target["external_id"],
        "kind": "virtual", "addresses": target["addresses"], "config": {"origin": "nsx_vm_vif_inventory",
        "vm_external_id": vm_external_id, "vif_external_id": target["external_id"], "segment_port_path": port.get("path") if port else None,
        "attachment_verified": attachment_known, "dfw_realization": "unknown"}}]
    return {"policies": entries, "interfaces": interfaces, "target": target, "capacity": capacity,
        "native_groups": deepcopy(list(groups.values())),
        "coverage": "partial", "findings": findings,
        "limitations": ["VM/vNIC scope and observed IP membership do not prove realized DFW filters or host preparation",
            "VLAN/overlay transport alone does not establish or exclude DFW protection",
            "NIC exclusion lists, realized rule counts, cross-domain/federation, L2/L7/identity, NAT and routing remain unverified"]}


def translate_vm(metadata, collection, *, vm_external_id, vif_external_id=None):
    """Keep every selected VM vNIC in one policy/interface snapshot pair."""
    machines = [m for m in list_results(collection.get("virtual_machines")) if isinstance(m, dict) and m.get("external_id") == vm_external_id]
    if len(machines) != 1:
        raise ValueError("selected VM identity missing or ambiguous")
    aliases = {vm_external_id, machines[0].get("id")} - {None}
    identifiers = [v.get("external_id") for v in list_results(collection.get("vifs")) if isinstance(v, dict)
        and v.get("owner_vm_id") in aliases and (vif_external_id is None or v.get("external_id") == vif_external_id)]
    if not identifiers or any(not isinstance(v, str) or not v for v in identifiers):
        raise ValueError("selected VM has no associated native vNIC identity")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("duplicate native vNIC identity")
    results = [translate_policy(metadata, collection, vm_external_id=vm_external_id, vif_external_id=identifier)
               for identifier in sorted(identifiers)]
    return {"vm_external_id": vm_external_id, "policies": [r for s in results for r in s["policies"]],
        "interfaces": [i for s in results for i in s["interfaces"]], "targets": [s["target"] for s in results],
        "capacity": [s["capacity"] for s in results], "findings": [f for s in results for f in s["findings"]],
        "native_groups": results[0]["native_groups"], "coverage": "partial", "limitations": results[0]["limitations"]}


def normalized_submissions(metadata, collection, namespace, external_device_id, *, vm_external_id, vif_external_id=None):
    if any(not isinstance(v, str) or not v.strip() for v in (namespace, external_device_id)):
        raise ValueError("namespace and mapped VM device identity required")
    semantics = translate_vm(metadata, collection, vm_external_id=vm_external_id, vif_external_id=vif_external_id)
    return [{"source": {"namespace": namespace, "external_device_id": external_device_id},
        "adapter": {"name": "navis", "input_format": "normalized-json", "format_version": "1"},
        "data_type": kind, "collected_at": metadata["collected_at"], "completeness": "partial",
        "payload": {"entries": semantics[key]}} for kind, key in (("policy", "policies"), ("interface", "interfaces"))]
