"""Collector-side Check Point Management API translation, scoped by UID.

Management configuration never establishes installed policy, gateway routing,
HA state, implied rules or runtime inspection/session behavior.
"""
from copy import deepcopy
from ipaddress import ip_address, ip_network, summarize_address_range
import re
from .checkpoint_nat import translate_nat


def uid(value):
    if isinstance(value, str) and value:
        return value
    if isinstance(value, dict) and isinstance(value.get("uid"), str) and value["uid"]:
        return value["uid"]
    raise ValueError("native object UID required")


def pages(pages, key):
    """Verify native pagination intervals; never silently accept truncation."""
    if not isinstance(pages, list) or not pages:
        raise ValueError("nonempty native response pages required: " + key)
    total, cursor, output = None, 0, []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(page.get(key), list):
            raise ValueError("invalid API response: " + key)
        reported = page.get("total")
        if not isinstance(reported, int) or isinstance(reported, bool) or reported < 0 or total is not None and total != reported:
            raise ValueError("missing or inconsistent pagination total")
        total = reported
        values = page[key]
        if not values:
            continue  # The bounded collector may request empty trailing pages.
        first, last = page.get("from"), page.get("to")
        if any(not isinstance(x, int) or isinstance(x, bool) for x in (first, last)) or first != cursor + 1 or not first <= last <= total:
            raise ValueError("missing, overlapping or out-of-order native pages")
        if key != "rulebase" and len(values) != last - first + 1:
            raise ValueError("object page length disagrees with native interval")
        cursor = last
        output.extend(values)
    if cursor != total:
        raise ValueError("native collection is truncated: " + key)
    return output


def flatten(rulebase, kind="access-rule", depth=0):
    if depth >= 64:
        raise ValueError("section nesting limit exceeded")
    result = []
    for row in rulebase:
        if not isinstance(row, dict):
            raise ValueError("invalid rulebase row")
        if row.get("type") in ("access-section", "nat-section"):
            if not isinstance(row.get("rulebase"), list):
                raise ValueError("section children missing")
            result.extend(flatten(row["rulebase"], kind, depth + 1))
        elif row.get("type") == kind:
            result.append(row)
        else:
            raise ValueError("unsupported rulebase row type")
        if len(result) > 100000:
            raise ValueError("rule limit exceeded")
    return result


def _ports(value):
    if not isinstance(value, str):
        raise ValueError("service port expression missing")
    match = re.fullmatch(r"\s*(>=|<=|>|<)?\s*(\d+)(?:\s*-\s*(\d+))?\s*", value)
    if not match:
        raise ValueError("unsupported service port expression")
    operator, first, last = match.groups()
    first = int(first)
    if operator and last:
        raise ValueError("ambiguous service port expression")
    start, end = first, int(last) if last is not None else first
    if operator in (">", ">="):
        start, end = first + (operator == ">"), 65535
    elif operator in ("<", "<="):
        start, end = 0, first - (operator == "<")
    if not 0 <= start <= end <= 65535:
        raise ValueError("invalid service port range")
    return start, end


def translate_management(metadata, collection, *, package_uid, gateway_uid):
    """Resolve one management/domain/package/gateway's ordered access layers.

    collection contains paginated objects/gateways/packages, optional full package
    details, full layer objects and per-layer show-access-rulebase response pages.
    """
    if not isinstance(metadata, dict) or any(not isinstance(metadata.get(k), str) or not metadata[k].strip()
        for k in ("management_id", "domain_uid", "collected_at")):
        raise ValueError("management_id, native domain_uid and collected_at required")
    if not isinstance(collection, dict):
        raise ValueError("management collection must be an object")
    package_uid, gateway_uid = uid(package_uid), uid(gateway_uid)
    domain = metadata["domain_uid"]
    objects = {}
    def remember(obj):
        key = uid(obj)
        old = objects.get(key, {})
        old_domain, new_domain = old.get("domain", {}).get("uid"), obj.get("domain", {}).get("uid")
        if old_domain and new_domain and old_domain != new_domain:
            raise ValueError("conflicting domain ownership for native UID: " + key)
        semantic = {"type", "name", "ipv4-address", "ipv6-address", "subnet4", "subnet6", "mask-length4",
                    "mask-length6", "subnet-mask", "members", "include", "except", "port", "source-port"}
        def comparable(field, value):
            return sorted(uid(v) for v in value) if field == "members" and isinstance(value, list) else value
        if any(k in old and k in obj and comparable(k, old[k]) != comparable(k, obj[k]) for k in semantic):
            raise ValueError("conflicting native object evidence: " + key)
        objects[key] = {**old, **deepcopy(obj)}
    for obj in pages(collection.get("objects"), "objects"):
        remember(obj)
    gateways = pages(collection.get("gateways"), "objects")
    for gateway in gateways:
        remember(gateway)
    packages = pages(collection.get("packages"), "packages")
    selected = [p for p in packages if uid(p) == package_uid]
    if len(selected) != 1:
        raise ValueError("package UID missing or ambiguous")
    package = collection.get("package_details", {}).get(package_uid, selected[0])
    if uid(package) != package_uid or package.get("domain", {}).get("uid") != domain:
        raise ValueError("package/domain identity not established")
    selected = [g for g in gateways if uid(g) == gateway_uid]
    if len(selected) != 1 or selected[0].get("domain", {}).get("uid") != domain:
        raise ValueError("gateway/domain identity not established")
    gateway = selected[0]
    if gateway.get("type") not in ("simple-gateway", "simple-cluster", "CpmiGatewayCluster", "CpmiVsClusterNetobj", "CpmiHostCkp"):
        raise ValueError("selected object is not a supported gateway/cluster type")
    target_uids = {gateway_uid}
    for candidate in gateways:
        if candidate.get("domain", {}).get("uid") == domain and any(uid(m) == gateway_uid for m in candidate.get("cluster-members", [])):
            target_uids.add(uid(candidate))
    def targets(value, policy_targets=False):
        if value == "all":
            return True
        if not isinstance(value, list) or not value:
            return None
        unknown = False
        for ref in value:
            key = uid(ref)
            obj = objects.get(key, ref if isinstance(ref, dict) else {})
            if key in target_uids:
                return True
            if policy_targets and obj.get("type") == "Global" and obj.get("name") == "Policy Targets":
                return True
            if not obj or obj.get("type") not in ("simple-gateway", "simple-cluster", "CpmiGatewayCluster", "CpmiVsClusterNetobj", "CpmiHostCkp"):
                unknown = True
        return None if unknown else False
    package_target = targets(package.get("installation-targets"))
    if package_target is False:
        raise ValueError("package does not target selected gateway")
    layer_objects = collection.get("layers")
    rulebase_pages = collection.get("rulebases")
    if not isinstance(layer_objects, list) or not isinstance(rulebase_pages, dict):
        raise ValueError("layer objects and rulebases required")
    layers = {}
    for layer in layer_objects:
        key = uid(layer)
        if key in layers:
            raise ValueError("duplicate layer UID")
        layers[key] = layer
        for page in rulebase_pages.get(key, []):
            if page.get("uid") != key:
                raise ValueError("rulebase page/layer identity mismatch")
            for obj in page.get("objects-dictionary", []):
                remember(obj)
    for page in collection.get("nat", []):
        for obj in page.get("objects-dictionary", []):
            remember(obj)
    ordered = package.get("access-layers")
    if not isinstance(ordered, list) or not ordered:
        raise ValueError("full package ordered access-layers required")
    ordered = [uid(layer) for layer in ordered]
    if len(set(ordered)) != len(ordered):
        raise ValueError("duplicate ordered layer")
    point = ":".join(("checkpoint", metadata["management_id"], domain, gateway_uid))

    def object_for(ref):
        key = uid(ref)
        if isinstance(ref, dict):
            remember(ref)
        if key not in objects:
            raise ValueError("referenced object not collected: " + key)
        obj = objects[key]
        owner = obj.get("domain", {}).get("uid")
        if owner and owner != domain and obj.get("domain", {}).get("name") != "Check Point Data":
            raise ValueError("cross-domain object association unresolved: " + key)
        return obj

    def resolve(ref, role, stack=()):
        obj = object_for(ref)
        key, kind = obj["uid"], obj.get("type")
        if key in stack or len(stack) >= 64:
            raise ValueError("cyclic or excessively deep object group")
        if kind == "CpmiAnyObject":
            return [("any", None)]
        if kind in ("group", "service-group"):
            if not isinstance(obj.get("members"), list) or not obj["members"]:
                raise ValueError("group members missing or empty")
            values = []
            for member in obj["members"]:
                values.extend(resolve(member, role, (*stack, key)))
                if len(values) > 10000:
                    raise ValueError("group expansion limit exceeded")
            if any(k == "any" for k, _ in values) and len(values) > 1:
                raise ValueError("any mixed with group alternatives")
            return values
        if role in ("source", "destination"):
            if kind == "host":
                values = [str(ip_network(str(ip_address(obj[field])), strict=False)) for field in ("ipv4-address", "ipv6-address") if obj.get(field)]
            elif kind == "network":
                values = []
                for address, mask in (("subnet4", "mask-length4"), ("subnet6", "mask-length6")):
                    if obj.get(address):
                        prefix = obj.get(mask, obj.get("subnet-mask") if address == "subnet4" else None)
                        if prefix is None:
                            raise ValueError("network prefix missing")
                        values.append(str(ip_network(str(obj[address]) + "/" + str(prefix), strict=False)))
            elif kind == "address-range":
                values = []
                for family in ("ipv4", "ipv6"):
                    if obj.get(family + "-address-first"):
                        values.extend(str(p) for p in summarize_address_range(ip_address(obj[family + "-address-first"]), ip_address(obj[family + "-address-last"])))
            else:
                raise ValueError("unsupported/dynamic address object: " + str(kind))
            if not values:
                raise ValueError("address evidence missing")
            return [("address", value) for value in values]
        if kind in ("service-tcp", "service-udp"):
            if obj.get("protocol") not in (None, "", "None", "none"):
                raise ValueError("service protocol inspection requires runtime evidence")
            start, end = _ports(obj.get("port"))
            source = _ports(obj["source-port"]) if obj.get("source-port") else (0, 65535)
            return [("service", {"protocol": kind[8:], "destination_port_start": start, "destination_port_end": end,
                                  "source_port_start": source[0], "source_port_end": source[1]})]
        raise ValueError("unsupported service/application: " + str(kind))

    findings, translated = [], {}
    expanded_rules = 0
    def layer_rules(layer_uid, stack=()):
        nonlocal expanded_rules
        if layer_uid in stack or len(stack) >= 32:
            raise ValueError("cyclic or excessively deep inline layer")
        if layer_uid not in layers or layer_uid not in rulebase_pages:
            raise ValueError("referenced layer not collected: " + layer_uid)
        layer = layers[layer_uid]
        if layer.get("domain", {}).get("uid") not in (None, domain):
            raise ValueError("cross-domain access layer")
        raw = flatten(pages(rulebase_pages[layer_uid], "rulebase"))
        seen, entries = set(), []
        for rule in raw:
            expanded_rules += 1
            if expanded_rules > 100000:
                raise ValueError("inline/ordered rule expansion limit exceeded")
            key = uid(rule)
            if key in seen:
                raise ValueError("duplicate access-rule UID")
            seen.add(key)
            target = targets(rule.get("install-on"), policy_targets=True)
            if target is False:
                continue
            unresolved, selectors = [], []
            if package_target is None or target is None:
                unresolved.append("gateway installation target unresolved")
            for field, role in (("source", "source"), ("destination", "destination"), ("service", "service")):
                references = rule.get(field)
                negate = rule.get(field + "-negate", False)
                if not isinstance(negate, bool):
                    unresolved.append("invalid negation: " + field)
                    continue
                try:
                    if not isinstance(references, list) or not references:
                        raise ValueError("selector references missing")
                    values = []
                    for reference in references:
                        values.extend(resolve(reference, role))
                        if len(values) > 10000:
                            raise ValueError("selector expansion limit exceeded")
                    if any(k == "any" for k, _ in values) and (negate or len(values) > 1):
                        raise ValueError("ambiguous or negated any")
                    selectors.extend({"role": role, "kind": kind, "value": value, "negated": negate} for kind, value in values)
                except (ValueError, TypeError, KeyError) as error:
                    unresolved.append(field + ": " + str(error))
            for field in ("vpn", "time", "content"):
                try:
                    if not isinstance(rule.get(field), list) or not rule[field] or not all(object_for(r).get("type") == "CpmiAnyObject" for r in rule[field]):
                        unresolved.append("unsupported or missing condition: " + field)
                except ValueError:
                    unresolved.append("unresolved condition: " + field)
            if layer.get("dynamic-layer"):
                unresolved.append("dynamic layer requires gateway runtime rules")
            enabled = rule.get("enabled")
            if not isinstance(enabled, bool):
                unresolved.append("enabled state unresolved")
            action = "unknown"
            try:
                native_action = object_for(rule.get("action"))
                if native_action.get("type") == "RulebaseAction":
                    action = {"accept": "allow", "drop": "deny", "reject": "deny"}.get(str(native_action.get("name", "")).lower(), "unknown")
            except ValueError:
                native_action = None
            details = {"origin": "checkpoint_management", "management_id": metadata["management_id"], "domain_uid": domain,
                "package_uid": package_uid, "gateway_uid": gateway_uid, "layer_uid": layer_uid,
                "native_rule_number": rule.get("rule-number"), "native_name": rule.get("name"),
                "native_rule": deepcopy(rule), "statefulness": "stateful", "selectors_complete": False}
            inline = rule.get("inline-layer")
            if inline:
                try:
                    children, default = layer_rules(uid(inline), (*stack, layer_uid))
                    details.update(inline_rules=children, inline_default=default, inline_complete=False,
                                   inline_layer_uid=uid(inline))
                except ValueError as error:
                    unresolved.append(str(error))
                action = "unknown"  # The inline result, not parent Accept, decides.
            elif action == "unknown":
                unresolved.append("unsupported or unresolved action")
            # Unrecognized native fields may add match semantics. Metadata and
            # known inspection settings are retained without claiming coverage.
            known = {"uid", "name", "type", "domain", "rule-number", "enabled", "source", "destination", "service",
                "source-negate", "destination-negate", "service-negate", "vpn", "time", "content", "action", "inline-layer",
                "install-on", "track", "comments", "meta-info", "custom-fields", "user-check", "action-settings", "hits",
                "content-direction", "content-negate", "service-resource"}
            unresolved.extend("unsupported rule field: " + k for k in rule if k not in known)
            if rule.get("content-negate") or rule.get("service-resource"):
                unresolved.append("content negation or service resource requires runtime evaluation")
            details.update(unresolved=unresolved, translated_conditions_complete=not unresolved)
            entries.append({"enforcement_point": point, "rule_set": ":".join(("access", package_uid, layer_uid)),
                "default_action": "unknown", "rule_id": key, "position": len(entries) + 1, "enabled": enabled is not False,
                "action": action, "selectors": selectors, "details": details})
            findings.extend({"layer": layer_uid, "rule": key, "reason": reason} for reason in unresolved)
        default = {"accept": "allow", "drop": "deny"}.get(str(layer.get("implicit-cleanup-action", "")).lower(), "unknown")
        if layer.get("dynamic-layer"):
            default = "unknown"
        for entry in entries:
            entry["default_action"] = default
        expanded_rules += 1
        if expanded_rules > 100000:
            raise ValueError("inline/ordered rule expansion limit exceeded")
        entries.append({"enforcement_point": point, "rule_set": ":".join(("access", package_uid, layer_uid)),
            "default_action": default, "rule_id": "implicit-cleanup:" + layer_uid, "position": len(entries) + 1,
            "enabled": True, "action": default,
            "selectors": [{"role": role, "kind": "any", "value": None, "negated": False} for role in ("source", "destination", "service")],
            "details": {"origin": "checkpoint_management", "statefulness": "stateful", "selectors_complete": False,
                "management_id": metadata["management_id"], "domain_uid": domain, "package_uid": package_uid,
                "gateway_uid": gateway_uid, "layer_uid": layer_uid, "derived_cleanup": True,
                "translated_conditions_complete": default != "unknown", "native_layer": deepcopy(layer),
                "unresolved": [] if default != "unknown" else ["implicit cleanup action unresolved"]}})
        return entries, default

    policies = []
    for position, layer_uid in enumerate(ordered, 1):
        entries, default = layer_rules(layer_uid)
        for entry in entries:
            entry["details"]["ordered_layer_position"] = position
        policies.extend(entries)
        translated[layer_uid] = {"rules": entries, "default_action": default, "complete": False}
    nat = []
    if "nat" in collection:
        def nat_targets(value, policy_targets=False):
            result = targets(value, policy_targets)
            return None if result is True and package_target is None else result
        nat, nat_findings = translate_nat(flatten(pages(collection["nat"], "rulebase"), "nat-rule"), point,
            package_uid, object_for, resolve, nat_targets)
        findings.extend(nat_findings)
    return {"management_id": metadata["management_id"], "domain_uid": domain, "package_uid": package_uid,
        "gateway_uid": gateway_uid, "collected_at": metadata["collected_at"], "ordered_layers": ordered,
        "layers": translated, "policies": policies, "nat": nat, "findings": findings, "coverage": "partial",
        "limitations": ["management policy is not verified installed gateway policy",
            "implied/global rules, application inspection, identity, VPN, time and dynamic objects require additional evidence",
            "automatic/hide NAT and packet stages, gateway routing/interfaces, cluster/VSX runtime state and sessions remain unverified"]}


def normalized_submissions(metadata, collection, namespace, external_device_id, *, package_uid, gateway_uid):
    policy = normalized_submission(metadata, collection, namespace, external_device_id, package_uid=package_uid, gateway_uid=gateway_uid)
    result = [policy]
    if "nat" in collection:
        semantics = translate_management(metadata, collection, package_uid=package_uid, gateway_uid=gateway_uid)
        result.append({**policy, "data_type": "nat", "payload": {"entries": semantics["nat"]}})
    return result


def normalized_submission(metadata, collection, namespace, external_device_id, *, package_uid, gateway_uid):
    if any(not isinstance(v, str) or not v.strip() for v in (namespace, external_device_id)):
        raise ValueError("namespace and explicit mapped gateway identity required")
    semantics = translate_management(metadata, collection, package_uid=package_uid, gateway_uid=gateway_uid)
    return {"source": {"namespace": namespace, "external_device_id": external_device_id},
        "adapter": {"name": "navis", "input_format": "normalized-json", "format_version": "1"},
        "data_type": "policy", "collected_at": metadata["collected_at"], "completeness": "partial",
        "payload": {"entries": semantics["policies"]}}
