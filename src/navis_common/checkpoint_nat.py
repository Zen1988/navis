"""Translate deterministic manual management NAT without guessing gateway stages."""
from copy import deepcopy
from ipaddress import ip_network


def translate_nat(raw, point, package_uid, object_for, resolve, targets):
    output, findings, seen = [], [], set()
    for rule in raw:
        key = rule.get("uid")
        if not isinstance(key, str) or not key or key in seen:
            raise ValueError("missing/duplicate NAT rule UID")
        seen.add(key)
        target = targets(rule.get("install-on"), policy_targets=True)
        if target is False:
            continue
        selectors, unresolved = [], []
        if target is None:
            unresolved.append("NAT installation target unresolved")
        for field, role in (("original-source", "source"), ("original-destination", "destination"), ("original-service", "service")):
            try:
                values = resolve(rule.get(field), role)
                selectors.extend({"role": role, "kind": kind, "value": value, "negated": False} for kind, value in values)
            except (ValueError, TypeError, KeyError) as error:
                unresolved.append(field + ": " + str(error))
        def original(obj):
            return obj.get("type") in ("Global", "Original") and obj.get("name") == "Original"
        changes = {}
        kind = "no_nat"
        try:
            if rule.get("auto-generated") is not False:
                raise ValueError("automatic NAT may combine source and destination rules; native combination semantics required")
            if str(rule.get("method", "")).lower() != "static":
                raise ValueError("hide/dynamic or unknown NAT method requires allocation evidence")
            for field, side in (("translated-source", "source"), ("translated-destination", "destination")):
                obj = object_for(rule.get(field))
                if original(obj):
                    continue
                values = resolve(obj, side)
                if len(values) != 1 or values[0][0] != "address" or ip_network(values[0][1]).num_addresses != 1:
                    raise ValueError("translated network/range requires offset-aware mapping")
                originals = [s for s in selectors if s["role"] == side]
                if len(originals) != 1 or originals[0]["kind"] != "address" or ip_network(originals[0]["value"]).num_addresses != 1:
                    raise ValueError("static translation requires original host evidence")
                if ip_network(originals[0]["value"]).version != ip_network(values[0][1]).version:
                    raise ValueError("cross-family NAT unsupported")
                changes[side] = {"address": str(ip_network(values[0][1]).network_address)}
            obj = object_for(rule.get("translated-service"))
            if not original(obj):
                values = resolve(obj, "service")
                originals = [s["value"] for s in selectors if s["role"] == "service" and s["kind"] == "service"]
                if len(values) != 1 or values[0][0] != "service" or len(originals) != 1:
                    raise ValueError("service translation requires explicit transport services")
                value = values[0][1]
                if value["protocol"] != originals[0]["protocol"] or value["destination_port_start"] != value["destination_port_end"] or value["source_port_start"] != 0 or value["source_port_end"] != 65535:
                    raise ValueError("unsupported translated service range/protocol/source port")
                changes.setdefault("destination", {})["port"] = value["destination_port_start"]
            if changes:
                kind = "combined" if len(changes) == 2 else next(iter(changes))
                translation = changes if kind == "combined" else changes[kind]
            else:
                translation = {}
        except (ValueError, TypeError, KeyError) as error:
            kind, translation = "unsupported", {}
            unresolved.append(str(error))
        enabled = rule.get("enabled")
        known = {"uid", "type", "domain", "name", "rule-number", "enabled", "original-source", "original-destination",
            "original-service", "translated-source", "translated-destination", "translated-service", "install-on", "method",
            "auto-generated", "comments", "meta-info", "original-source-negate", "original-destination-negate"}
        unresolved.extend("unsupported NAT field: " + k for k in rule if k not in known)
        if rule.get("original-source-negate") or rule.get("original-destination-negate"):
            unresolved.append("NAT address negation requires additional translation")
        if not isinstance(enabled, bool):
            unresolved.append("NAT enabled state unresolved")
        output.append({"enforcement_point": point, "rule_set": "nat:" + package_uid,
            "processing_stage": "checkpoint_management_nat_stage_unverified", "rule_id": key,
            "position": len(output) + 1, "enabled": enabled is not False,
            "translation_kind": kind, "translation": translation, "selectors": selectors,
            "details": {"origin": "checkpoint_management_nat", "package_uid": package_uid,
                "native_rule": deepcopy(rule), "selectors_complete": False, "packet_stage_verified": False,
                "translated_conditions_complete": not unresolved, "unresolved": unresolved}})
        findings.extend({"nat_rule": key, "reason": reason} for reason in unresolved)
    return output, findings
