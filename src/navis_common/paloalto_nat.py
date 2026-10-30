"""Translate ordered PAN-OS NAT rules without inventing dynamic allocations."""
from ipaddress import ip_address, ip_network
import json
import xml.etree.ElementTree as ET

from .paloalto_xml import target_match
from .policy_pipeline import ORIGINAL_ADDRESS_STAGE


def translate_nat(rules, point, metadata, vsys, selectors_for, resolve_address):
    entries, findings = [], []
    for rule, origin, phase in rules:
        targeted = target_match(rule, metadata["serial"], vsys)
        if targeted is False:
            continue
        selectors, unresolved = selectors_for(rule, nat=True)
        if targeted is None:
            unresolved.append("NAT target unresolved")
        translation = {}
        kind = "no_nat"
        def host(text):
            values = resolve_address(text or "")
            if len(values) != 1 or ip_network(values[0]).num_addresses != 1:
                raise ValueError("translation requires one host address")
            return str(ip_address(ip_network(values[0]).network_address))
        source = rule.find("source-translation")
        destination = rule.find("destination-translation")
        try:
            if source is not None:
                modes = list(source)
                if len(modes) != 1:
                    raise ValueError("ambiguous source translation mode")
                mode = modes[0]
                if mode.tag == "static-ip":
                    translation["source"] = {"address": host(mode.findtext("translated-address"))}
                    originals = [s for s in selectors if s["role"] == "source"]
                    if len(originals) != 1 or originals[0]["kind"] != "address" or ip_network(originals[0]["value"]).num_addresses != 1:
                        raise ValueError("static source NAT requires an original host for deterministic host translation")
                    if mode.findtext("bi-directional", "no") != "no":
                        unresolved.append("bidirectional static NAT reverse mapping requires explicit expansion")
                else:
                    # Preserve pool/interface allocation semantics as native
                    # evidence; never select an arbitrary pool member or port.
                    raise ValueError("runtime source NAT allocation required: " + mode.tag)
            if destination is not None:
                translation["destination"] = {}
                if destination.findtext("translated-address"):
                    translation["destination"]["address"] = host(destination.findtext("translated-address"))
                port = destination.findtext("translated-port")
                if port:
                    if not port.isdigit() or not 0 <= int(port) <= 65535:
                        raise ValueError("invalid translated destination port")
                    translation["destination"]["port"] = int(port)
                if not translation["destination"]:
                    raise ValueError("destination translation missing address and port")
            if translation:
                kind = "combined" if len(translation) == 2 else next(iter(translation))
                if kind != "combined":
                    translation = translation[kind]
        except (ValueError, TypeError) as error:
            kind, translation = "unsupported", {}
            unresolved.append(str(error))
        known = {"from", "to", "source", "destination", "service", "source-translation", "destination-translation",
                 "disabled", "description", "tag", "target", "to-interface", "nat-type", "active-active-device-binding",
                 "group-tag"}
        unresolved.extend("unsupported NAT field: " + child.tag for child in rule if child.tag not in known)
        if rule.findtext("nat-type", "ipv4") != "ipv4":
            unresolved.append("non-IPv4 NAT type requires additional translation semantics")
        if rule.find("active-active-device-binding") is not None:
            unresolved.append("active/active HA binding requires runtime state")
        interface = rule.findtext("to-interface", "any")
        if interface != "any":
            selectors.append({"role": "interface", "kind": "interface", "value": interface, "negated": False})
        disabled = rule.findtext("disabled", "no")
        if disabled not in ("yes", "no"):
            unresolved.append("invalid NAT disabled state")
        name = rule.get("name")
        rule_id = name if origin == "local" else json.dumps([origin, phase, name], separators=(",", ":"))
        entries.append({"enforcement_point": point, "rule_set": "nat:" + vsys,
            "processing_stage": ORIGINAL_ADDRESS_STAGE,
            "rule_id": rule_id, "position": len(entries) + 1, "enabled": disabled != "yes",
            "translation_kind": kind, "translation": translation, "selectors": selectors,
            "details": {"origin": "paloalto_nat", "native_name": name, "native_uuid": rule.get("uuid"),
                "scope": origin, "phase": phase, "selectors_complete": False,
                "translated_conditions_complete": not unresolved,
                "policy_address_basis": "original", "policy_zone_basis": "post_nat",
                "nat_address_basis": "original", "nat_zone_basis": "pre_nat",
                "unresolved": unresolved, "native_xml": ET.tostring(rule, encoding="unicode")}})
        findings.extend({"nat_rule": name, "reason": reason} for reason in unresolved)
    return entries, findings
