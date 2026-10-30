"""Strict native XML and inherited-policy helpers for the PAN-OS adapter."""
import xml.etree.ElementTree as ET
from copy import deepcopy


def result_element(xml, tag):
    if not isinstance(xml, str) or len(xml) > 32 * 1024 * 1024 or "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
        raise ValueError("unsupported or oversized XML")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise ValueError("invalid PAN-OS XML") from error
    if root.tag == "response":
        if root.get("status") != "success":
            raise ValueError("PAN-OS API did not report success")
        nodes = root.findall("result/" + tag) if tag else root.findall("result")
    else:
        nodes = [root] if root.tag == tag else []
    if len(nodes) != 1:
        raise ValueError("expected exactly one " + (tag or "result") + " element")
    return nodes[0]


def inherited_scopes(config, local, serial, vsys, *, pushed_xml=None, panorama_xml=None, hierarchy_xml=None):
    """Return ancestor scopes from native pushed config or Panorama hierarchy.

    Pushed data is preferred because the firewall has already resolved hierarchy
    and object precedence. Never combine two inherited sources into duplicate rules.
    """
    if pushed_xml is not None and panorama_xml is not None:
        raise ValueError("choose pushed config or Panorama hierarchy, not both")
    if pushed_xml is not None:
        pushed = result_element(pushed_xml, "panorama")
    else:
        pushed = config.find("panorama") if panorama_xml is None else None
    if pushed is not None:
        scopes = [n for n in pushed.findall("vsys/entry") if n.get("name") == vsys]
        if len(scopes) != 1:
            raise ValueError("pushed VSYS missing or ambiguous")
        shared = pushed.find("shared")
        return [("pushed-shared", shared)] * (shared is not None) + [("pushed:" + vsys, scopes[0])], "firewall_pushed"
    if panorama_xml is None:
        return [], "local_only"
    panorama = result_element(panorama_xml, "config")
    if hierarchy_xml is None:
        raise ValueError("Panorama config requires native dg-hierarchy evidence")
    hierarchy = result_element(hierarchy_xml, "dg-hierarchy")
    parents = {}
    def visit(node, parent=None, depth=0):
        if depth > 64:
            raise ValueError("device-group hierarchy too deep")
        for group in node.findall("dg"):
            name = group.get("name")
            if not name or name in parents:
                raise ValueError("duplicate/missing device group in hierarchy")
            parents[name] = parent
            visit(group, name, depth + 1)
    visit(hierarchy)
    groups = {}
    selected = []
    for group in panorama.findall("devices/entry/device-group/entry"):
        name = group.get("name")
        if not name or name in groups:
            raise ValueError("duplicate/missing device group in config")
        groups[name] = group
        for device in group.findall("devices/entry"):
            systems = device.findall("vsys/entry")
            if device.get("name") == serial and (any(v.get("name") == vsys for v in systems) or not systems and vsys == "vsys1"):
                selected.append(name)
    if len(selected) != 1:
        raise ValueError("firewall/VSYS device-group membership missing or ambiguous")
    chain, current = [], selected[0]
    while current is not None:
        if current in chain or current not in parents or current not in groups:
            raise ValueError("incomplete or cyclic device-group ancestry")
        chain.append(current)
        current = parents[current]
    shared = panorama.find("shared")
    scopes = [("panorama-shared", shared)] if shared is not None else []
    scopes.extend(("device-group:" + name, groups[name]) for name in reversed(chain))
    # Object precedence can be reversed by Panorama. Instead of guessing its
    # setting, conflicting definitions are unresolved unless pushed evidence is used.
    return scopes, "panorama_hierarchy"


def ordered_rules(ancestors, local, kind):
    sources = [(name, "pre-rulebase", scope) for name, scope in ancestors]
    sources.append(("local", "rulebase", local))
    sources.extend((name, "post-rulebase", scope) for name, scope in reversed(ancestors))
    output = []
    for origin, phase, scope in sources:
        seen = set()
        for rule in scope.findall(phase + "/" + kind + "/rules/entry"):
            name = rule.get("name")
            if not name or name in seen:
                raise ValueError("missing or duplicate " + kind + " rule name in scope")
            seen.add(name)
            output.append((rule, origin, phase))
    return output


def default_security_rules(ancestors, local):
    """Resolve documented zone defaults and lowest-scope native overrides."""
    output = []
    for name, relation, action in (("intrazone-default", "intrazone", "allow"),
                                   ("interzone-default", "interzone", "deny")):
        rule = ET.Element("entry", name=name)
        for field in ("from", "to", "source", "destination", "application", "service"):
            ET.SubElement(ET.SubElement(rule, field), "member").text = "any"
        ET.SubElement(rule, "rule-type").text = relation
        ET.SubElement(rule, "action").text = action
        origin = "builtin-default"
        for label, scope in [*ancestors, ("local", local)]:
            overrides = [r for r in scope.findall("rulebase/default-security-rules/rules/entry")
                         + scope.findall("default-security-rules/rules/entry") if r.get("name") == name]
            if len(overrides) > 1:
                raise ValueError("duplicate default rule override")
            if overrides:
                origin = label
                for child in overrides[0]:
                    for old in rule.findall(child.tag):
                        rule.remove(old)
                    rule.append(deepcopy(child))
                rule.attrib.update(overrides[0].attrib)
        output.append((rule, "default:" + origin, "default-security-rules"))
    return output


def target_match(rule, serial, vsys):
    """True/False for explicit serial/VSYS targets, None for unknown extensions."""
    target = rule.find("target")
    if target is None:
        return True
    if any(c.tag not in ("devices", "negate") for c in target):
        return None
    negate = target.findtext("negate", "no")
    if negate not in ("yes", "no"):
        return None
    devices = target.findall("devices/entry")
    if any(not d.get("name") for d in devices):
        return None
    match = not devices or any(d.get("name") == serial and
        (d.find("vsys") is None or any(v.get("name") == vsys for v in d.findall("vsys/entry"))) for d in devices)
    return not match if negate == "yes" else match
