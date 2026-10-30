"""Translate App-ID names/groups and collected application-default ports."""
from .paloalto_xml import result_element


def application_condition(rule, objects, catalog, ports, filters=()):
    names = [(n.text or "").strip() for n in rule.findall("application/member")]
    unresolved = []
    def expand(name, chain=()):
        if name in filters:
            raise ValueError("dynamic application filter: " + name)
        if name in chain or len(chain) >= 64:
            raise ValueError("cyclic or excessively deep application group")
        node = objects.get(name)
        if node is None:
            node = catalog.get(name)
        if node is not None and (node.find("members") is not None or node.find("functions") is not None):
            path = "members/member" if node.find("members") is not None else "functions/member"
            members = [(n.text or "").strip() for n in node.findall(path)]
            if not members:
                raise ValueError("empty application group: " + name)
            result = []
            for member in members:
                result.extend(expand(member, (*chain, name)))
                if len(result) > 10000:
                    raise ValueError("application expansion limit exceeded")
            return result
        if node is not None and (node.find("filter") is not None or node.tag == "application-filter"):
            raise ValueError("dynamic application filter: " + name)
        if not name or name == "any":
            raise ValueError("invalid application alternative")
        if node is None:
            raise ValueError("application definition unavailable: " + name)
        # A collected leaf definition distinguishes exact App-ID identity from
        # an application container that needs expansion into its functions.
        return [name]
    applications = None
    if names != ["any"]:
        try:
            if not names:
                raise ValueError("missing application condition")
            applications = sorted(set(n for name in names for n in expand(name)))
        except ValueError as error:
            unresolved.append(str(error))
    default = [(n.text or "").strip() for n in rule.findall("service/member")] == ["application-default"]
    services = []
    incomplete = []
    if default:
        selected = applications if applications is not None else list(catalog)
        if not selected:
            unresolved.append("application-default catalog unavailable")
        for name in selected:
            node = catalog.get(name)
            native = node.findall("default/port/member") if node is not None else []
            app_services = []
            try:
                if not native:
                    raise ValueError("application default ports unavailable")
                for member in native:
                    expression = (member.text or "").split("/", 1)
                    if len(expression) != 2 or expression[0] not in ("tcp", "udp"):
                        raise ValueError("unsupported application default protocol")
                    # Dynamic port negotiation requires runtime evidence; it is
                    # not equivalent to allowing every transport port.
                    if expression[1] == "dynamic":
                        raise ValueError("dynamic application default ports")
                    ranges = ports(expression[1])
                    app_services.extend({"application": name, "protocol": expression[0], "start": s, "end": e} for s, e in ranges)
                services.extend(app_services)
            except ValueError:
                incomplete.append(name)
        if incomplete:
            unresolved.append("application-default definitions incomplete: " + ", ".join(incomplete))
    return {"applications": applications, "any_application": names == ["any"],
            "application_default": default, "default_services": services,
            "incomplete_applications": incomplete, "complete": not unresolved}, unresolved


def catalog_objects(xml):
    if xml is None:
        return {}
    root = result_element(xml, "application")
    result = {}
    for node in root.findall("entry"):
        name = node.get("name")
        if not name or name in result:
            raise ValueError("duplicate/missing predefined application name")
        result[name] = node
    return result
