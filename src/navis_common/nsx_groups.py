"""Separate NSX packet membership from VM/vNIC Applied To membership."""
from ipaddress import ip_address, ip_network, summarize_address_range
from .nsx_inventory import list_results


def address_prefixes(value):
    if not isinstance(value, str):
        raise ValueError("NSX address must be a host, subnet or range")
    if "-" in value:
        first, last = value.split("-", 1)
        return [str(p) for p in summarize_address_range(ip_address(first.strip()), ip_address(last.strip()))]
    return [str(ip_network(value, strict=False))]


class GroupResolver:
    def __init__(self, groups, collection, machines, vifs, target):
        self.groups, self.collection, self.machines, self.vifs, self.target = groups, collection, machines, vifs, target
        self.aliases = {alias: key for key, vm in machines.items() for alias in (key, vm.get("id")) if alias}
        self.ports = {p["path"]: p for pages in collection.get("segment_ports", {}).values() for p in list_results(pages)}
        self.cache = {}
        self.vifs_by_vm = {}
        for vif in vifs.values():
            self.vifs_by_vm.setdefault(vif["vm_external_id"], []).append(vif)

    def vm_members(self, path):
        pages = self.collection.get("group_virtual_machines", {}).get(path)
        if pages is None:
            raise ValueError("resolved VM group membership not collected")
        result = set()
        for member in list_results(pages):
            if not isinstance(member, dict) or member.get("resource_type") not in (None, "VirtualMachine", "RealizedVirtualMachine"):
                raise ValueError("unexpected resolved VM member type")
            key = self.aliases.get(member.get("external_id")) or self.aliases.get(member.get("id"))
            if key is None:
                raise ValueError("VM member identity not associated with native inventory")
            result.add(key)
        return result

    def addresses_for_vms(self, keys):
        addresses = set()
        for key in keys:
            members = self.vifs_by_vm.get(key, [])
            if not members or any(not v["addresses"] for v in members):
                raise ValueError("VM-to-vNIC IP bindings incomplete")
            addresses.update(p for v in members for ip in v["addresses"] for p in address_prefixes(ip))
            if len(addresses) > 10000:
                raise ValueError("VM/IP selector expansion limit exceeded")
        return addresses

    def workload_expression(self, expression):
        if not isinstance(expression, list) or not expression:
            return False
        for node in expression:
            if not isinstance(node, dict):
                return False
            kind = node.get("resource_type")
            if kind == "Condition" and node.get("member_type") == "VirtualMachine":
                continue
            if kind == "ConjunctionOperator" and node.get("conjunction_operator") in ("AND", "OR"):
                continue
            if kind == "NestedExpression" and self.workload_expression(node.get("expressions")):
                continue
            return False
        return True

    def resolve(self, path, *, scope=False, stack=()):
        key = (path, scope)
        if key in self.cache:
            return self.cache[key]
        result = self._resolve(path, scope=scope, stack=stack)
        self.cache[key] = result
        return result

    def _resolve(self, path, *, scope=False, stack=()):
        if path in stack or len(stack) >= 64:
            raise ValueError("cyclic or excessively deep NSX group")
        if path not in self.groups:
            if scope:
                raise ValueError("Applied To must resolve to a workload group")
            return set(address_prefixes(path))
        group = self.groups[path]
        if group.get("marked_for_delete") or group.get("extended_expression") or group.get("state") in ("FAILURE", "IN_PROGRESS"):
            raise ValueError("deleted, pending, failed or extended group semantics unresolved")
        expression = group.get("expression")
        declared = group.get("group_type", [])
        if not isinstance(declared, list) or len(declared) > 1:
            raise ValueError("invalid native group type declaration")
        if declared:
            if declared != ["IPAddress"]:
                raise ValueError("unsupported typed group: " + str(declared))
            if scope:
                raise ValueError("IP-only typed group cannot establish Applied To vNIC scope")
            if not isinstance(expression, list) or any(not isinstance(n, dict) or n.get("resource_type") not in ("IPAddressExpression", "ConjunctionOperator") for n in expression):
                raise ValueError("IP-only group contains incompatible workload members")
        if self.workload_expression(expression):
            keys = self.vm_members(path)
            return self.target["vm_external_id"] in keys if scope else self.addresses_for_vms(keys)
        if not isinstance(expression, list) or not expression:
            raise ValueError("group expression missing")
        values = []
        expect_operand = True
        for node in expression:
            if not isinstance(node, dict):
                raise ValueError("invalid native group expression")
            kind = node.get("resource_type")
            if not expect_operand:
                if kind != "ConjunctionOperator" or node.get("conjunction_operator") != "OR":
                    raise ValueError("mixed/static AND group expression unsupported")
                expect_operand = True
                continue
            if kind == "IPAddressExpression":
                if scope:
                    raise ValueError("IP member or mixed IP/workload expression cannot establish Applied To vNIC scope")
                addresses = node.get("ip_addresses")
                if not isinstance(addresses, list) or not addresses:
                    raise ValueError("IP address expression missing members")
                values.append({p for ip in addresses for p in address_prefixes(ip)})
            elif kind == "ExternalIDExpression" and node.get("member_type") == "VirtualMachine":
                identifiers = node.get("external_ids")
                if not isinstance(identifiers, list) or not identifiers or any(k not in self.machines for k in identifiers):
                    raise ValueError("external VM identities not collected")
                keys = set(identifiers)
                values.append(self.target["vm_external_id"] in keys if scope else self.addresses_for_vms(keys))
            elif kind == "PathExpression":
                paths = node.get("paths")
                if not isinstance(paths, list) or not paths:
                    raise ValueError("path expression missing members")
                parts = []
                for member in paths:
                    if member in self.groups:
                        parts.append(self.resolve(member, scope=scope, stack=(*stack, path)))
                        continue
                    ports = [p for p in self.ports.values() if p["path"] == member or p.get("parent_path") == member]
                    if not ports:
                        raise ValueError("segment/port workload membership not collected")
                    attachments = {p.get("attachment", {}).get("id") for p in ports} - {None}
                    selected = self.target["native"].get("lport_attachment_id")
                    if scope:
                        parts.append(selected in attachments if selected else None)
                    else:
                        vifs = [v for v in self.vifs.values() if v["native"].get("lport_attachment_id") in attachments]
                        if not vifs or any(not v["addresses"] for v in vifs):
                            raise ValueError("segment/port IP bindings incomplete")
                        parts.append({p for v in vifs for ip in v["addresses"] for p in address_prefixes(ip)})
                if any(p is None for p in parts):
                    raise ValueError("selected vNIC attachment unresolved")
                values.append(any(parts) if scope else set().union(*parts))
            else:
                raise ValueError("group requires supported workload/member evidence: " + str(kind))
            expect_operand = False
        if expect_operand:
            raise ValueError("incomplete group expression")
        if scope:
            return any(values)
        result = set().union(*values)
        if len(result) > 10000:
            raise ValueError("NSX group expansion limit exceeded")
        if not result:
            raise ValueError("empty group cannot become an unrestricted selector")
        return result
