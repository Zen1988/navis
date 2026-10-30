"""Native NSX list validation and VM/vNIC-first inventory joins."""
from ipaddress import ip_address


def list_results(pages):
    if not isinstance(pages, list) or not pages:
        raise ValueError("native NSX response pages required")
    output, cursors, total = [], set(), None
    for index, page in enumerate(pages):
        if not isinstance(page, dict) or not isinstance(page.get("results"), list):
            raise ValueError("invalid NSX list response")
        count = page.get("result_count")
        if count is not None:
            if not isinstance(count, int) or isinstance(count, bool) or count < 0 or total is not None and count != total:
                raise ValueError("inconsistent NSX result count")
            total = count
        cursor = page.get("cursor") or ""
        if not isinstance(cursor, str) or cursor and cursor in cursors:
            raise ValueError("invalid or repeated NSX cursor")
        if index < len(pages) - 1 and not cursor or index == len(pages) - 1 and cursor:
            raise ValueError("missing or truncated NSX cursor chain")
        if cursor:
            cursors.add(cursor)
        output.extend(page["results"])
        if len(output) > 1000000:
            raise ValueError("NSX inventory size limit exceeded")
    if total is not None and len(output) != total:
        raise ValueError("NSX result count disagrees with collected pages")
    return output


def index_resources(values, prefix, resource_type):
    result = {}
    for value in values:
        if not isinstance(value, dict) or value.get("resource_type") != resource_type:
            raise ValueError("unexpected native NSX resource type")
        path = value.get("path")
        if not isinstance(path, str) or not path.startswith(prefix + "/") or "/" in path[len(prefix) + 1:] or path in result:
            raise ValueError("missing, duplicate or foreign NSX resource path")
        if value.get("id") != path.rsplit("/", 1)[-1]:
            raise ValueError("NSX path/ID identity mismatch")
        if value.get("parent_path") not in (None, prefix.rsplit("/", 1)[0]):
            raise ValueError("NSX native parent/path association mismatch")
        result[path] = value
    return result


def vm_inventory(collection, vm_external_id, vif_external_id=None):
    vms = list_results(collection.get("virtual_machines"))
    vifs = list_results(collection.get("vifs"))
    aliases, machines = {}, {}
    for vm in vms:
        if not isinstance(vm, dict):
            raise ValueError("invalid native VM resource")
        key = vm.get("external_id")
        if vm.get("resource_type") != "VirtualMachine" or not isinstance(key, str) or not key or key in machines:
            raise ValueError("VM external identity missing or duplicate")
        machines[key] = vm
        for alias in (key, vm.get("id")):
            if alias:
                if alias in aliases and aliases[alias] != key:
                    raise ValueError("ambiguous native VM ID/external-ID association")
                aliases[alias] = key
    if vm_external_id not in machines:
        raise ValueError("selected VM external ID not collected")
    interfaces = {}
    for vif in vifs:
        if not isinstance(vif, dict):
            raise ValueError("invalid native vNIC resource")
        key = vif.get("external_id")
        if vif.get("resource_type") != "VirtualNetworkInterface" or not isinstance(key, str) or not key or key in interfaces:
            raise ValueError("vNIC external identity missing or duplicate")
        addresses = set()
        for info in vif.get("ip_address_info", []):
            for address in info.get("ip_addresses", []):
                addresses.add(str(ip_address(address)))
        interfaces[key] = {"external_id": key, "vm_external_id": aliases.get(vif.get("owner_vm_id")),
                           "addresses": sorted(addresses), "native": vif}
    selected = [v for v in interfaces.values() if v["vm_external_id"] == vm_external_id
                and (vif_external_id is None or v["external_id"] == vif_external_id)]
    if len(selected) != 1:
        raise ValueError("select one unambiguous VM vNIC by external ID")
    target = selected[0]
    ports = [p for pages in collection.get("segment_ports", {}).values() for p in list_results(pages)]
    attachments = [p for p in ports if not p.get("marked_for_delete") and p.get("attachment", {}).get("id")
                   and p.get("attachment", {}).get("id") == target["native"].get("lport_attachment_id")]
    if len(attachments) > 1:
        raise ValueError("ambiguous vNIC/segment-port attachment")
    target = {**target, "segment_port": attachments[0] if attachments else None,
              "vm": machines[vm_external_id], "identity_source": "native_vm_vif_join"}
    return target, machines, interfaces
