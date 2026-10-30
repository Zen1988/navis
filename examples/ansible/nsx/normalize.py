"""Translate NSX Local Manager exports for one native VM and vNIC identity."""
import argparse
import json
from pathlib import Path
import re

from navis_common.nsx_adapter import normalized_submissions, translate_vm
from navis_common.nsx_inventory import list_results


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def read_pages(root, name, *, optional=False):
    files = list(root.glob(name + "-*.json"))
    indexed = {}
    for path in files:
        suffix = path.stem[len(name) + 1:]
        if not suffix.isdigit() or int(suffix) in indexed:
            raise ValueError("invalid or duplicate export page filename")
        indexed[int(suffix)] = path
    if not indexed and optional:
        return None
    if not indexed or sorted(indexed) != list(range(len(indexed))):
        raise ValueError("missing native export pages: " + name)
    return [read(indexed[i]) for i in range(len(indexed))]


def safe_id(resource):
    value = resource.get("id")
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("native resource ID is unsafe as an export filename")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--vm-external-id", required=True)
    parser.add_argument("--vif-external-id", help="optionally restrict output to one vNIC; defaults to all NICs on the selected VM")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--external-device-id", required=True, help="Navis identity mapped to the selected VM")
    parser.add_argument("--semantics", type=Path)
    args = parser.parse_args()
    root = args.output_dir
    metadata = read(root / "metadata.json")
    collection = {key: read_pages(root, name) for key, name in (
        ("domains", "domains"), ("groups", "groups"), ("policies", "security-policies"), ("services", "services"),
        ("virtual_machines", "virtual-machines"), ("vifs", "vifs"), ("segments", "segments"))}
    collection["rulebases"] = {p["path"]: read_pages(root, "policy-" + safe_id(p) + "-rules") for p in list_results(collection["policies"])}
    collection["group_virtual_machines"] = {}
    for group in list_results(collection["groups"]):
        members = read_pages(root, "group-" + safe_id(group) + "-vms", optional=True)
        if members is not None:
            collection["group_virtual_machines"][group["path"]] = members
    collection["segment_ports"] = {s["path"]: read_pages(root, "segment-" + safe_id(s) + "-ports") for s in list_results(collection["segments"])}
    requests = normalized_submissions(metadata, collection, args.namespace, args.external_device_id,
        vm_external_id=args.vm_external_id, vif_external_id=args.vif_external_id)
    if args.semantics:
        semantics = translate_vm(metadata, collection, vm_external_id=args.vm_external_id, vif_external_id=args.vif_external_id)
        args.semantics.write_text(json.dumps(semantics, indent=2), encoding="utf-8")
    print(json.dumps(requests, indent=2))


if __name__ == "__main__":
    main()
