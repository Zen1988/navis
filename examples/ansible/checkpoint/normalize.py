"""Translate a Check Point management export for one package and gateway UID."""
import argparse
import json
from pathlib import Path
import re

from navis_common.checkpoint_adapter import normalized_submissions, pages, translate_management, uid


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def safe_uid(value):
    value = uid(value)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("native UID cannot be used as an export filename")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--package-uid", required=True)
    parser.add_argument("--gateway-uid", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--external-device-id", required=True)
    parser.add_argument("--semantics", type=Path)
    args = parser.parse_args()
    root = args.output_dir
    metadata = read(root / "metadata.json")
    package = safe_uid(args.package_uid)
    discovered = pages(read(root / "access-layers.json"), "access-layers")
    layers, rulebases = [], {}
    for entry in discovered:
        key = safe_uid(entry)
        layers.append(read(root / ("layer-" + key + ".json")))
        rulebases[key] = read(root / ("access-" + key + ".json"))
    collection = {"objects": read(root / "objects.json"), "gateways": read(root / "gateways.json"),
        "packages": read(root / "packages.json"), "package_details": {package: read(root / ("package-" + package + ".json"))},
        "layers": layers, "rulebases": rulebases}
    nat_file = root / ("nat-" + package + ".json")
    if nat_file.exists():
        collection["nat"] = read(nat_file)
    submissions = normalized_submissions(metadata, collection, args.namespace, args.external_device_id,
        package_uid=package, gateway_uid=args.gateway_uid)
    if args.semantics:
        semantics = translate_management(metadata, collection, package_uid=package, gateway_uid=args.gateway_uid)
        args.semantics.write_text(json.dumps(semantics, indent=2), encoding="utf-8")
    print(json.dumps(submissions, indent=2))


if __name__ == "__main__":
    main()
