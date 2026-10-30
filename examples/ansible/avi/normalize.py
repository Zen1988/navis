"""Translate one Controller tenant/VRF export into partial Navis requests."""
import argparse
import json
from pathlib import Path

from navis_common.avi_adapter import normalized_submissions, translate_controller


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pages(root, kind):
    indexed = {}
    for path in root.glob(kind + "-*.json"):
        index = path.stem[len(kind) + 1:]
        if not index.isdigit() or int(index) in indexed:
            raise ValueError("invalid Avi page filename")
        indexed[int(index)] = path
    if not indexed or sorted(indexed) != list(range(len(indexed))):
        raise ValueError("missing native Avi export pages: " + kind)
    return [read(indexed[i]) for i in range(len(indexed))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--vrf-uuid", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--external-device-id", required=True)
    parser.add_argument("--semantics", type=Path)
    args = parser.parse_args()
    metadata = read(args.output_dir / "metadata.json")
    collection = {kind: pages(args.output_dir, kind) for kind in ("virtualservice", "vsvip", "pool", "poolgroup", "vrfcontext", "networkprofile")}
    requests = normalized_submissions(metadata, collection, args.namespace, args.external_device_id, vrf_uuid=args.vrf_uuid)
    if args.semantics:
        args.semantics.write_text(json.dumps(translate_controller(metadata, collection, vrf_uuid=args.vrf_uuid), indent=2), encoding="utf-8")
    print(json.dumps(requests, indent=2))


if __name__ == "__main__":
    main()
