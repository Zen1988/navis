"""Translate one targeted firewall/VSYS collection into partial Navis requests."""
import argparse
import json
from pathlib import Path
import re

from navis_common.paloalto_adapter import normalized_submissions, translate_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--vsys", required=True)
    parser.add_argument("--device-entry", required=True, help="exact device entry in native XML")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--external-device-id", required=True)
    parser.add_argument("--semantics", type=Path, help="write separate translation findings and limitations")
    parser.add_argument("--pushed-config", type=Path)
    parser.add_argument("--panorama-config", type=Path, help="use raw Panorama hierarchy instead of pushed config")
    parser.add_argument("--hierarchy", type=Path)
    parser.add_argument("--applications", type=Path)
    parser.add_argument("--routes", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.serial):
        parser.error("invalid serial directory name")
    metadata = json.loads((args.output_dir / "metadata.json").read_text(encoding="utf-8-sig"))
    if args.serial not in metadata.get("firewall_serials", []):
        parser.error("serial absent from collection metadata")
    selected = {"serial": args.serial, "collected_at": metadata.get("collected_at")}
    xml = (args.output_dir / args.serial / "running-config.xml").read_text(encoding="utf-8-sig")
    if args.pushed_config and args.panorama_config:
        parser.error("choose --pushed-config or --panorama-config")
    evidence = {}
    paths = {"applications_xml": args.applications or args.output_dir / args.serial / "applications.xml",
             "routes_xml": args.routes or args.output_dir / args.serial / "routes.xml"}
    pushed = args.pushed_config or args.output_dir / args.serial / "pushed-config.xml"
    panorama = args.panorama_config or args.output_dir / "panorama-config.xml"
    if not args.panorama_config and pushed.exists():
        paths["pushed_xml"] = pushed
    elif panorama.exists():
        paths["panorama_xml"] = panorama
        paths["hierarchy_xml"] = args.hierarchy or args.output_dir / "device-group-hierarchy.xml"
    explicit = [p for p in (args.pushed_config, args.panorama_config, args.hierarchy, args.applications, args.routes) if p is not None]
    if any(not p.is_file() for p in explicit):
        parser.error("explicit evidence file does not exist")
    for key, path in paths.items():
        if path.exists():
            evidence[key] = path.read_text(encoding="utf-8-sig")
    requests = normalized_submissions(xml, selected, args.namespace, args.external_device_id,
                                      device_entry=args.device_entry, vsys=args.vsys, **evidence)
    if args.semantics:
        semantics = translate_config(xml, selected, device_entry=args.device_entry, vsys=args.vsys, **evidence)
        args.semantics.write_text(json.dumps(semantics, indent=2), encoding="utf-8")
    print(json.dumps(requests, indent=2))


if __name__ == "__main__":
    main()
