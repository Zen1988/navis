"""Convert APIC collector files to Navis ingestion requests on stdout."""
import argparse
import json
from pathlib import Path
from navis_common.aci_adapter import (CLASS_GROUPS, adapt_interfaces, fabric_evidence_submission,
                                     normalized_policy_submission, translate_inventory, translate_semantics)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--identities", required=True, type=Path)
    parser.add_argument("--inventory", type=Path, help="write separate partial evidence inventory JSON")
    parser.add_argument("--semantics", type=Path, help="write translated candidate routes and contracts")
    parser.add_argument("--fabric-external-id", help="append a raw-only fabric evidence ingestion request")
    parser.add_argument("--policy", action="store_true", help="append partial normalized policy candidates")
    args = parser.parse_args()
    if args.policy and not args.fabric_external_id:
        parser.error("--policy requires --fabric-external-id")
    requests = adapt_interfaces(read(args.output_dir / "metadata.json"),
                                read(args.output_dir / "l1PhysIf.json"),
                                read(args.output_dir / "ethpmPhysIf.json"),
                                args.namespace, read(args.identities))
    if args.inventory or args.semantics or args.fabric_external_id:
        pages = {cls: read(args.output_dir / (cls + ".json")) for cls in CLASS_GROUPS
                 if (args.output_dir / (cls + ".json")).exists()}
        inventory = translate_inventory(read(args.output_dir / "metadata.json"), pages)
        if args.inventory:
            args.inventory.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
        if args.semantics:
            args.semantics.write_text(json.dumps(translate_semantics(inventory), indent=2), encoding="utf-8")
        if args.fabric_external_id:
            requests.append(fabric_evidence_submission(inventory, args.namespace, args.fabric_external_id))
        if args.policy:
            requests.append(normalized_policy_submission(inventory, args.namespace, args.fabric_external_id))
    print(json.dumps(requests, indent=2))


if __name__ == "__main__":
    main()
