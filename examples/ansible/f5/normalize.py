"""Normalize one BIG-IP management export for an explicit partition/route domain."""
import argparse
import json
from pathlib import Path
from navis_common.f5_adapter import normalized_submissions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export', type=Path)
    parser.add_argument('--partition', required=True)
    parser.add_argument('--route-domain', type=int, required=True)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--external-device-id', required=True)
    args = parser.parse_args()
    export = json.loads(args.export.read_text(encoding='utf-8-sig'))
    print(json.dumps(normalized_submissions(export['metadata'], export['collection'], args.namespace,
        args.external_device_id, partition=args.partition, route_domain=args.route_domain), indent=2))


if __name__ == '__main__':
    main()
