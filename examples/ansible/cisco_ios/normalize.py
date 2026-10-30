"""Translate a Cisco IOS/IOS XE collector export into partial Navis envelopes."""
import argparse
import json
from pathlib import Path
from navis_common.ios_adapter import normalized_submissions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('export', type=Path)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--external-device-id', required=True)
    args = parser.parse_args()
    export = json.loads(args.export.read_text(encoding='utf-8-sig'))
    print(json.dumps(normalized_submissions(export, args.namespace, args.external_device_id), indent=2))


if __name__ == '__main__':
    main()
