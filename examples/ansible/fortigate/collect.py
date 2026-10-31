"""Read one FortiOS VDOM through the REST API with an externally provisioned token."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

from navis_common.fortigate_adapter import ENDPOINTS, REQUIRED

MAX_BYTES = 64 * 1024 * 1024


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def collect(origin, token, vdom, *, ca_file=None, timeout=30, opener=None):
    parsed = urlsplit(origin)
    if parsed.scheme != 'https' or not parsed.netloc or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('plain HTTPS management origin required')
    if not token or not isinstance(vdom, str) or not vdom.strip():
        raise ValueError('external token and explicit VDOM required')
    origin = origin.rstrip('/')
    opener = opener or build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)), NoRedirect())
    responses, serial, version = {}, None, None
    for path in ENDPOINTS:
        url = origin + '/api/v2/' + quote(path) + '?' + urlencode({'vdom': vdom})
        request = Request(url, headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}, method='GET')
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError('response too large: ' + path)
            data = json.loads(body)
        except HTTPError as error:
            if path in REQUIRED:
                raise ValueError('required endpoint failed (HTTP ' + str(error.code) + '): ' + path) from None
            responses[path] = {'status': 'error', 'http_status': error.code}
            continue
        if not isinstance(data, dict):
            raise ValueError('unexpected response shape: ' + path)
        if data.get('status') != 'success' and path in REQUIRED:
            raise ValueError('required endpoint reported failure: ' + path)
        serial, version = serial or data.get('serial'), version or data.get('version')
        responses[path] = data
    return {'device_id': None, 'serial': serial, 'version': version, 'vdom': vdom,
            'collected_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'coverage': 'partial',
            'responses': responses}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='https://fortigate-management[:port]')
    parser.add_argument('--vdom', required=True)
    parser.add_argument('--device-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ca-file')
    args = parser.parse_args()
    token = os.environ.get('FORTIGATE_API_TOKEN')
    if not token:
        parser.error('FORTIGATE_API_TOKEN must be set from a protected credential source')
    export = collect(args.url, token, args.vdom, ca_file=args.ca_file)
    export['device_id'] = args.device_id
    # Exclusive creation keeps an existing export from being overwritten.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        json.dump(export, output, indent=2)


if __name__ == '__main__':
    main()
