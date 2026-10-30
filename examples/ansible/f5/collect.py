"""Read BIG-IP management configuration with an externally provisioned REST token."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
from urllib.parse import quote, urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPSHandler, HTTPRedirectHandler

from navis_common.f5_adapter import objects


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def next_url(origin, value, path):
    """BIG-IP often advertises localhost; never send credentials to that host."""
    parsed, target = urlsplit(value), urlsplit(origin)
    if parsed.username or parsed.password or parsed.fragment or parsed.path != path:
        raise ValueError('unexpected BIG-IP pagination path')
    if parsed.scheme and parsed.scheme != 'https' or parsed.netloc and parsed.netloc.lower() not in (target.netloc.lower(), 'localhost'):
        raise ValueError('foreign/insecure BIG-IP pagination origin')
    return urlunsplit(('https', target.netloc, path, parsed.query, ''))


def collect(origin, token, *, max_pages=100, page_size=100, ca_file=None):
    parsed = urlsplit(origin)
    if parsed.scheme != 'https' or not parsed.netloc or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('plain HTTPS management origin required')
    if max_pages < 1 or page_size < 1 or not token:
        raise ValueError('positive page budgets and external token required')
    origin = origin.rstrip('/')
    opener = build_opener(HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)), NoRedirect())
    def pages(path):
        url, seen, result = origin + path + '?$top=' + str(page_size), set(), []
        for _ in range(max_pages):
            url = next_url(origin, url, path)
            if url in seen:
                raise ValueError('repeated BIG-IP page URL')
            seen.add(url)
            request = Request(url, headers={'X-F5-Auth-Token': token, 'Accept': 'application/json'}, method='GET')
            with opener.open(request, timeout=60) as response:
                # Bound each response as well as the page count.
                raw = response.read(32 * 1024 * 1024 + 1)
                if len(raw) > 32 * 1024 * 1024:
                    raise ValueError('BIG-IP response size budget exceeded')
                page = json.loads(raw)
            if not isinstance(page, dict) or page.get('kind', '').endswith(':error'):
                raise ValueError('invalid BIG-IP REST response')
            result.append(page)
            if not page.get('nextLink'):
                objects(result)
                return result
            url = page['nextLink']
        raise ValueError('BIG-IP page budget reached')
    paths = dict(virtual='ltm/virtual', pool='ltm/pool', snatpool='ltm/snatpool', route='net/route',
                 self='net/self', **{'route-domain':'net/route-domain', 'partition':'auth/partition'})
    result = {kind: pages('/mgmt/tm/' + path) for kind, path in paths.items()}
    result['members'] = {}
    for full_path in objects(result['pool']):
        parts = full_path.strip('/').split('/')
        if any(not part or part in ('.', '..') or '~' in part for part in parts):
            raise ValueError('unsupported pool identity')
        identity = quote('~' + '~'.join(parts), safe='~')
        result['members'][full_path] = pages('/mgmt/tm/ltm/pool/' + identity + '/members')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--device-id', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ca-file')
    parser.add_argument('--max-pages', type=int, default=100)
    parser.add_argument('--page-size', type=int, default=100)
    args = parser.parse_args()
    # Refuse overwrite/mixed exports. Token is never serialized or passed in argv.
    if args.output.exists():
        raise ValueError('use a fresh output file')
    data = collect(args.url, os.environ.get('F5_AUTH_TOKEN'), max_pages=args.max_pages, page_size=args.page_size, ca_file=args.ca_file)
    export = dict(metadata=dict(device_id=args.device_id, management_url=args.url,
        collected_at=datetime.now(timezone.utc).isoformat()), collection=data)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(export, handle, indent=2)


if __name__ == '__main__':
    main()
