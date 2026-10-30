import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from io import BytesIO

from navis_api.normalized_adapter import normalize
from navis_common.f5_adapter import address, endpoint, objects, translate_management, normalized_submissions
from navis_common.load_balancer import candidate_evidence
from navis_common.nat import Packet, evaluate_nat


def paged(items):
    return [dict(items=items, totalItems=len(items))]


class F5Tests(unittest.TestCase):
    def setUp(self):
        self.meta = dict(device_id='f5-a', collected_at='2026-10-30T00:00:00Z')
        self.vs = dict(fullPath='/Common/web', partition='Common', name='web', destination='/Common/198.51.100.5:443',
            mask='255.255.255.255', ipProtocol='tcp', pool='/Common/app', translateAddress='enabled', translatePort='enabled',
            sourceAddressTranslation=dict(type='automap'))
        self.member = dict(fullPath='/Common/node-a:8080', address='192.0.2.10', session='user-enabled', state='up')
        self.collection = dict(virtual=paged([self.vs]), pool=paged([dict(fullPath='/Common/app', partition='Common')]),
            members={'/Common/app':paged([self.member, dict(fullPath='/Common/node-b:8081', address='192.0.2.11')])},
            route=paged([dict(fullPath='/Common/default', partition='Common', network='default', gw='192.0.2.1')]),
            self=paged([dict(fullPath='/Common/self', partition='Common', address='192.0.2.2/24', vlan='/Common/vlan')]),
            snatpool=paged([]), partition=paged([dict(fullPath='/Common', name='Common', defaultRouteDomain=0)]),
            **{'route-domain':paged([dict(fullPath='/Common/0', partition='Common', id=0)])})

    def translate(self, rd=0):
        return translate_management(self.meta, self.collection, partition='Common', route_domain=rd)

    def evidence(self):
        return candidate_evidence([('s', dict(kind='f5_load_balancer_evidence', version=1, semantics=self.translate()))],
            '203.0.113.1', '198.51.100.5', 'tcp', 443)

    def test_routes_and_self_ips(self):
        result = self.translate()
        self.assertEqual(result['routes'][0]['destination'], '0.0.0.0/0')
        self.assertIsNone(result['routes'][0]['interface'])
        self.assertEqual(result['interfaces'][0]['addresses'], ['192.0.2.2/24'])

    def test_named_nodes_and_backend_candidates(self):
        candidates = self.evidence()['candidates'][0]['backend_connection_candidates']
        self.assertEqual([c['destination_port'] for c in candidates], [8080, 8081])
        self.assertTrue(all(c['source'] is None and c['health'] == 'unknown' for c in candidates))

    def test_no_port_translation(self):
        self.vs['translatePort'] = 'disabled'
        self.assertEqual(self.evidence()['candidates'][0]['backend_connection_candidates'][0]['destination_port'], 443)

    def test_no_address_translation_not_guessed(self):
        self.vs['translateAddress'] = 'disabled'
        self.assertEqual(self.translate()['virtual_services'][0]['backends'], [])

    def test_disabled_members_and_virtuals(self):
        self.member['session'] = 'user-disabled'
        self.assertEqual(len(self.translate()['virtual_services'][0]['backends']), 1)
        self.vs['disabled'] = True
        self.assertEqual(self.evidence()['candidates'], [])

    def test_partition_default_route_domain(self):
        self.collection['partition'][0]['items'][0]['defaultRouteDomain'] = 7
        self.collection['route-domain'][0]['items'][0]['id'] = 7
        self.assertEqual(len(self.translate(rd=7)['virtual_services']), 1)

    def test_explicit_route_domain_isolation(self):
        self.vs['destination'] = '/Common/198.51.100.5%7:443'
        self.assertEqual(self.translate()['virtual_services'], [])

    def test_missing_partition_identity_rejected(self):
        self.collection['partition'] = paged([])
        with self.assertRaises(ValueError):
            self.translate()

    def test_snat_pool_not_allocation(self):
        self.vs['sourceAddressTranslation'] = dict(type='snat', pool='/Common/snat')
        self.collection['snatpool'] = paged([dict(fullPath='/Common/snat', partition='Common', members=['192.0.2.50'])])
        mode = self.translate()['virtual_services'][0]['source_translation']
        self.assertEqual(mode['addresses'], ['192.0.2.50'])
        self.assertEqual(mode['allocation'], 'unknown')

    def test_irules_remain_incomplete(self):
        self.vs['rules'] = ['/Common/select-pool']
        self.assertFalse(self.translate()['virtual_services'][0]['conditions_complete'])

    def test_pagination_rejects_truncation_duplicates_count(self):
        for pages in ([dict(items=[], nextLink='/next')], paged([dict(fullPath='/x'), dict(fullPath='/x')]), [dict(items=[], totalItems=1)]):
            with self.assertRaises(ValueError):
                objects(pages)

    def test_ipv6_route_domain_endpoint(self):
        self.assertEqual(endpoint('/Common/2001:db8::5%12.443'), ('2001:db8::5', 12, 443))
        self.assertEqual(address('192.0.2.1%7'), ('192.0.2.1', 7))

    def test_normalized_envelopes_and_nat_rejection(self):
        requests = normalized_submissions(self.meta, self.collection, 'f5', 'f5-common-rd0', partition='Common', route_domain=0)
        for request in requests[:3]:
            normalize(request['data_type'], request['payload'])
        rule = requests[2]['payload']['entries'][0]
        packet = Packet('203.0.113.1', '198.51.100.5', 'tcp', 443)
        translated, result = evaluate_nat([dict(rule, kind='load_balance', selectors_complete=True)], packet, complete=True)
        self.assertEqual(translated, packet)
        self.assertEqual(result['status'], 'unknown')

    def test_management_pagination_url_security(self):
        path = Path(__file__).resolve().parents[1] / 'examples/ansible/f5/collect.py'
        spec = importlib.util.spec_from_file_location('f5_collect', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        origin, resource = 'https://f5.example', '/mgmt/tm/ltm/virtual'
        self.assertEqual(module.next_url(origin, 'https://localhost' + resource + '?$skip=10', resource), origin + resource + '?$skip=10')
        for value in ('https://foreign'+resource, 'http://localhost'+resource, 'https://f5.example/mgmt/tm/util/bash', 'https://user@f5.example'+resource):
            with self.assertRaises(ValueError):
                module.next_url(origin, value, resource)

    def test_cli_export(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=root) as directory:
            export = Path(directory) / 'export.json'
            export.write_text(json.dumps(dict(metadata=self.meta, collection=self.collection)), encoding='utf-8')
            result = subprocess.run([sys.executable, str(root/'examples/ansible/f5/normalize.py'), str(export), '--partition', 'Common',
                '--route-domain', '0', '--namespace', 'f5', '--external-device-id', 'f5-common-rd0'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(result.stdout)), 4)

    def test_collector_gets_native_collections_and_members(self):
        path = Path(__file__).resolve().parents[1] / 'examples/ansible/f5/collect.py'
        spec = importlib.util.spec_from_file_location('f5_collector_test', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        requests = []
        class Opener:
            def open(inner, request, timeout):
                requests.append(request)
                if '/pool/~' in request.full_url:
                    page = self.collection['members']['/Common/app'][0]
                else:
                    key = request.full_url.split('?')[0].rsplit('/', 1)[-1]
                    page = self.collection[key][0]
                return BytesIO(json.dumps(page).encode())
        with patch.object(module, 'build_opener', return_value=Opener()):
            data = module.collect('https://f5.example', 'test-token')
        self.assertEqual(len(requests), 8)
        self.assertTrue(all(r.get_method() == 'GET' and r.get_header('X-f5-auth-token') == 'test-token' for r in requests))
        self.assertEqual(len(data['members']['/Common/app'][0]['items']), 2)

    def test_unknown_gateway_pool_not_a_direct_route(self):
        self.collection['route'][0]['items'][0]['pool'] = '/Common/gateways'
        result = self.translate()
        self.assertEqual(result['routes'], [])
        self.assertTrue(result['findings'])
