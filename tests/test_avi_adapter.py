from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from navis_common.avi_adapter import translate_controller, normalized_submissions, list_objects, reference
from navis_common.load_balancer import candidate_evidence
from navis_api.normalized_adapter import normalize
from navis_common.nat import Packet, evaluate_nat


def ref(kind, uuid):
    return '/api/' + kind + '/' + uuid


class AviTests(unittest.TestCase):
    def setUp(self):
        self.meta = dict(controller_id='controller-a', controller_url='https://avi.example', tenant_uuid='tenant-a',
                         collected_at='2026-10-30T00:00:00Z', api_version='31.2.1')
        context = dict(tenant_ref=ref('tenant', 'tenant-a'), cloud_ref=ref('cloud', 'cloud-a'))
        self.pool = dict(context, uuid='pool-a', vrf_ref=ref('vrfcontext', 'vrf-a'), default_server_port=8080,
                         servers=[dict(ip=dict(addr='192.0.2.10', type='V4')), dict(ip=dict(addr='192.0.2.11', type='V4'), port=8081)])
        self.vs = dict(context, uuid='vs-a', name='web', vrf_context_ref=ref('vrfcontext', 'vrf-a'),
                       vsvip_ref=ref('vsvip', 'vip-a'), pool_ref=ref('pool', 'pool-a'),
                       network_profile_ref=ref('networkprofile', 'tcp'), services=[dict(port=443, enable_ssl=True)])
        values = dict(virtualservice=[self.vs], pool=[self.pool], poolgroup=[],
                      vsvip=[dict(context, uuid='vip-a', vrf_context_ref=ref('vrfcontext', 'vrf-a'),
                                  vip=[dict(ip_address=dict(addr='198.51.100.5', type='V4'))])],
                      networkprofile=[dict(uuid='tcp', profile=dict(type='PROTOCOL_TYPE_TCP_PROXY'))],
                      vrfcontext=[dict(context, uuid='vrf-a', static_routes=[dict(route_id='r1',
                          prefix=dict(ip_addr=dict(addr='0.0.0.0', type='V4'), mask=0),
                          next_hop=dict(addr='192.0.2.1', type='V4'), if_name='eth1')])])
        self.collection = {k: [dict(count=len(v), results=v)] for k, v in values.items()}

    def translate(self):
        return translate_controller(self.meta, self.collection, vrf_uuid='vrf-a')

    def evidence(self, **kwargs):
        payload = dict(kind='avi_load_balancer_evidence', version=1, semantics=self.translate())
        return candidate_evidence([('snapshot', payload)], '203.0.113.1', '198.51.100.5', 'tcp', 443, **kwargs)

    def test_routes_are_configuration_without_invented_interface(self):
        route = self.translate()['routes'][0]
        self.assertEqual(route['destination'], '0.0.0.0/0')
        self.assertIsNone(route['interface'])
        self.assertEqual(route['details']['evidence'], 'configured_unverified')

    def test_multiple_backends_and_port_mapping(self):
        result = self.evidence()
        branches = result['candidates'][0]['backend_connection_candidates']
        self.assertEqual([x['destination_port'] for x in branches], [8080, 8081])
        self.assertTrue(all(x['source'] is None and x['health'] == 'unknown' for x in branches))
        self.assertEqual(result['status'], 'unknown')

    def test_preserve_service_port(self):
        self.pool['use_service_port'] = True
        self.assertEqual([x['destination_port'] for x in self.evidence()['candidates'][0]['backend_connection_candidates']], [443, 443])

    def test_snat_pool_is_not_allocated(self):
        self.vs['snat_ip'] = [dict(addr='192.0.2.100', type='V4')]
        mode = self.translate()['virtual_services'][0]['source_translation']
        self.assertEqual(mode['mode'], 'configured_snat_pool')
        self.assertEqual(mode['allocation'], 'connection_dependent')

    def test_vip_snat(self):
        self.vs['use_vip_as_snat'] = True
        self.assertEqual(self.translate()['virtual_services'][0]['source_translation']['addresses'], ['198.51.100.5'])

    def test_disabled_server_and_virtualservice(self):
        self.pool['servers'][0]['enabled'] = False
        self.assertEqual(len(self.translate()['virtual_services'][0]['backends']), 1)
        self.vs['enabled'] = False
        self.assertEqual(self.evidence()['candidates'], [])

    def test_conditional_selection_incomplete(self):
        self.vs['http_policies'] = [dict(http_policy_set_ref='/api/httppolicyset/policy')]
        self.assertFalse(self.translate()['virtual_services'][0]['conditions_complete'])

    def test_cross_tenant_pool_does_not_translate(self):
        self.pool['tenant_ref'] = ref('tenant', 'other')
        result = self.translate()['virtual_services'][0]
        self.assertFalse(result['conditions_complete'])
        self.assertEqual(result['backends'], [])

    def test_pool_group_retains_candidates(self):
        del self.vs['pool_ref']
        self.vs['pool_group_ref'] = ref('poolgroup', 'pg')
        self.collection['poolgroup'] = [dict(count=1, results=[dict(uuid='pg', tenant_ref=ref('tenant', 'tenant-a'), members=[dict(pool_ref=ref('pool', 'pool-a'), ratio=5)])])]
        self.assertEqual(self.translate()['virtual_services'][0]['backends'][0]['pool_group_member']['ratio'], 5)

    def test_invalid_route_preserved_as_unresolved(self):
        self.collection['vrfcontext'][0]['results'][0]['static_routes'][0]['prefix']['mask'] = 99
        result = self.translate()
        self.assertEqual(result['routes'], [])
        self.assertTrue(result['route_candidates'][0]['unresolved'])

    def test_native_pagination_integrity(self):
        with self.assertRaises(ValueError):
            list_objects([dict(count=2, results=[dict(uuid='a')])], 'pool', self.meta['controller_url'])
        with self.assertRaises(ValueError):
            list_objects([dict(count=0, results=[], next='https://foreign/api/pool?page=2'), dict(count=0, results=[])], 'pool', self.meta['controller_url'])

    def test_reference_uuid_fragments_and_foreign_origin(self):
        self.assertEqual(reference('/api/pool/pool-a#name', 'pool', self.meta['controller_url']), 'pool-a')
        with self.assertRaises(ValueError):
            reference('https://foreign/api/pool/pool-a', 'pool', self.meta['controller_url'])

    def test_typed_submissions_validate(self):
        requests = normalized_submissions(self.meta, self.collection, 'avi', 'vrf-a', vrf_uuid='vrf-a')
        for request in requests[:3]:
            normalize(request['data_type'], request['payload'])
        self.assertEqual(requests[3]['payload']['kind'], 'avi_load_balancer_evidence')
        self.assertEqual(requests[2]['payload']['entries'][0]['translation_kind'], 'load_balance')

    def test_candidate_budget(self):
        result = self.evidence(limit=1)
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['candidates'][0]['backend_connection_candidates']), 1)

    def test_load_balancing_never_becomes_deterministic_nat(self):
        native = self.translate()['nat'][0]
        rule = dict(native, kind=native['translation_kind'], selectors_complete=True)
        packet = Packet('203.0.113.1', '198.51.100.5', 'tcp', 443)
        translated, evidence = evaluate_nat([rule], packet, complete=True)
        self.assertEqual(translated, packet)
        self.assertEqual(evidence['status'], 'unknown')

    def test_ipv6_routes_and_vips(self):
        route = self.collection['vrfcontext'][0]['results'][0]['static_routes'][0]
        route['prefix'] = dict(ip_addr=dict(addr='2001:db8::', type='V6'), mask=64)
        route['next_hop'] = dict(addr='2001:db8::1', type='V6')
        self.collection['vsvip'][0]['results'][0]['vip'][0]['ip6_address'] = dict(addr='2001:db8::5', type='V6')
        result = self.translate()
        self.assertEqual(result['routes'][0]['destination'], '2001:db8::/64')
        self.assertIn('2001:db8::5', result['virtual_services'][0]['vip_addresses'])

    def test_cli_native_export(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=root) as directory:
            output = Path(directory)
            (output / 'metadata.json').write_text(json.dumps(self.meta), encoding='utf-8')
            for kind, pages in self.collection.items():
                for index, page in enumerate(pages):
                    (output / (kind + '-' + str(index) + '.json')).write_text(json.dumps(page), encoding='utf-8')
            result = subprocess.run([sys.executable, str(root / 'examples/ansible/avi/normalize.py'), str(output),
                '--vrf-uuid', 'vrf-a', '--namespace', 'avi', '--external-device-id', 'vrf-a'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(result.stdout)), 4)

    def test_malformed_evidence_ignored(self):
        payload = dict(kind='avi_load_balancer_evidence', version=1, semantics=dict(virtual_services=[dict(enabled=True, vip_addresses=['198.51.100.5'], uuid='vs', vrf_uuid='v', tenant_uuid='t', listeners=[None, {}], backends=[None])]))
        self.assertEqual(candidate_evidence([('s', payload)], '203.0.113.1', '198.51.100.5', 'tcp', 443)['candidates'], [])
