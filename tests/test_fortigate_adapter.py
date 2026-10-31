import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.error import HTTPError

from navis_common.fortigate_adapter import ENDPOINTS, translate_export, normalized_submissions, _portrange
from navis_common.policy_selectors import evaluate_policy
from navis_api.normalized_adapter import normalize

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples' / 'ansible' / 'fortigate'))
from collect import collect  # noqa: E402


def ok(results):
    return {'http_method': 'GET', 'status': 'success', 'vdom': 'root', 'serial': 'FGT60F0000000001', 'version': 'v7.2.8', 'results': results}


class FortiGateTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            'cmdb/system/settings': {'opmode': 'nat', 'ngfw-mode': 'profile-based', 'central-nat': 'disable'},
            'cmdb/system/interface': [
                {'name': 'port1', 'vdom': 'root', 'type': 'physical', 'mode': 'static', 'ip': '198.51.100.1 255.255.255.0', 'vrf': 0,
                 'ipv6': {'ip6-mode': 'static', 'ip6-address': '2001:db8:1::1/64'}},
                {'name': 'port2', 'vdom': 'root', 'type': 'physical', 'mode': 'static', 'ip': '192.0.2.1 255.255.255.0', 'vrf': 0,
                 'password': 'secret-value'},
                {'name': 'port3', 'vdom': 'root', 'type': 'physical', 'mode': 'static', 'ip': '203.0.113.1 255.255.255.0', 'vrf': 0},
                {'name': 'vlan10', 'vdom': 'root', 'type': 'vlan', 'interface': 'port2', 'vlanid': 10, 'mode': 'dhcp', 'vrf': 0},
                {'name': 'port9', 'vdom': 'other', 'type': 'physical', 'mode': 'static', 'ip': '10.9.9.1 255.255.255.0'}],
            'cmdb/system/zone': [{'name': 'LAN', 'intrazone': 'deny', 'interface': [{'interface-name': 'x', 'name': 'port2'}, {'name': 'port3'}]}],
            'cmdb/firewall/address': [
                {'name': 'all', 'type': 'ipmask', 'subnet': '0.0.0.0 0.0.0.0'},
                {'name': 'lan-net', 'type': 'ipmask', 'subnet': '192.0.2.0 255.255.255.0'},
                {'name': 'web', 'type': 'ipmask', 'subnet': '198.51.100.5 255.255.255.255'},
                {'name': 'range', 'type': 'iprange', 'start-ip': '192.0.2.10', 'end-ip': '192.0.2.13'},
                {'name': 'cdn', 'type': 'fqdn', 'fqdn': 'cdn.example'}],
            'cmdb/firewall/addrgrp': [{'name': 'servers', 'member': [{'name': 'web'}, {'name': 'range'}]}],
            'cmdb/firewall/address6': [{'name': 'all', 'type': 'ipprefix', 'ip6': '::/0'}],
            'cmdb/firewall/addrgrp6': [],
            'cmdb/firewall.service/custom': [
                {'name': 'ALL', 'protocol': 'IP', 'protocol-number': 0},
                {'name': 'HTTPS', 'protocol': 'TCP/UDP/SCTP', 'tcp-portrange': '443', 'udp-portrange': '', 'sctp-portrange': ''},
                {'name': 'ALT', 'protocol': 'TCP/UDP/SCTP', 'tcp-portrange': '8000-8080:1024-65535'},
                {'name': 'PING', 'protocol': 'ICMP', 'icmptype': 8}],
            'cmdb/firewall.service/group': [{'name': 'web-svc', 'member': [{'name': 'HTTPS'}, {'name': 'ALT'}]}],
            'cmdb/firewall/policy': [
                {'policyid': 7, 'name': 'lan-to-web', 'uuid': 'u7', 'status': 'enable', 'srcintf': [{'name': 'LAN'}], 'dstintf': [{'name': 'port1'}],
                 'srcaddr': [{'name': 'lan-net'}], 'dstaddr': [{'name': 'web'}], 'service': [{'name': 'web-svc'}], 'action': 'accept',
                 'schedule': 'always', 'nat': 'enable'},
                {'policyid': 3, 'name': 'block-fqdn', 'status': 'enable', 'srcintf': [{'name': 'LAN'}], 'dstintf': [{'name': 'port1'}],
                 'srcaddr': [{'name': 'all'}], 'dstaddr': [{'name': 'cdn'}], 'service': [{'name': 'ALL'}], 'action': 'deny', 'schedule': 'always'},
                {'policyid': 9, 'name': 'vip-in', 'status': 'enable', 'srcintf': [{'name': 'port1'}], 'dstintf': [{'name': 'LAN'}],
                 'srcaddr': [{'name': 'all'}], 'dstaddr': [{'name': 'web-vip'}], 'service': [{'name': 'HTTPS'}], 'action': 'accept', 'schedule': 'always'},
                {'policyid': 4, 'name': 'off', 'status': 'disable', 'srcintf': [{'name': 'any'}], 'dstintf': [{'name': 'any'}],
                 'srcaddr': [{'name': 'all'}], 'dstaddr': [{'name': 'all'}], 'service': [{'name': 'ALL'}], 'action': 'accept', 'schedule': 'always'}],
            'cmdb/firewall/vip': [
                {'name': 'web-vip', 'type': 'static-nat', 'extip': '198.51.100.20', 'mappedip': [{'range': '192.0.2.20'}], 'extintf': 'port1',
                 'portforward': 'enable', 'protocol': 'tcp', 'extport': '443', 'mappedport': '8443'},
                {'name': 'pool-vip', 'type': 'static-nat', 'extip': '198.51.100.30', 'mappedip': [{'range': '192.0.2.30-192.0.2.31'}], 'extintf': 'any'}],
            'cmdb/firewall/vipgrp': [],
            'cmdb/firewall/ippool': [],
            'cmdb/firewall/central-snat-map': [],
            'cmdb/router/static': [
                {'seq-num': 1, 'status': 'enable', 'dst': '0.0.0.0 0.0.0.0', 'gateway': '198.51.100.254', 'device': 'port1', 'distance': 10},
                {'seq-num': 2, 'status': 'enable', 'dst': '10.0.0.0 255.0.0.0', 'blackhole': 'enable'},
                {'seq-num': 3, 'status': 'enable', 'dst': '0.0.0.0 0.0.0.0', 'device': '', 'sdwan-zone': [{'name': 'virtual-wan-link'}]}],
            'cmdb/router/static6': [{'seq-num': 1, 'status': 'enable', 'dst': '::/0', 'gateway': '2001:db8:1::fe', 'device': 'port1'}],
        }

    def export(self, data=None, **extra):
        return dict(device_id='fgt-a', collected_at='2026-10-30T00:00:00Z', vdom='root', serial='FGT60F0000000001',
                    responses={k: ok(v) for k, v in (data or self.data).items()}, **extra)

    def evaluate(self, result, *args, **context):
        rules = result['policies']
        for rule in rules:
            rule['details']['selectors_complete'] = rule['details'].get('translated_conditions_complete', False)
        return evaluate_policy(rules, 'deny', *args, complete=True, **context)

    def test_interfaces_vdom_and_dynamic_addresses(self):
        result = translate_export(self.export())
        names = [i['name'] for i in result['interfaces']]
        self.assertEqual(names, ['port1', 'port2', 'port3', 'vlan10'])
        self.assertEqual(result['interfaces'][0]['addresses'], ['198.51.100.1/24', '2001:db8:1::1/64'])
        vlan = result['interfaces'][3]
        self.assertEqual((vlan['parent'], vlan['vlans'], vlan['addresses']), ('port2', [10], []))
        self.assertTrue(vlan['config']['unresolved'])

    def test_zones_include_pseudo_zones_for_unzoned_interfaces(self):
        zones = {z['zone']: z['interfaces'] for z in translate_export(self.export())['zones']}
        self.assertEqual(zones, {'LAN': ['port2', 'port3'], 'port1': ['port1'], 'vlan10': ['vlan10']})

    def test_policy_order_and_service_ports(self):
        result = translate_export(self.export())
        self.assertEqual([p['rule_id'] for p in result['policies']], ['7', '3', '9', '4'])
        services = [s['value'] for s in result['policies'][0]['selectors'] if s['role'] == 'service']
        self.assertEqual(services[1], dict(protocol='tcp', destination_port_start=8000, destination_port_end=8080,
                                           source_port_start=1024, source_port_end=65535))
        self.assertEqual(_portrange('53'), dict(destination_port_start=53, destination_port_end=53, source_port_start=0, source_port_end=65535))

    def test_policy_allow_with_zone_context(self):
        result = translate_export(self.export())
        args = ('192.0.2.10', '198.51.100.5', 'tcp', 443)
        self.assertEqual(self.evaluate(result, *args, source_zone='LAN', destination_zone='port1')['decision'], 'allow')
        self.assertEqual(self.evaluate(result, *args, source_zone='port1', destination_zone='LAN')['decision'], 'deny')
        self.assertEqual(self.evaluate(result, *args)['decision'], 'unknown')

    def test_unresolved_fqdn_rule_is_ordered_barrier(self):
        result = translate_export(self.export())
        decision = self.evaluate(result, '192.0.2.10', '198.51.100.99', 'tcp', 443, source_zone='LAN', destination_zone='port1')
        self.assertEqual((decision['decision'], decision['rule_id']), ('unknown', '3'))
        self.assertIn('fqdn', ' '.join(result['policies'][1]['details']['unresolved']))

    def test_ipv4_all_does_not_match_ipv6(self):
        result = translate_export(self.export())
        decision = self.evaluate(result, '2001:db8:1::5', '2001:db8:2::5', 'tcp', 443, source_zone='port1', destination_zone='LAN')
        self.assertEqual(decision['decision'], 'deny')

    def test_negated_address_keeps_family(self):
        self.data['cmdb/firewall/policy'] = [{'policyid': 1, 'srcintf': [{'name': 'any'}], 'dstintf': [{'name': 'any'}],
            'srcaddr': [{'name': 'lan-net'}], 'srcaddr-negate': 'enable', 'dstaddr': [{'name': 'all'}],
            'service': [{'name': 'ALL'}], 'action': 'accept', 'schedule': 'always'}]
        result = translate_export(self.export())
        context = dict(source_zone='port1', destination_zone='LAN')
        self.assertEqual(self.evaluate(result, '192.0.2.5', '203.0.113.5', 'udp', 53, **context)['decision'], 'deny')
        self.assertEqual(self.evaluate(result, '10.1.1.1', '203.0.113.5', 'udp', 53, **context)['decision'], 'allow')
        self.assertEqual(self.evaluate(result, '2001:db8::1', '2001:db8::2', 'udp', 53, **context)['decision'], 'deny')

    def test_vip_policy_matches_external_address_and_nat_candidate(self):
        result = translate_export(self.export())
        destinations = [s['value'] for s in result['policies'][2]['selectors'] if s['role'] == 'destination']
        self.assertEqual(destinations, ['198.51.100.20/32'])
        vip = next(n for n in result['nat'] if n['rule_id'] == 'web-vip')
        self.assertEqual((vip['translation_kind'], vip['translation']), ('destination', {'address': '192.0.2.20', 'port': 8443}))
        ranged = next(n for n in result['nat'] if n['rule_id'] == 'pool-vip')
        self.assertEqual((ranged['translation_kind'], ranged['translation']), ('unsupported', {}))

    def test_policy_snat_is_not_allocated(self):
        snat = [n for n in translate_export(self.export())['nat'] if n['rule_set'] == 'policy-snat:root']
        self.assertEqual(len(snat), 1)
        self.assertEqual((snat[0]['rule_id'], snat[0]['translation_kind']), ('7', 'unsupported'))

    def test_unsupported_conditions_and_disabled(self):
        self.data['cmdb/firewall/policy'][0].update({'groups': [{'name': 'staff'}], 'schedule': 'weekdays'})
        policies = translate_export(self.export())['policies']
        self.assertEqual(len(policies[0]['details']['unresolved']), 2)
        self.assertFalse(policies[3]['enabled'])

    def test_intrazone_allow_is_first_barrier(self):
        self.data['cmdb/system/zone'][0]['intrazone'] = 'allow'
        result = translate_export(self.export())
        self.assertEqual(result['policies'][0]['rule_id'], 'intrazone:LAN')
        decision = self.evaluate(result, '192.0.2.5', '203.0.113.5', 'tcp', 22, source_zone='LAN', destination_zone='LAN')
        self.assertEqual(decision['decision'], 'unknown')

    def test_static_routes_without_rib(self):
        result = translate_export(self.export())
        self.assertEqual([(r['destination'], r['route_type']) for r in result['routes']],
                         [('0.0.0.0/0', 'forward'), ('10.0.0.0/8', 'discard'), ('::/0', 'forward')])
        self.assertIn('SD-WAN', result['route_candidates'][2]['unresolved'][0])

    def test_active_rib_replaces_configured_routes(self):
        self.data['monitor/router/ipv4'] = [
            {'ip_version': 4, 'type': 'connect', 'ip_mask': '192.0.2.0/24', 'gateway': '0.0.0.0', 'interface': 'port2', 'distance': 0, 'vrf': 0},
            {'ip_version': 4, 'type': 'static', 'ip_mask': '0.0.0.0/0', 'gateway': '198.51.100.254', 'interface': 'port1', 'distance': 10, 'vrf': 0},
            {'ip_version': 4, 'type': 'static', 'ip_mask': '10.9.0.0/16', 'gateway': '10.9.9.254', 'interface': 'port9', 'vrf': 0}]
        result = translate_export(self.export())
        self.assertEqual([(r['destination'], r['route_type']) for r in result['routes']], [('192.0.2.0/24', 'connected'), ('0.0.0.0/0', 'forward')])
        self.assertIn('reason', result['rib_evidence'][2])

    def test_missing_required_endpoint_rejected(self):
        del self.data['cmdb/firewall/policy']
        with self.assertRaises(ValueError):
            translate_export(self.export())

    def test_central_nat_ignores_policy_snat(self):
        self.data['cmdb/system/settings']['central-nat'] = 'enable'
        result = translate_export(self.export())
        self.assertFalse([n for n in result['nat'] if n['rule_set'].startswith('policy-snat')])
        self.assertTrue(any(f.get('setting') == 'central-nat' for f in result['findings']))

    def test_normalized_envelopes_validate_and_redact(self):
        requests = normalized_submissions(self.export(), 'lab', 'fgt-a-root')
        self.assertEqual([r['data_type'] for r in requests], ['interface', 'security_zone', 'route', 'policy', 'nat', 'topology'])
        for request in requests[:5]:
            normalize(request['data_type'], request['payload'])
        self.assertNotIn('secret-value', json.dumps(requests))

    def test_cli_export(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'export.json'
            path.write_text(json.dumps(self.export()), encoding='utf-8')
            root = Path(__file__).resolve().parents[1]
            output = subprocess.run([sys.executable, str(root / 'examples/ansible/fortigate/normalize.py'), str(path),
                '--namespace', 'lab', '--external-device-id', 'fgt-a-root'], capture_output=True, text=True, check=True,
                env={'PYTHONPATH': str(root / 'src')})
        self.assertEqual(len(json.loads(output.stdout)), 6)

    def test_collector_uses_bearer_vdom_and_records_optional_failures(self):
        seen = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class Opener:
            def open(opener, request, timeout):
                seen.append(request)
                path = request.full_url.split('/api/v2/')[1].split('?')[0]
                if path.startswith('monitor/'):
                    raise HTTPError(request.full_url, 403, 'Forbidden', {}, None)
                return Response(json.dumps(ok(self.data.get(path, []))).encode())

        export = collect('https://fgt.example:8443', 'tok', 'root', opener=Opener())
        self.assertEqual(len(seen), len(ENDPOINTS))
        self.assertEqual(seen[0].get_header('Authorization'), 'Bearer tok')
        self.assertTrue(all(r.full_url.endswith('?vdom=root') and r.get_method() == 'GET' for r in seen))
        self.assertEqual(export['responses']['monitor/router/ipv4'], {'status': 'error', 'http_status': 403})
        self.assertEqual((export['serial'], export['version']), ('FGT60F0000000001', 'v7.2.8'))
        with self.assertRaises(ValueError):
            collect('http://fgt.example', 'tok', 'root', opener=Opener())


if __name__ == '__main__':
    unittest.main()
