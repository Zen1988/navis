import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from navis_common.ios_adapter import CONFIG_COMMANDS, ace, parse_acls, parse_interfaces, static_routes, rib_routes, translate_export, normalized_submissions
from navis_common.policy_selectors import evaluate_policy
from navis_api.normalized_adapter import normalize
from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.nat import Packet


class IosTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            'interfaces': 'interface GigabitEthernet0/0\n description LAN\n vrf forwarding BLUE\n ip address 192.0.2.1 255.255.255.0\n ipv6 address 2001:db8::1/64\n ip access-group WEB in\n ip nat inside\n!\ninterface GigabitEthernet0/1\n ip address 198.51.100.1 255.255.255.0\n ip nat outside\n!',
            'acls': 'ip access-list extended WEB\n 20 deny ip any any\n 10 permit tcp 192.0.2.0 0.0.0.255 host 198.51.100.5 eq 443\n!',
            'routes': 'ip route vrf BLUE 0.0.0.0 0.0.0.0 192.0.2.254 10\nipv6 route 2001:db8:2::/64 GigabitEthernet0/1 2001:db8::2\nip route 203.0.113.0 255.255.255.0 Null0',
            'nat': 'ip nat inside source static 192.0.2.5 198.51.100.5\nip nat inside source list NAT interface GigabitEthernet0/1 overload',
            'vrfs': 'vrf definition BLUE\n rd 65000:1\n!'}

    def export(self, extra=None):
        results = [dict(command=CONFIG_COMMANDS[k], stdout=[v]) for k,v in self.config.items()]
        results.extend(extra or [])
        return dict(device_id='ios-a', collected_at='2026-10-30T00:00:00Z', results=results)

    def test_interfaces_and_vrf(self):
        result = translate_export(self.export())
        self.assertEqual(result['interfaces'][0]['vrf'], 'BLUE')
        self.assertEqual(result['interfaces'][0]['addresses'], ['192.0.2.1/24','2001:db8::1/64'])

    def test_static_vrf_recursive_and_discard(self):
        routes, candidates = static_routes(self.config['routes'])
        self.assertEqual(len(routes), 3)
        self.assertEqual(routes[0]['vrf'], 'BLUE')
        self.assertIsNone(routes[0]['interface'])
        self.assertEqual(routes[2]['route_type'], 'discard')
        self.assertEqual(routes[0]['details']['administrative_distance'], 10)

    def test_acl_order_and_direction(self):
        rules = translate_export(self.export())['policies']
        self.assertEqual([r['rule_id'] for r in rules], ['10','20'])
        self.assertEqual(rules[0]['details']['interface_condition'], dict(native_id='GigabitEthernet0/0',direction='in',ip_version=4))
        self.assertFalse(rules[0]['details']['selectors_complete'])

    def test_acl_traversal_and_family_required(self):
        rules = translate_export(self.export())['policies']
        for rule in rules:
            rule['selectors_complete'] = True
        args = (rules, 'deny', '192.0.2.10', '198.51.100.5', 'tcp', 443)
        self.assertEqual(evaluate_policy(*args, complete=True, ingress_interface='GigabitEthernet0/0')['decision'], 'allow')
        self.assertEqual(evaluate_policy(*args, complete=True)['decision'], 'unknown')
        self.assertEqual(evaluate_policy(*args, complete=True, egress_interface='GigabitEthernet0/0')['decision'], 'unknown')
        self.assertEqual(evaluate_policy(*args, complete=True, ingress_interface='GigabitEthernet0/1')['decision'], 'unknown')

    def test_source_ports_and_established(self):
        result = ace('permit tcp any range 1024 65535 host 198.51.100.5 eq 443 established log', 4)
        self.assertTrue(result['parsed'])
        service = result['selectors'][2]['value']
        self.assertEqual(service['source_port_start'], 1024)
        self.assertEqual(service['tcp_flags_any'], ['ack','rst'])

    def test_discontiguous_wildcard_not_widened(self):
        self.assertFalse(ace('permit ip 192.0.2.0 0.0.5.255 any', 4)['parsed'])

    def test_unsupported_acl_is_ordered_barrier(self):
        self.config['acls'] = 'ip access-list extended WEB\n 5 permit tcp any any eq https time-range NIGHT\n 10 permit ip any any\n!'
        rules = translate_export(self.export())['policies']
        for rule in rules:
            rule['selectors_complete'] = rule['details']['syntax_parsed']
        result = evaluate_policy(rules, 'deny', '192.0.2.5','198.51.100.5','tcp',443,complete=True,ingress_interface='GigabitEthernet0/0')
        self.assertEqual(result['decision'], 'unknown')
        self.assertEqual(result['rule_id'], '5')

    def test_numbered_standard_acl(self):
        result = parse_acls('access-list 10 permit 192.0.2.0 0.0.0.255\naccess-list 10 deny any')
        self.assertEqual(len(result[(4,'10')]['entries']), 2)
        self.assertTrue(result[(4,'10')]['entries'][0]['parsed'])

    def test_ipv6_acl(self):
        result = ace('10 permit tcp 2001:db8::/64 host 2001:db8:1::5 eq 443', 6)
        self.assertTrue(result['parsed'])

    def test_missing_acl_not_allow(self):
        self.config['acls'] = ''
        rules = translate_export(self.export())['policies']
        self.assertEqual(rules[0]['action'], 'unknown')

    def test_failed_config_reported(self):
        export = self.export()
        export['results'][0]['stdout'] = ['% Invalid input detected']
        result = translate_export(export)
        self.assertEqual(result['interfaces'], [])
        self.assertTrue(result['findings'])

    def test_nat_candidates_have_unknown_stage(self):
        nat = translate_export(self.export())['nat']
        self.assertEqual(nat[0]['translation'], dict(address='198.51.100.5'))
        self.assertEqual(nat[1]['translation_kind'], 'unknown')
        self.assertTrue(all(not r['details']['selectors_complete'] for r in nat))

    def test_active_rib_ecmp_vrf_and_no_static_mix(self):
        output = 'Routing Table: BLUE\nO E2 203.0.113.0/24 [110/20] via 192.0.2.2, 00:01:20, GigabitEthernet0/0\n [110/20] via 192.0.2.3, 00:01:20, Gi0/0\nC 192.0.2.0/24 is directly connected, GigabitEthernet0/0\nL 192.0.2.1/32 is directly connected, GigabitEthernet0/0'
        result = translate_export(self.export([dict(command='show ip route vrf *', stdout=[output])]))
        self.assertEqual(len(result['routes']), 3)
        self.assertEqual([r['next_hop'] for r in result['routes'][:2]], ['192.0.2.2','192.0.2.3'])
        self.assertTrue(all(r['details']['origin'] == 'ios_active_rib' and r['vrf'] == 'BLUE' for r in result['routes']))
        self.assertEqual(result['routes'][1]['interface'], 'GigabitEthernet0/0')

    def test_ipv6_rib_multiline(self):
        routes, evidence = rib_routes('O 2001:db8:2::/64 [110/20]\n via 2001:db8::2, GigabitEthernet0/0', parse_interfaces(self.config['interfaces']), 6, 'BLUE')
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]['next_hop'], '2001:db8::2')

    def test_classful_rib_not_guessed(self):
        routes, evidence = rib_routes('O 10.0.0.0 [110/20] via 192.0.2.2, GigabitEthernet0/0', parse_interfaces(self.config['interfaces']))
        self.assertEqual(routes, [])
        self.assertTrue(evidence)

    def test_rib_cross_vrf_interface_not_used(self):
        routes, evidence = rib_routes('C 192.0.2.0/24 is directly connected, GigabitEthernet0/0', parse_interfaces(self.config['interfaces']))
        self.assertEqual(routes, [])
        self.assertIn('another VRF', evidence[0]['reason'])

    def test_database_policy_reader_uses_actual_ingress(self):
        def evaluate(ingress, egress):
            cursor = Mock()
            details = dict(selectors_complete=True, interface_condition=dict(native_id='GigabitEthernet0/0',direction='in',ip_version=4))
            cursor.fetchall.side_effect = [
                [('set','deny','ios-a:GigabitEthernet0/0','snapshot','stateless',{},True)],
                [('rule','10','allow',True,details)],
                [(role,False,True,None,None,None,None,None,None,None,None,None) for role in ('source','destination','service')]]
            with patch.object(PostgresTraceProcessor,'_zone_memberships',return_value={}):
                return PostgresTraceProcessor._policies(cursor,'build','device',Packet('192.0.2.5','198.51.100.5','tcp',443),ingress,egress)[0]
        self.assertEqual(evaluate('GigabitEthernet0/0',None)['decision'],'allow')
        self.assertEqual(evaluate(None,'GigabitEthernet0/0')['decision'],'unknown')

    def test_tracked_static_route_preserved_without_fabricated_forwarding(self):
        routes, candidates = static_routes('ip route 0.0.0.0 0.0.0.0 192.0.2.2 track 1')
        self.assertEqual(routes, [])
        self.assertTrue(candidates[0]['unresolved'])

    def test_sensitive_lines_redacted(self):
        self.config['interfaces'] += '\ninterface Dialer1\n ppp chap password 0 sensitive-example\n!'
        self.assertNotIn('sensitive-example', json.dumps(translate_export(self.export())))

    def test_normalized_submissions(self):
        requests = normalized_submissions(self.export(), 'ios-site', 'router-a')
        for request in requests[:4]:
            normalize(request['data_type'], request['payload'])
        self.assertEqual(len(requests), 5)

    def test_cli_export(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=root) as directory:
            path = Path(directory)/'ios.json'
            path.write_text(json.dumps(self.export()), encoding='utf-8')
            result = subprocess.run([sys.executable,str(root/'examples/ansible/cisco_ios/normalize.py'),str(path),
                '--namespace','ios','--external-device-id','router-a'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(len(json.loads(result.stdout)),5)
