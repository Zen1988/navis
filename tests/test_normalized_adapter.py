import unittest
from navis_api.normalized_adapter import normalize


class AdapterTests(unittest.TestCase):
    def test_mac_and_route(self):
        mac = normalize("mac", {"entries": [{"interface": "eth0", "mac": "AABB.CCDD.EEFF", "vlan": 10}]})
        self.assertEqual(mac[0]["mac"], "aa:bb:cc:dd:ee:ff")
        route = normalize("route", {"entries": [{"vrf": "blue", "destination": "10.0.0.0/24", "next_hop": "10.0.1.1", "interface": "eth0"}]})
        self.assertEqual(route[0]["destination"], "10.0.0.0/24")

    def test_reject_unknown_or_incomplete(self):
        for kind, payload in [("topology", {"entries": []}), ("route", {"entries": [{"vrf": "x"}]}), ("mac", {"entries": [{"interface": "x", "mac": "bad", "vlan": 1}]})]:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                normalize(kind, payload)

    def test_interface_and_neighbor(self):
        self.assertEqual(normalize("interface", {"entries": [{"name": "vlan10", "kind": "vlan", "addresses": ["10.0.0.1/24"]}]})[0]["addresses"], ["10.0.0.1/24"])
        self.assertEqual(normalize("neighbor", {"entries": [{"interface": "eth0", "vrf": "blue", "ip": "10.0.0.1", "mac": "AABB.CCDD.EEFF", "state": "reachable"}]})[0]["mac"], "aa:bb:cc:dd:ee:ff")

    def test_policy_requires_explicit_fields(self):
        policy = {"enforcement_point": "fw", "rule_set": "main", "default_action": "deny", "rule_id": "r1", "position": 1, "action": "allow", "enabled": True, "selectors": [{"role": "source", "kind": "address", "value": "172.20.0.1/24", "negated": False}]}
        self.assertEqual(normalize("policy", {"entries": [policy]})[0]["rule_id"], "r1")


if __name__ == "__main__":
    unittest.main()
