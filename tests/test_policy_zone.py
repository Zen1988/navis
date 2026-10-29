import unittest
from navis_common.policy_selectors import evaluate_policy


class PolicyZoneTests(unittest.TestCase):
    def test_zone_match_and_missing(self):
        selectors = [{"role": "source", "kind": "any"}, {"role": "destination", "kind": "any"},
                     {"role": "service", "kind": "any"}, {"role": "source_zone", "kind": "zone", "value": "APP"},
                     {"role": "destination_zone", "kind": "zone", "value": "DB"}]
        rules = [{"rule_id": "r", "enabled": True, "selectors_complete": True, "action": "allow", "selectors": selectors}]
        args = (rules, "deny", "192.0.2.1", "198.51.100.1", "tcp", 443)
        self.assertEqual(evaluate_policy(*args, complete=True, source_zone="APP", destination_zone="DB")["decision"], "allow")
        self.assertEqual(evaluate_policy(*args, complete=True, source_zone=None, destination_zone="DB")["decision"], "unknown")
        self.assertEqual(evaluate_policy(*args, complete=True, source_zone="DMZ", destination_zone="DB")["decision"], "deny")
