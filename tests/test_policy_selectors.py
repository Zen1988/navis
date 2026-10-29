import unittest
from navis_common.policy_selectors import evaluate_policy


class PolicySelectorTests(unittest.TestCase):
    def setUp(self):
        self.rule = {"rule_id": "allow-web", "enabled": True, "action": "allow", "selectors_complete": True,
                     "selectors": [{"role": "source", "kind": "address", "value": "192.0.2.1/32"},
                                   {"role": "destination", "kind": "address", "value": "198.51.100.10/32"},
                                   {"role": "service", "kind": "service", "value": {"protocol": "tcp", "start": 443, "end": 443}}]}

    def check(self, port, complete=True):
        return evaluate_policy([self.rule], "deny", "192.0.2.1", "198.51.100.10", "tcp", port, complete=complete)

    def test_allow_and_default_deny(self):
        self.assertEqual(self.check(443)["decision"], "allow")
        self.assertEqual(self.check(22)["decision"], "deny")

    def test_incomplete_evidence(self):
        self.rule["selectors_complete"] = False
        self.assertEqual(self.check(443)["decision"], "unknown")
        self.assertEqual(self.check(22, complete=False)["decision"], "unknown")

    def test_exclusion_overrides_matching_positive(self):
        self.rule["selectors"].append({"role": "source", "kind": "address", "value": "192.0.2.1/32", "negated": True})
        self.assertEqual(self.check(443)["decision"], "deny")

    def test_unknown_earlier_rule_cannot_be_skipped(self):
        self.rule["selectors_complete"] = False
        later = {**self.rule, "rule_id": "later", "selectors_complete": True}
        result = evaluate_policy([self.rule, later], "deny", "192.0.2.1", "198.51.100.10", "tcp", 443, complete=True)
        self.assertEqual((result["decision"], result["rule_id"]), ("unknown", "allow-web"))
