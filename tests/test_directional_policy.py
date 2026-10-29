import unittest
from navis_common.directional_policy import combine_directional_policy


class DirectionalPolicyTests(unittest.TestCase):
    def test_ingress_and_egress(self):
        self.assertEqual(combine_directional_policy(source_egress="allow", destination_ingress="not_applicable")["decision"], "allow")
        self.assertEqual(combine_directional_policy(source_egress="allow", destination_ingress="deny")["decision"], "deny")
        self.assertEqual(combine_directional_policy(source_egress="unknown", destination_ingress="allow")["decision"], "unknown")

    def test_rejects_unknown_vocabulary(self):
        with self.assertRaises(ValueError):
            combine_directional_policy(source_egress="permit", destination_ingress="allow")
