import unittest
from navis_common.coverage import applicability_coverage


class ApplicabilityTests(unittest.TestCase):
    def test_context_and_conflicts(self):
        records = [{"direction": "ingress", "interface": "in", "state": "enforced"},
                   {"direction": "egress", "interface": "out", "state": "not_applicable"}]
        self.assertEqual(applicability_coverage(records, "in", "out"), {"ingress": "enforced", "egress": "not_applicable"})
        self.assertEqual(applicability_coverage(records, None, "out")["ingress"], "unknown")
        records.append({"direction": "ingress", "interface": "in", "state": "not_applicable"})
        self.assertEqual(applicability_coverage(records, "in", "out")["ingress"], "unknown")
