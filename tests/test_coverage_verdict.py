import unittest
from navis_common.verdict import derive_verdict


class CoverageVerdictTests(unittest.TestCase):
    def test_allowed_requires_complete_evidence_and_destination(self):
        hops = [{"device_id": "fw", "policy_evaluations": [{"decision": "allow"}]}]
        self.assertEqual(derive_verdict(hops, destination_reached=True, evidence_complete=True)["status"], "allowed")
        self.assertEqual(derive_verdict(hops, destination_reached=True, evidence_complete=False)["status"], "unknown")
        self.assertEqual(derive_verdict(hops, destination_reached=False, evidence_complete=True)["status"], "unknown")

    def test_unknown_policy_prevents_allow(self):
        hops = [{"device_id": "fw", "policy_evaluations": [{"decision": "unknown"}]}]
        self.assertEqual(derive_verdict(hops, destination_reached=True, evidence_complete=True)["status"], "unknown")
