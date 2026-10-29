import unittest
from navis_common.findings import trace_findings


class FindingTests(unittest.TestCase):
    def test_identifies_device_and_missing_evidence(self):
        hops = [{"device_id": "router-1", "stop_reason": "Next device connection is missing or ambiguous", "policy_evaluations": [{"decision": "unknown", "reason": "ACL missing"}]}]
        findings = trace_findings(hops, [{"device_id": "a"}], [])
        self.assertEqual(findings[0]["code"], "DESTINATION_UNRESOLVED")
        self.assertEqual(findings[1]["device_id"], "router-1")
        self.assertEqual(findings[2]["message"], "ACL missing")
