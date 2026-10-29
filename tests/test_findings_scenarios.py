import unittest
from navis_common.findings import trace_findings


class FindingScenarioTests(unittest.TestCase):
    def test_missing_route_and_policy_are_attributed(self):
        hops = [{"device_id": "router", "policy_coverage": "partial",
                 "stop_reason": "No matching route data was found for this device and routing context",
                 "policy_evaluations": [{"decision": "unknown", "reason": "ACL incomplete"}]}]
        findings = trace_findings(hops, [{"device_id": "source"}], [{"device_id": "destination"}])
        self.assertEqual({item["code"] for item in findings}, {"POLICY_COVERAGE_INCOMPLETE", "PATH_EVIDENCE_MISSING", "POLICY_EVIDENCE_INCOMPLETE"})
        self.assertTrue(all(item["device_id"] == "router" for item in findings))

    def test_definite_deny_is_not_a_missing_path_finding(self):
        hops = [{"device_id": "fw", "stop_reason": "policy denied traffic", "policy_coverage": "complete", "policy_evaluations": [{"decision": "deny"}]}]
        self.assertEqual(trace_findings(hops, [{}], [{}]), [])
