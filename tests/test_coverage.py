import unittest
from navis_common.coverage import policy_coverage


class CoverageTests(unittest.TestCase):
    def test_all_hops_require_complete_policy_data(self):
        hops = [{"device_id": "r1", "policy_coverage": "complete", "policy_not_applicable": True, "policy_evaluations": []},
                {"device_id": "fw", "policy_coverage": "complete", "policy_evaluations": [{"decision": "allow"}]}]
        self.assertTrue(policy_coverage(hops, destination_reached=True)["complete"])
        hops[0]["policy_coverage"] = "unknown"
        self.assertFalse(policy_coverage(hops, destination_reached=True)["complete"])
        hops[0]["policy_coverage"] = "complete"
        hops[1]["policy_evaluations"][0]["decision"] = "unknown"
        self.assertFalse(policy_coverage(hops, destination_reached=True)["complete"])
        self.assertFalse(policy_coverage(hops, destination_reached=False)["complete"])

    def test_empty_policy_requires_explicit_non_applicability(self):
        hop = {"device_id": "router", "policy_coverage": "complete", "policy_evaluations": []}
        self.assertFalse(policy_coverage([hop], destination_reached=True)["complete"])
        hop["policy_not_applicable"] = True
        self.assertTrue(policy_coverage([hop], destination_reached=True)["complete"])
