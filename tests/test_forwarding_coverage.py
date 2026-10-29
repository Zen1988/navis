import unittest
from navis_common.coverage import forwarding_coverage, overall_coverage


class ForwardingCoverageTests(unittest.TestCase):
    def test_requires_reached_destination_and_installed_selection(self):
        hops = [{"device_id": "router", "route_assessment": {"status": "selected"}}, {"device_id": "destination"}]
        self.assertTrue(forwarding_coverage(hops, [], destination_reached=True, evidence_unchanged=True)["complete"])
        self.assertFalse(forwarding_coverage(hops, [], destination_reached=True, evidence_unchanged=False)["complete"])
        hops[0]["route_assessment"]["status"] = "unknown"
        self.assertFalse(forwarding_coverage(hops, [], destination_reached=True, evidence_unchanged=True)["complete"])

    def test_overall_requires_each_independent_check(self):
        checks = dict(forwarding=True, policy=True, nat=True, return_path=True, alternatives=True, evidence_unchanged=True)
        self.assertTrue(overall_coverage(**checks)["complete"])
        for key in checks:
            incomplete = dict(checks, **{key: False})
            self.assertFalse(overall_coverage(**incomplete)["complete"])
