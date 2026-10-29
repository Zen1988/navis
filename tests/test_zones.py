import unittest
from navis_common.zones import resolve_zone, rule_recommendation


class ZoneTests(unittest.TestCase):
    def test_resolve_and_ambiguity(self):
        memberships = {"in": ["APP"], "out": ["DB", "DMZ"]}
        self.assertEqual(resolve_zone("in", memberships).zone, "APP")
        self.assertEqual(resolve_zone("out", memberships).status, "ambiguous")
        self.assertEqual(resolve_zone("missing", memberships).status, "unknown")

    def test_recommendation_includes_both_zones(self):
        result = rule_recommendation(device_id="fw", source="192.0.2.1", destination="198.51.100.10", protocol="tcp", destination_port=443, ingress="in", egress="out", memberships={"in": ["APP"], "out": ["DB"]}, reason="default deny")
        self.assertEqual((result["source_zone"], result["destination_zone"], result["status"]), ("APP", "DB", "draft"))
        self.assertEqual(rule_recommendation(device_id="fw", source="a", destination="b", protocol="tcp", destination_port=443, ingress="in", egress="out", memberships={}, reason="missing")["status"], "incomplete")
