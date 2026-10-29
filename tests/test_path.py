import unittest
from navis_common.path import HopEvidence, walk_path


class PathTests(unittest.TestCase):
    def test_longest_prefix_and_order(self):
        evidence = [HopEvidence("a", "0.0.0.0/0", "wrong", "default"), HopEvidence("a", "10.0.0.0/24", "b", "specific"), HopEvidence("b", "10.0.0.0/24", "c", "second", enforcement="fw")]
        result = walk_path("a", "c", "10.0.0.2", evidence)
        self.assertEqual([hop["device_id"] for hop in result["hops"]], ["a", "b", "c"])
        self.assertEqual(result["hops"][1]["type"], "firewall")
        self.assertEqual(result["status"], "unknown")

    def test_loop_and_ambiguous(self):
        result = walk_path("a", "c", "10.0.0.1", [HopEvidence("a", "10.0.0.0/24", "a", "r")])
        self.assertEqual(result["reason"], "routing loop")
        result = walk_path("a", "c", "10.0.0.1", [HopEvidence("a", "10.0.0.0/24", "b", "r1"), HopEvidence("a", "10.0.0.0/24", "c", "r2")])
        self.assertEqual(result["reason"], "multiple equally specific route candidates")
