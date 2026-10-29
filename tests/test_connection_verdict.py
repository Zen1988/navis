import unittest
from navis_common.verdict import connection_verdict


class ConnectionVerdictTests(unittest.TestCase):
    def test_requires_every_component_and_all_alternatives(self):
        evidence = dict(forwarding="allow", nat="allow", policy="allow", return_path="allow", alternatives_complete=True)
        self.assertEqual(connection_verdict(**evidence)["status"], "allowed")
        for key in ("forwarding", "nat", "policy", "return_path"):
            changed = dict(evidence, **{key: "unknown"})
            self.assertIn(key, connection_verdict(**changed)["missing"])
        self.assertEqual(connection_verdict(**dict(evidence, alternatives_complete=False))["status"], "unknown")

    def test_candidate_block_does_not_prove_all_alternatives_blocked(self):
        evidence = dict(forwarding="allow", nat="allow", policy="blocked", return_path="unknown")
        self.assertEqual(connection_verdict(**evidence, alternatives_complete=False)["status"], "unknown")
        self.assertEqual(connection_verdict(**evidence, alternatives_complete=True)["status"], "unknown")
        self.assertEqual(connection_verdict(**evidence, alternatives_complete=True, all_paths_blocked=True)["status"], "blocked")
