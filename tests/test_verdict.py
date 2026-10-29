import unittest
from navis_common.verdict import derive_verdict


class VerdictTests(unittest.TestCase):
    def test_explicit_deny_identifies_blocking_point(self):
        result = derive_verdict([{"device_id": "fw", "policy_evaluations": [{"decision": "deny", "reason": "rule set default", "rule_id": None}]}])
        self.assertEqual((result["status"], result["blocking_point"]), ("blocked", "fw"))

    def test_allow_without_end_to_end_evidence_is_unknown(self):
        self.assertEqual(derive_verdict([{"device_id": "fw", "policy_evaluations": [{"decision": "allow"}]}])["status"], "unknown")
