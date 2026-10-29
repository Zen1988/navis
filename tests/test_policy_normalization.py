import unittest
from navis_common.policy_normalization import normalize_enforcement


class PolicyNormalizationTests(unittest.TestCase):
    def test_no_acl_is_explicit_allow_only_when_confirmed(self):
        self.assertEqual(normalize_enforcement(state="not_applicable", complete=True)["default_action"], "allow")
        self.assertEqual(normalize_enforcement(state="not_applicable", complete=False)["default_action"], "unknown")

    def test_acl_default_comes_from_adapter(self):
        result = normalize_enforcement(state="enforced", rules=[], default_action="deny", complete=True)
        self.assertEqual(result["default_action"], "deny")
        self.assertEqual(normalize_enforcement(state="enforced", rules=[], complete=True)["default_action"], "unknown")
