import unittest
from navis_common.auth import Principal
from navis_common.local_auth import LocalTokenVerifier


class LocalAuthTests(unittest.TestCase):
    def test_token_matching_and_minimum_length(self):
        with self.assertRaises(ValueError):
            LocalTokenVerifier("short", Principal("a", frozenset()))
        principal = Principal("client", frozenset({"inventory:write"}), "issuer")
        verifier = LocalTokenVerifier("x" * 32, principal)
        self.assertEqual(verifier.verify("x" * 32), principal)
        self.assertIsNone(verifier.verify("y" * 32))
