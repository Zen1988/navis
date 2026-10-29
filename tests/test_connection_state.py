import unittest
from navis_common.connection_state import evaluate_return, evaluate_connection


class ConnectionStateTests(unittest.TestCase):
    def test_stateful_requires_explicit_session_evidence(self):
        result = evaluate_return(mode="stateful", forward_decision="allow", session_supported=True)
        self.assertEqual(result["decision"], "allow")
        self.assertIn("if a session is established", result["reason"])
        self.assertEqual(evaluate_return(mode="stateful", forward_decision="allow")["decision"], "unknown")

    def test_stateless_requires_reverse_policy(self):
        self.assertEqual(evaluate_return(mode="stateless", forward_decision="allow", reverse_decision="deny")["decision"], "deny")
        self.assertEqual(evaluate_return(mode="stateless", forward_decision="allow")["decision"], "unknown")
        self.assertEqual(evaluate_return(mode="unknown", forward_decision="allow")["decision"], "unknown")

    def test_stateful_still_requires_return_route(self):
        self.assertEqual(evaluate_connection(mode="stateful", forward_decision="allow", session_supported=True, return_route="reachable")["decision"], "allow")
        self.assertEqual(evaluate_connection(mode="stateful", forward_decision="allow", session_supported=True, return_route="unknown")["decision"], "unknown")
        self.assertEqual(evaluate_connection(mode="stateless", forward_decision="allow", reverse_decision="deny", return_route="reachable")["decision"], "deny")
