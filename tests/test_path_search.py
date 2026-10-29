import unittest
from navis_common.path_search import ForwardingState, explore_paths, alternative_verdict


class PathSearchTests(unittest.TestCase):
    def test_alternative_paths_and_loop(self):
        a = ForwardingState("a", "default", "10.0.0.1")
        b = ForwardingState("b", "default", "10.0.0.1")
        c = ForwardingState("c", "default", "10.0.0.1")
        def lookup(state):
            next_states = [b, c] if state == a else [a]
            return ([{"prefix": "10.0.0.0/24", "route_type": "forward", "next_states": next_states}], True, "installed")
        result = explore_paths(a, lambda state: state == c, lookup)
        self.assertEqual({path["reason"] for path in result["paths"]}, {"destination reached", "routing loop"})
        self.assertFalse(result["complete"])

    def test_unresolved_does_not_become_reachable(self):
        state = ForwardingState("a", "vrf", "10.0.0.1")
        result = explore_paths(state, lambda _: False, lambda _: ([{"prefix": "0.0.0.0/0", "route_type": "forward"}], True, "installed"))
        self.assertEqual(result["paths"][0]["reason"], "next hop unresolved")

    def test_policy_blocks_one_branch_and_unknown_stops_another(self):
        a = ForwardingState("a", "vrf", "10.0.0.1")
        b = ForwardingState("b", "vrf", "10.0.0.1")
        c = ForwardingState("c", "vrf", "10.0.0.1")
        def lookup(state):
            return ([{"prefix": "10.0.0.0/24", "route_type": "forward", "next_states": [b, c]}], True, "installed")
        def policy(state):
            return {"decision": {"a": "allow", "b": "deny", "c": "unknown"}[state.device_id]}
        result = explore_paths(a, lambda _: False, lookup, evaluate_policy=policy)
        self.assertEqual({p["status"] for p in result["paths"]}, {"blocked", "unknown"})
        self.assertFalse(result["complete"])

    def test_policy_receives_branch_ingress_context(self):
        a = ForwardingState("a", "vrf", "10.0.0.1", ingress_interface="eth-in")
        result = explore_paths(a, lambda _: True, lambda _: ([], True, "installed"),
                               evaluate_policy=lambda state: {"decision": "allow" if state.ingress_interface == "eth-in" else "unknown"})
        self.assertEqual(result["paths"][0]["status"], "candidate")

    def test_nat_changes_route_destination_and_unknown_stops(self):
        from dataclasses import replace
        a = ForwardingState("a", "vrf", "198.51.100.10", "192.0.2.1", "tcp", 443)
        b = ForwardingState("b", "vrf", "10.10.1.10", "192.0.2.1", "tcp", 443)
        def lookup(state):
            return ([{"prefix": "10.10.1.0/24", "route_type": "forward", "next_states": [b]}], True, "installed")
        def nat(state):
            return replace(state, destination="10.10.1.10"), {"status": "translated"}
        result = explore_paths(a, lambda state: state.device_id == "b", lookup, evaluate_nat=nat)
        self.assertEqual(result["paths"][0]["reason"], "destination reached")
        result = explore_paths(a, lambda _: False, lookup, evaluate_nat=lambda state: (state, {"status": "unknown"}))
        self.assertEqual(result["paths"][0]["reason"], "NAT decision unknown")

    def test_aggregate_verdict(self):
        self.assertEqual(alternative_verdict({"complete": True, "paths": [{"status": "blocked"}, {"status": "discard"}]})["status"], "blocked")
        self.assertEqual(alternative_verdict({"complete": True, "paths": [{"status": "blocked"}, {"status": "candidate"}]})["status"], "unknown")
        self.assertEqual(alternative_verdict({"complete": False, "paths": [{"status": "blocked"}]})["status"], "unknown")
        self.assertEqual(alternative_verdict({"complete": True, "paths": []})["status"], "unknown")

    def test_path_limit_does_not_claim_complete(self):
        a = ForwardingState("a", "vrf", "10.0.0.1")
        routes = [{"prefix": "10.0.0.0/24", "route_type": "discard"} for _ in range(3)]
        result = explore_paths(a, lambda _: False, lambda _: (routes, True, "installed"), max_paths=1)
        self.assertFalse(result["complete"])
        self.assertEqual(alternative_verdict(result)["status"], "unknown")

    def test_explicit_nat_before_policy(self):
        from dataclasses import replace
        state = ForwardingState("fw", "vrf", "198.51.100.10")
        nat = lambda item: (replace(item, destination="10.0.0.10"), {"status": "translated"})
        policy = lambda item: {"decision": "allow" if item.destination == "10.0.0.10" else "deny"}
        result = explore_paths(state, lambda item: item.destination == "10.0.0.10", lambda _: ([], True, "installed"), evaluate_policy=policy, evaluate_nat=nat, processing_order="nat_then_policy")
        self.assertEqual(result["paths"][0]["status"], "candidate")
        with self.assertRaises(ValueError):
            explore_paths(state, lambda _: False, lambda _: ([], True, "installed"), processing_order="unknown")
