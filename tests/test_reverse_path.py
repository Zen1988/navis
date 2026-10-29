import unittest
from navis_common.nat import Packet
from navis_common.reverse_path import ReverseTransition, apply_reverse_mapping, return_path_verdict, trace_reverse_path, assess_reverse_paths
from navis_common.path_search import ForwardingState


class ReversePathTests(unittest.TestCase):
    def test_mapping_requires_matching_established_session(self):
        before = Packet("10.0.0.5", "192.0.2.9", "tcp", 60000, 8443)
        after = Packet("198.51.100.10", "192.0.2.1", "tcp", 50000, 443)
        transition = ReverseTransition("fw", before, after, True)
        self.assertEqual(apply_reverse_mapping("fw", before, [transition])[0], after)
        self.assertEqual(apply_reverse_mapping("fw", after, [transition])[1]["status"], "unknown")
        self.assertEqual(apply_reverse_mapping("fw", before, [ReverseTransition("fw", before, after, False)])[1]["status"], "unknown")

    def test_conflicting_mappings_are_never_guessed(self):
        before = Packet("10.0.0.5", "192.0.2.9", "tcp", 60000, 8443)
        after = Packet("198.51.100.10", "192.0.2.1", "tcp", 50000, 443)
        transition = ReverseTransition("fw", before, after, True)
        self.assertEqual(apply_reverse_mapping("fw", before, [transition, transition])[1]["reason"], "ambiguous reverse NAT mappings")

    def test_return_route_requires_all_evidence(self):
        self.assertEqual(return_path_verdict(destination_reached=True, route_coverage_complete=True, policy_decision="allow", nat_decision="allow")["status"], "reachable")
        self.assertEqual(return_path_verdict(destination_reached=True, route_coverage_complete=False, policy_decision="allow", nat_decision="allow")["status"], "unknown")

    def test_reverse_mapping_precedes_route_lookup(self):
        before = Packet("10.0.0.5", "192.0.2.9", "tcp", 60000, 8443)
        after = Packet("198.51.100.10", "192.0.2.1", "tcp", 50000, 443)
        start = ForwardingState("fw", "vrf", before.destination, before.source, before.protocol, before.destination_port, before.source_port)
        target = ForwardingState("client", "vrf", after.destination, after.source, after.protocol, after.destination_port, after.source_port)
        lookup = lambda state: ([{"prefix": "192.0.2.1/32", "route_type": "forward", "next_states": [target]}], True, "installed")
        result = trace_reverse_path(start, lambda state: state.device_id == "client", lookup, lambda _: {"decision": "allow"}, [ReverseTransition("fw", before, after, True)], nat_absence_confirmed=lambda _: True)
        self.assertEqual(result["paths"][0]["reason"], "destination reached")
        self.assertEqual(assess_reverse_paths(result)["status"], "candidate_reachable")

    def test_missing_nat_coverage_stops_reverse_trace(self):
        state = ForwardingState("router", "vrf", "192.0.2.1", "10.0.0.5", "tcp", 50000, 443)
        result = trace_reverse_path(state, lambda _: False, lambda _: ([], True, "installed"), lambda _: {"decision": "allow"}, [])
        self.assertEqual(result["paths"][0]["reason"], "NAT decision unknown")

    def test_incomplete_branch_prevents_definitive_return_verdict(self):
        result = {"complete": False, "paths": [{"status": "blocked"}, {"status": "unknown"}]}
        self.assertEqual(assess_reverse_paths(result)["status"], "unknown")
