import copy
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from navis_common.path_visibility import add_visibility, visibility_graph
from navis_api.topology import TopologyService, application_view
from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.auth import Principal
from navis_common.trace import Flow


class PathVisibilityTests(unittest.TestCase):
    def flow(self, destination=True):
        return {"source": "192.0.2.10", "destination": "198.51.100.8", "protocol": "tcp", "destination_port": 443,
                "source_candidates": [{"device_id": "home"}],
                "destination_candidates": [{"device_id": "server"}] if destination else [],
                "hops": [{"device_id": "home", "name": "Home router", "route": {"next_hop": "192.0.2.254"},
                          "stop_reason": "Next device connection is missing or ambiguous", "visibility_stop": "next_device_missing"}],
                "coverage": {"destination_reached": False, "complete": False},
                "verdict": {"status": "unknown"}}

    def test_external_destination_shows_boundary_and_unknown_remainder(self):
        result = self.flow(destination=False)
        original = copy.deepcopy(result)
        graph = visibility_graph(result)
        gap = next(n for n in graph["nodes"] if n.get("role") == "segment")
        self.assertIsNone(gap["device_id"])
        self.assertIsNone(gap["unknown_hop_count"])
        self.assertEqual(gap["addresses"], ["192.0.2.254"])
        self.assertEqual(gap["reason"], "next_device_missing")
        self.assertEqual([e["status"] for e in graph["connections"]], ["unknown", "unknown"])
        self.assertEqual(graph["connections"][0]["source"], "home")
        self.assertEqual(result, original)
        self.assertEqual(graph, visibility_graph(result))

    def test_gap_between_managed_endpoints_is_not_a_direct_verified_link(self):
        graph = visibility_graph(self.flow())
        self.assertEqual(len([n for n in graph["nodes"] if n.get("role") == "segment"]), 1)
        self.assertEqual(graph["connections"][-1]["target"], "server")
        self.assertFalse(any(e["source"] == "home" and e["target"] == "server" for e in graph["connections"]))

    def test_managed_aws_endpoint_keeps_verified_inventory_across_unverified_internet(self):
        result = self.flow()
        result["destination_candidates"] = [{"device_id": "aws-server"}]
        graph = visibility_graph(result)
        nodes = {node["id"]: node for node in graph["nodes"]}
        for device in ("home", "aws-server"):
            self.assertEqual(nodes[device]["evidence_status"], "verified")
            self.assertEqual(nodes[device]["verification_scope"], "inventory_presence")
        self.assertEqual(nodes["home"]["trace_status"], "visited")
        self.assertEqual(nodes["aws-server"]["trace_status"], "not_traced")
        gap = next(n for n in graph["nodes"] if n.get("role") == "segment")
        self.assertEqual(gap["evidence_status"], "unverified")
        self.assertIsNone(gap["verification_scope"])
        self.assertEqual(result["verdict"]["status"], "unknown")

    def test_all_inventory_missing_still_returns_an_explicit_unknown_path(self):
        result = self.flow(False)
        result.update(source_candidates=[], hops=[])
        graph = visibility_graph(result)
        self.assertEqual({n["role"] for n in graph["nodes"]}, {"source", "segment", "destination"})
        self.assertTrue(all(n["placeholder"] for n in graph["nodes"]))

    def test_ambiguous_destination_does_not_pick_a_device(self):
        result = self.flow()
        result["destination_candidates"] = [{"device_id": "a"}, {"device_id": "b"}]
        graph = visibility_graph(result)
        endpoint = next(n for n in graph["nodes"] if n.get("role") == "destination")
        self.assertEqual(endpoint["reason"], "destination_ambiguous")
        self.assertEqual(endpoint["candidate_device_ids"], ["a", "b"])

    def test_block_or_discard_does_not_invent_a_missing_transit_device(self):
        for denied in (True, False):
            result = self.flow()
            result["hops"][0].update(policy_evaluations=[{"decision": "deny"}] if denied else [],
                                     route={"route_type": "forward" if denied else "discard"})
            graph = visibility_graph(result)
            self.assertFalse(any(n.get("role") == "segment" for n in graph["nodes"]))
            self.assertEqual(graph["connections"], [])

    def test_reached_path_has_no_placeholders_and_verdict_is_preserved(self):
        result = self.flow()
        result["coverage"]["destination_reached"] = True
        result["hops"] = [{"device_id": "home"}, {"device_id": "server"}]
        response = add_visibility({"results": [result]})
        self.assertFalse(any(n.get("placeholder") for n in response["results"][0]["visibility_graph"]["nodes"]))
        self.assertEqual(result["verdict"], {"status": "unknown"})

    def test_translated_managed_destination_does_not_create_false_unmanaged_endpoint(self):
        result = self.flow(False)
        result["coverage"]["destination_reached"] = True
        result["hops"] = [{"device_id": "home", "translated_destination_candidates": [{"device_id": "server"}]}, {"device_id": "server"}]
        self.assertFalse(any(n.get("placeholder") for n in visibility_graph(result)["nodes"]))

    def test_default_topology_keeps_unmanaged_next_hop_and_named_view_boundary(self):
        cur = MagicMock()
        cur.fetchall.side_effect = [[("home", "Home router", "192.0.2.10")], [],
                                   [("route", "home", "192.0.2.254", "hop")], []]
        projection = TopologyService.projection(cur, "dataset")
        gap = next(n for n in projection["nodes"] if n.get("placeholder"))
        self.assertEqual(gap["reason"], "next_hop_inventory_missing")
        view = application_view(projection, ["192.0.2.10", "198.51.100.8"])
        self.assertIn(gap["id"], {n["id"] for n in view["nodes"]})
        self.assertEqual(view["endpoint_candidates"]["198.51.100.8"], [])


class ExternalDestinationTraversalTests(unittest.TestCase):
    def test_real_processor_follows_known_router_before_external_visibility_gap(self):
        connection, cursor = MagicMock(), MagicMock()
        connection.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchone.side_effect = [("consumer",), ("dataset", "completed", "navis_test", {}), None, ("Home router", "router")]
        cursor.fetchall.return_value = []
        route = {"route_id": str(uuid4()), "prefix": "0.0.0.0/0", "route_type": "forward", "next_hop": "192.0.2.254", "interface": "wan"}
        processor = PostgresTraceProcessor(lambda: connection)
        flow = Flow("192.0.2.10", "198.51.100.8", "tcp", 443)
        with ExitStack() as stack:
            stack.enter_context(patch("navis_api.trace_postgres.evidence_manifest", return_value={}))
            # The remote server is not in inventory; the source is managed.
            stack.enter_context(patch.object(processor, "_endpoints", side_effect=[[], [{"device_id": "home", "vrf": "default"}]]))
            routes = stack.enter_context(patch.object(processor, "_routes", return_value=[route]))
            stack.enter_context(patch.object(processor, "_policies", return_value=[]))
            stack.enter_context(patch.object(processor, "_nat", side_effect=lambda cur, build, dev, packet, **kwargs: (packet, [])))
            stack.enter_context(patch.object(processor, "_coverage", return_value={"devices": [{"device_id": "home", "data_types": {}}]}))
            stack.enter_context(patch("navis_api.trace_postgres.next_hops", return_value=[]))
            response = processor.trace(SimpleNamespace(graph_build_id=uuid4()), [flow],
                Principal(issuer="i", subject="s", scopes=frozenset()), include_reverse=False)
        result = response["results"][0]
        self.assertEqual(result["hops"][0]["device_id"], "home")
        self.assertEqual(result["hops"][0]["route"]["next_hop"], "192.0.2.254")
        self.assertGreaterEqual(routes.call_count, 2)
        self.assertEqual(result["connection_verdict"]["status"], "unknown")
        self.assertFalse(result["coverage"]["destination_reached"])
        self.assertTrue(any(f["code"] == "UNMANAGED_PATH_SEGMENT" for f in result["findings"]))


if __name__ == "__main__":
    unittest.main()
