import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from unittest.mock import MagicMock
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from navis_api.main import app
from navis_api.topology import application_view, TopologyRequest, TopologyService
from navis_api.trace import TraceRequest
from navis_api.graph_trace import next_hops
from navis_common.auth import Principal


class ApplicationViewTests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            "nodes": [{"id": n, "addresses": ips} for n, ips in
                      [("a", ["10.0.0.1"]), ("transit", []), ("b", ["10.0.0.2"]), ("unrelated", [])]],
            "connections": [{"source": "a", "target": "transit"}, {"source": "transit", "target": "b"}],
        }

    def test_named_view_keeps_transit_and_reports_missing_endpoint(self):
        view = application_view(self.graph, ["10.0.0.1", "10.0.0.2", "10.9.9.9"])
        self.assertEqual({n["id"] for n in view["nodes"]}, {"a", "transit", "b"})
        self.assertEqual(view["endpoint_candidates"]["10.9.9.9"], [])
        self.assertEqual(len(self.graph["nodes"]), 4)

    def test_reused_ip_remains_ambiguous(self):
        self.graph["nodes"][-1]["addresses"] = ["10.0.0.1"]
        view = application_view(self.graph, ["10.0.0.1"])
        self.assertEqual(view["endpoint_candidates"]["10.0.0.1"], ["a", "unrelated"])

    def test_default_keeps_disconnected_devices(self):
        self.assertEqual(application_view(self.graph, []), self.graph)

    def test_request_generates_unique_session_and_accepts_no_build(self):
        values = dict(source="10.0.0.1", destination="10.0.0.2", protocol="tcp")
        a, b = TraceRequest(**values), TraceRequest(**values)
        self.assertIsNone(a.graph_build_id)
        self.assertNotEqual(a.caller_session_id, b.caller_session_id)
        self.assertEqual(TopologyRequest(ips=["2001:0db8::1", "2001:db8::1"]).ips, ["2001:db8::1"])

    def test_route_candidates_remain_marked_inferred(self):
        device = str(uuid4())
        cur = Mock()
        cur.fetchall.side_effect = [[], [], [('"' + device + '"',)]]
        result = next_hops(cur, "navis_" + uuid4().hex, uuid4())
        self.assertEqual(result, [device])
        self.assertTrue(result.inferred)

    def test_source_selection_refuses_ambiguous_or_unauthorized_namespace(self):
        service = TopologyService(None)
        cur = Mock()
        cur.fetchone.return_value = (uuid4(),)
        cur.fetchall.return_value = [(uuid4(), "a"), (uuid4(), "b")]
        with self.assertRaises(ValueError):
            service.source(cur, Principal(issuer="i", subject="s", scopes=frozenset()), None, "analysis:run")
        cur.fetchall.return_value = []
        with self.assertRaises(PermissionError):
            service.source(cur, Principal(issuer="i", subject="s", scopes=frozenset()), "private", "analysis:run")


class TopologyApiTests(unittest.TestCase):
    def setUp(self):
        self.names = ("token_verifier", "topology_service", "trace_processor", "trace_sessions", "ingestion_processor")
        self.old = {name: getattr(app.state, name) for name in self.names}
        self.scopes = {"analysis:run", "analysis:read", "graph:read", "inventory:write"}
        app.state.token_verifier = SimpleNamespace(verify=lambda token: Principal(issuer="i", subject="s", scopes=frozenset(self.scopes)))
        self.service = app.state.topology_service = Mock()
        self.build = str(uuid4())
        self.service.refresh.return_value = {"graph_build_id": self.build}
        app.state.trace_processor = SimpleNamespace(trace=lambda request, flows, principal: {"results": [], "graph_build_id": str(request.graph_build_id)})
        self.sessions = app.state.trace_sessions = Mock()
        self.sessions.save.return_value = uuid4()
        self.client = TestClient(app, headers={"Authorization": "Bearer test"})

    def tearDown(self):
        self.client.close()
        for name, value in self.old.items():
            setattr(app.state, name, value)

    def test_on_demand_trace_persists_resolved_build_and_generated_session(self):
        response = self.client.post("/v1/traces", json={"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "tcp", "namespace": "lab"})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(data["graph_build_id"], self.build)
        UUID(data["caller_session_id"])
        saved = self.sessions.save.call_args.args
        self.assertEqual(str(saved[2]), self.build)
        self.assertEqual(saved[3]["graph_build_id"], self.build)
        self.service.refresh.assert_called_once()

    def test_explicit_build_does_not_rebuild(self):
        response = self.client.post("/v1/traces", json={"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "icmp", "graph_build_id": self.build})
        self.assertEqual(response.status_code, 200, response.text)
        self.service.refresh.assert_not_called()

    def test_scope_and_namespace_denial_do_not_run_trace(self):
        self.scopes.remove("analysis:run")
        payload = {"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "tcp"}
        self.assertEqual(self.client.post("/v1/traces", json=payload).status_code, 403)
        self.service.refresh.assert_not_called()
        self.scopes.add("analysis:run")
        self.service.refresh.side_effect = PermissionError()
        self.assertEqual(self.client.post("/v1/traces", json=payload).status_code, 403)
        self.sessions.save.assert_not_called()

    def test_named_topology_validates_ips_and_passes_selection(self):
        response = self.client.post("/v1/topologies", json={"namespace": "lab", "name": "checkout", "ips": ["10.0.0.1", "10.0.0.2"]})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(self.service.refresh.call_args.kwargs["name"], "checkout")
        self.assertEqual(self.client.post("/v1/topologies", json={"ips": ["bad"]}).status_code, 422)

    def test_session_ownership_checked_before_graph_lookup(self):
        self.sessions.get.side_effect = LookupError()
        self.assertEqual(self.client.get("/v1/trace-sessions/foreign/graph").status_code, 404)
        self.service.read.assert_not_called()

    def test_session_graph_is_selected_from_saved_request(self):
        self.sessions.get.return_value = {"graph_build_id": self.build, "request": {"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "tcp"}, "result": {}}
        self.service.read.return_value = {"nodes": [{"id": "a", "addresses": ["10.0.0.1"]}, {"id": "b", "addresses": ["10.0.0.2"]}, {"id": "other", "addresses": []}], "connections": []}
        response = self.client.get("/v1/trace-sessions/ours/graph")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual({n["id"] for n in response.json()["graph"]["nodes"]}, {"a", "b"})

    def test_ingestion_schedules_namespace_refresh_after_persistence(self):
        import json
        from pathlib import Path
        payload = json.loads(Path("docs/api/examples/ingestion-interface.json").read_text())
        app.state.ingestion_processor = Mock()
        app.state.ingestion_processor.submit.return_value = {"ingestion_id": str(uuid4()), "status": "pending_identity"}
        response = self.client.post("/v1/ingestions", json=payload)
        self.assertEqual(response.status_code, 202, response.text)
        self.service.after_ingestion.assert_called_once()
        self.assertEqual(self.service.after_ingestion.call_args.args[1], payload["source"]["namespace"])


class RefreshOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.conn, self.cur = MagicMock(), MagicMock()
        self.conn.__enter__.return_value = self.conn
        self.conn.cursor.return_value.__enter__.return_value = self.cur
        self.service = TopologyService(lambda: self.conn)
        self.principal = Principal(issuer="i", subject="s", scopes=frozenset())
        self.source = uuid4()
        self.service.source = Mock(return_value=(uuid4(), self.source, "lab"))
        self.service.projection = Mock(return_value={"nodes": [], "connections": []})
        self.snapshot = (uuid4(), "route", uuid4(), datetime.now(timezone.utc), "partial")

    def test_pending_mapping_failure_does_not_discard_existing_evidence(self):
        pending = uuid4()
        self.cur.fetchall.side_effect = [[(pending,)], [self.snapshot]]
        with patch("navis_api.topology.process_submission", side_effect=ValueError("mapping missing")), patch("navis_api.topology.build_graph", return_value={"build_id": str(uuid4())}) as build:
            response = self.service.refresh(self.principal, "lab")
        self.assertEqual(response["pending_submissions"], [{"ingestion_id": str(pending), "reason": "mapping missing"}])
        self.assertEqual(response["snapshots"][0]["coverage"], "partial")
        build.assert_called_once()
        self.assertEqual(build.call_args.args[1], UUID(response["dataset_id"]))
        self.assertIn("pg_advisory_unlock", self.cur.execute.call_args.args[0])

    def test_no_snapshots_releases_lock_without_building(self):
        self.cur.fetchall.side_effect = [[], []]
        with patch("navis_api.topology.build_graph") as build, self.assertRaises(ValueError):
            self.service.refresh(self.principal, "lab")
        build.assert_not_called()
        self.assertIn("pg_advisory_unlock", self.cur.execute.call_args.args[0])

    def test_builder_failure_releases_lock_without_publishing_topology(self):
        self.cur.fetchall.side_effect = [[], [self.snapshot]]
        with patch("navis_api.topology.build_graph", side_effect=RuntimeError("AGE unavailable")), self.assertRaises(RuntimeError):
            self.service.refresh(self.principal, "lab")
        self.assertFalse(any("INSERT INTO navis.topology_build" in call.args[0] for call in self.cur.execute.call_args_list))
        self.assertIn("pg_advisory_unlock", self.cur.execute.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
