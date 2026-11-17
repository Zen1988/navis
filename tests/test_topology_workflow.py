import unittest
from contextlib import nullcontext
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
        self.assertEqual({n["id"] for n in view["nodes"] if not n.get("placeholder")}, {"a", "transit", "b"})
        missing = [n for n in view["nodes"] if n.get("placeholder")]
        self.assertEqual(missing[0]["addresses"], ["10.9.9.9"])
        self.assertEqual(view["endpoint_candidates"]["10.9.9.9"], [])
        self.assertEqual(len(self.graph["nodes"]), 4)

    def test_reused_ip_remains_ambiguous(self):
        self.graph["nodes"][-1]["addresses"] = ["10.0.0.1"]
        view = application_view(self.graph, ["10.0.0.1"])
        self.assertEqual(view["endpoint_candidates"]["10.0.0.1"], ["a", "unrelated"])

    def test_default_keeps_disconnected_devices(self):
        self.assertEqual(application_view(self.graph, []), self.graph)

    def test_application_server_names_and_external_ids_keep_transit(self):
        self.graph["nodes"][0].update(name="appserver1", aliases=["cmdb-app-1"])
        self.graph["nodes"][2].update(name="dbserver1")
        view = application_view(self.graph, ["appserver1", "dbserver1", "missing-server"])
        self.assertEqual({n["id"] for n in view["nodes"] if not n.get("placeholder")}, {"a", "transit", "b"})
        self.assertEqual(view["member_resolution"]["appserver1"]["status"], "resolved")
        self.assertEqual(view["member_resolution"]["missing-server"]["status"], "missing")
        unknown = next(n for n in view["nodes"] if n.get("requested_member") == "missing-server")
        self.assertEqual(unknown["addresses"], [])
        self.assertEqual(application_view(self.graph, ["cmdb-app-1"])["endpoint_candidates"]["cmdb-app-1"], ["a"])

    def test_duplicate_device_names_are_reported_as_ambiguous(self):
        for node in self.graph["nodes"][:2]:
            node["name"] = "appserver1"
        view = application_view(self.graph, ["appserver1"])
        self.assertEqual(view["member_resolution"]["appserver1"], {"status": "ambiguous", "device_ids": ["a", "transit"]})

    def test_members_trim_deduplicate_and_keep_names_opaque(self):
        request = TopologyRequest(name=" application 1 ", members=[" appserver1 ", "appserver1", "2001:0db8::1"])
        self.assertEqual(request.name, "application 1")
        self.assertEqual(request.members, ["appserver1", "2001:db8::1"])

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
        self.service.trace_lease.side_effect = lambda build: nullcontext()
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

    def test_create_and_retrieve_topology_by_human_name(self):
        members = ["appserver1", "appserver2", "appserver3", "dbserver1", "dbserver2", "dbserver3"]
        response = self.client.post("/v1/topologies", json={"namespace": "lab", "name": "application 1", "members": members})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(self.service.refresh.call_args.kwargs["members"], members)
        self.service.read_named.return_value = {"name": "application 1", "members": members, "nodes": []}
        response = self.client.get("/v1/topologies/by-name/application%201?namespace=lab")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["name"], "application 1")
        self.service.read_named.assert_called_once()
        self.assertEqual(self.service.read_named.call_args.args[1:], ("application 1", "lab"))

    def test_named_trace_resolves_build_and_saves_name_with_member_snapshot(self):
        self.service.refresh.return_value = {"graph_build_id": self.build, "name": "application 1", "members": ["appserver1", "dbserver1"]}
        response = self.client.post("/v1/traces", json={"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "tcp", "namespace": "lab", "topology_name": "application 1"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.service.refresh.call_args.kwargs, {"name": "application 1"})
        self.assertEqual(response.json()["topology"]["name"], "application 1")
        saved = self.sessions.save.call_args.args
        self.assertEqual(saved[4]["topology"]["members"], ["appserver1", "dbserver1"])
        TraceRequest.model_validate(saved[3])

    def test_name_and_build_are_mutually_exclusive_and_unknown_name_is_404(self):
        payload = {"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "tcp", "topology_name": "application 1"}
        self.assertEqual(self.client.post("/v1/traces", json={**payload, "graph_build_id": self.build}).status_code, 422)
        self.service.refresh.side_effect = LookupError()
        self.assertEqual(self.client.post("/v1/traces", json=payload).status_code, 404)
        self.sessions.save.assert_not_called()

    def test_historical_version_trace_does_not_refresh_current_name(self):
        version = str(uuid4())
        self.service.read_named.return_value = {"graph_build_id": self.build, "version_id": version, "name": "application 1", "members": ["appserver1"], "built_at": datetime.now(timezone.utc)}
        response = self.client.post("/v1/traces", json={"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "tcp", "namespace": "lab", "topology_name": "application 1", "topology_version_id": version})
        self.assertEqual(response.status_code, 200, response.text)
        self.service.refresh.assert_not_called()
        self.assertEqual(response.json()["topology"]["version_id"], version)
        import json
        json.dumps(self.sessions.save.call_args.args[4])

    def test_archived_version_is_inspection_only(self):
        self.service.read_named.return_value = {"graph_build_id": self.build, "lifecycle": {"storage_status": "audit"}}
        response = self.client.post("/v1/traces", json={"source": "10.0.0.1", "destination": "10.0.0.2", "protocol": "tcp", "topology_name": "application 1", "topology_version_id": str(uuid4())})
        self.assertEqual(response.status_code, 409)
        self.sessions.save.assert_not_called()

    def test_version_history_and_comparison_routes_are_name_scoped(self):
        first = str(uuid4())
        self.service.versions.return_value = {"name": "application 1", "versions": []}
        self.service.compare.return_value = {"changed": True}
        response = self.client.get('/v1/topologies/by-name/application%201/versions?namespace=lab&include_audit=true')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(self.service.versions.call_args.kwargs['include_audit'])
        response = self.client.get('/v1/topologies/by-name/application%201/compare?namespace=lab&from_version='+first)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.service.compare.call_args.args[1:3], ('application 1', UUID(first)))

    def test_named_graph_lookup_checks_scope_and_ownership(self):
        self.service.read_named.side_effect = LookupError()
        self.assertEqual(self.client.get("/v1/topologies/by-name/private?namespace=lab").status_code, 404)
        self.scopes.remove("graph:read")
        self.service.read_named.reset_mock()
        self.assertEqual(self.client.get("/v1/topologies/by-name/default?namespace=lab").status_code, 403)
        self.service.read_named.assert_not_called()

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

    def test_session_graph_retains_unknown_segment_from_trace(self):
        from navis_common.path_visibility import add_visibility
        trace = add_visibility({"results": [{"source": "10.0.0.1", "destination": "198.51.100.8", "protocol": "tcp",
            "source_candidates": [{"device_id": "home"}], "destination_candidates": [],
            "hops": [{"device_id": "home", "stop_reason": "Next device connection is missing or ambiguous"}],
            "coverage": {"destination_reached": False}}]})
        self.sessions.get.return_value = {"graph_build_id": self.build,
            "request": {"source": "10.0.0.1", "destination": "198.51.100.8", "protocol": "tcp"}, "result": trace}
        self.service.read.return_value = {"nodes": [{"id": "home", "name": "Home router", "addresses": ["10.0.0.1"]}], "connections": []}
        response = self.client.get("/v1/trace-sessions/ours/graph")
        self.assertEqual(response.status_code, 200, response.text)
        graph = response.json()["graph"]
        self.assertEqual(graph["visibility_status"], "incomplete")
        self.assertTrue(any(n.get("role") == "segment" for n in graph["nodes"]))
        self.assertEqual(len(graph["connections"]), 2)
        home = next(n for n in graph["nodes"] if n["id"] == "home")
        self.assertEqual(home["addresses"], ["10.0.0.1"])

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
        self.service.head = Mock(return_value=None)
        self.service.publish = Mock(return_value={"version_id": str(uuid4()), "changed": True})
        self.service.refresh_named_views = Mock()
        content = patch("navis_api.topology.content_state", return_value={"records": [], "builder": "test"})
        content.start()
        self.addCleanup(content.stop)
        self.snapshot = (uuid4(), "route", uuid4(), datetime.now(timezone.utc), "partial")

    def finish_build(self, build_id, callback):
        return {"build_id": build_id, "publication": callback(self.cur, UUID(build_id))}

    def test_pending_mapping_failure_does_not_discard_existing_evidence(self):
        pending = uuid4()
        self.cur.fetchall.side_effect = [[(pending,)], [self.snapshot]]
        with patch("navis_api.topology.process_submission", side_effect=ValueError("mapping missing")), patch("navis_api.topology.build_graph", side_effect=lambda *args, **kw: self.finish_build(str(uuid4()), kw["after_build"])) as build:
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

    def test_default_refresh_publishes_live_name_and_advances_named_views(self):
        self.cur.fetchall.side_effect = [[], [self.snapshot]]
        build = str(uuid4())
        with patch("navis_api.topology.build_graph", side_effect=lambda *args, **kw: self.finish_build(build, kw["after_build"])):
            result = self.service.refresh(self.principal, "lab")
        self.assertEqual(result["name"], "default")
        self.assertEqual(result["members"], [])
        self.service.refresh_named_views.assert_called_once()
        self.assertEqual(self.service.refresh_named_views.call_args.args[1:3], (self.source, UUID(build)))

    def test_name_only_refresh_reuses_saved_member_list(self):
        self.cur.fetchone.return_value = (["appserver1", "dbserver1"],)
        self.cur.fetchall.side_effect = [[], [self.snapshot]]
        with patch("navis_api.topology.build_graph", side_effect=lambda *args, **kw: self.finish_build(str(uuid4()), kw["after_build"])):
            result = self.service.refresh(self.principal, "lab", name="application 1")
        self.assertEqual(result["name"], "application 1")
        self.assertEqual(result["members"], ["appserver1", "dbserver1"])

    def test_unknown_name_and_filtered_default_do_not_build(self):
        for kwargs, error in [({"name": "absent"}, LookupError), ({"members": ["appserver1"]}, ValueError)]:
            self.cur.fetchone.return_value = None
            with patch("navis_api.topology.build_graph") as build, self.assertRaises(error):
                self.service.refresh(self.principal, "lab", **kwargs)
            build.assert_not_called()

    def test_unchanged_upload_does_not_save_a_new_graph_or_dataset(self):
        self.cur.fetchall.side_effect = [[], [self.snapshot]]
        old_build, old_dataset, old_version = uuid4(), uuid4(), uuid4()
        self.service.head.return_value = {"graph_build_id": old_build, "dataset_id": old_dataset}
        self.service.reusable = Mock(return_value=True)
        self.service.read = Mock(return_value={"nodes": [], "connections": []})
        self.service.publish.return_value = {"version_id": str(old_version), "changed": False}
        with patch("navis_api.topology.build_graph") as build:
            result = self.service.refresh(self.principal, "lab")
        build.assert_not_called()
        self.assertEqual(result["graph_build_id"], str(old_build))
        self.assertEqual(result["dataset_id"], str(old_dataset))
        self.assertFalse(result["changed"])
        statements = [call.args[0] for call in self.cur.execute.call_args_list]
        self.assertFalse(any("INSERT INTO navis.topology_build" in sql for sql in statements))
        self.assertTrue(any("DELETE FROM navis.graph_dataset WHERE" in sql for sql in statements))


if __name__ == "__main__":
    unittest.main()
