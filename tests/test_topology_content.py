import copy
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
from uuid import uuid4

from navis_api.topology_content import canonical_records, compare_content, digest, selected_content
from navis_api.topology import TopologyService


class ContentTests(unittest.TestCase):
    def records(self, prefix, address="192.0.2.1/24", coverage="complete"):
        return [
            ("device", "device", {"id": "device", "display_name": "appserver1", "last_seen_at": prefix}),
            ("device_snapshot", prefix+"snap", {"id": prefix+"snap", "device_id": "device", "collected_at": prefix}),
            ("interface", prefix+"if", {"id": prefix+"if", "snapshot_id": prefix+"snap", "normalization_run_id": prefix+"run", "native_id": "eth0"}),
            ("interface_address", prefix+"addr", {"id": prefix+"addr", "interface_id": prefix+"if", "address": address}),
            ("snapshot_coverage", prefix+"cov", {"id": prefix+"cov", "snapshot_id": prefix+"snap", "coverage": coverage}),
        ]

    def test_identical_import_with_new_ids_and_dates_has_same_content(self):
        self.assertEqual(canonical_records(self.records("first")), canonical_records(self.records("second")))

    def test_route_rewiring_device_address_and_coverage_changes_are_significant(self):
        original = canonical_records(self.records("first"))
        self.assertNotEqual(original, canonical_records(self.records("next", address="192.0.2.2/24")))
        self.assertNotEqual(original, canonical_records(self.records("next", coverage="partial")))
        changed = self.records("first")
        changed[2][2]["native_id"] = "eth1"
        self.assertNotEqual(original, canonical_records(changed))

    def test_declared_link_reference_survives_interface_recollection(self):
        old = self.records("old") + [("topology_link", "link", {"id": "link", "origin": "manual"}),
            ("topology_link_endpoint", "a", {"link_id": "link", "endpoint_number": 1, "interface_id": "oldif"}),
            ("topology_link_endpoint", "b", {"link_id": "link", "endpoint_number": 2, "interface_id": "oldif"})]
        new = self.records("new") + old[-3:]
        self.assertEqual(canonical_records(old), canonical_records(new, {"oldif": "newif"}))

    def test_comparison_reports_changed_tables_and_member_changes(self):
        a = {"records": canonical_records(self.records("a")), "members": ["appserver1"], "builder": "1"}
        b = {"records": canonical_records(self.records("b", address="192.0.2.2/24")), "members": ["appserver1", "dbserver1"], "builder": "1"}
        result = compare_content(a, b)
        self.assertTrue(result["changed"])
        self.assertEqual(result["tables"]["interface_address"], {"added": 1, "removed": 1})
        self.assertEqual(result["members_added"], ["dbserver1"])

    def test_membership_rewire_changes_policy_even_when_groups_have_identical_metadata(self):
        records = [('address_object','g1',{'id':'g1','kind':'group'}),
                   ('address_object','g2',{'id':'g2','kind':'group'}),
                   ('address_object','a',{'id':'a','prefix':'192.0.2.0/24'}),
                   ('address_object','b',{'id':'b','prefix':'198.51.100.0/24'}),
                   ('address_group_member','1',{'group_id':'g1','member_id':'a'}),
                   ('address_group_member','2',{'group_id':'g2','member_id':'b'}),
                   ('policy_selector','selector',{'id':'selector','address_object_id':'g1','role':'source'})]
        changed = copy.deepcopy(records)
        changed[4][2]['member_id']='b'
        changed[5][2]['member_id']='a'
        self.assertNotEqual(canonical_records(records),canonical_records(changed))

    def test_disconnected_device_does_not_change_named_graph_content(self):
        state = {"records": [{"table": "device", "devices": ["a"], "record_hash": "a"}], "builder": "1"}
        projection = {"nodes": [{"id": "a", "name": "appserver1", "addresses": []}], "connections": []}
        first = selected_content(state, projection, ["appserver1"])
        state["records"].append({"table": "device", "devices": ["other"], "record_hash": "other"})
        projection["nodes"].append({"id": "other", "name": "unrelated", "addresses": []})
        self.assertEqual(first, selected_content(state, projection, ["appserver1"]))
        projection["connections"].append({"source": "a", "target": "other"})
        self.assertNotEqual(first, selected_content(state, projection, ["appserver1"]))

    def test_publish_same_version_updates_timestamp_without_inserting_version(self):
        cur = Mock()
        now = datetime.now(timezone.utc)
        earlier = now-timedelta(days=100)
        topology, version, build = uuid4(), uuid4(), uuid4()
        cur.fetchone.side_effect = [(topology,), (earlier, now, 2)]
        head = {"version_id": version, "graph_build_id": build}
        result = TopologyService.publish(cur, uuid4(), None, "default", [], build, {"records": []}, {}, head, True)
        self.assertEqual(result["version_id"], str(version))
        self.assertEqual(result["built_at"], earlier)
        self.assertEqual(result["updated_at"], now)
        self.assertFalse(result["changed"])
        self.assertFalse(any("INSERT INTO navis.topology_version" in call.args[0] for call in cur.execute.call_args_list))

    def test_changed_graph_has_new_version_and_initial_dates_match(self):
        cur = Mock()
        now = datetime.now(timezone.utc)
        cur.fetchone.side_effect = [(uuid4(),), (now, now, 1)]
        result = TopologyService.publish(cur, uuid4(), None, "default", [], uuid4(), {"records": []}, {}, None, False)
        self.assertTrue(result["changed"])
        self.assertEqual(result["built_at"], result["updated_at"])

    def test_modified_original_graph_is_not_reused(self):
        state = {"records": [], "builder": "1", "members": []}
        head = {"content_hash": digest(state), "evidence_manifest": {"digest": "old"}, "dataset_id": uuid4(),
                "graph_build_id": uuid4(), "members": []}
        cur = Mock()
        cur.fetchone.return_value = ({"nodes": [], "connections": []},)
        with patch("navis_api.topology.evidence_manifest", return_value={"digest": "new"}), patch("navis_api.topology.content_state", return_value={"records": [], "builder": "changed"}):
            self.assertFalse(TopologyService.reusable(cur, head, state))


if __name__ == '__main__':
    unittest.main()
