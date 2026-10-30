from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from navis_api.normalized_adapter import normalize
from navis_common.nsx_adapter import normalized_submissions, translate_policy, translate_vm
from navis_common.nsx_inventory import list_results
from navis_common.policy_selectors import evaluate_policy


def paged(values):
    return [{"result_count": len(values), "results": values}]


def resource(kind, path, **fields):
    return {"resource_type": kind, "id": path.rsplit("/", 1)[-1], "path": path,
            "parent_path": path.rsplit("/", 2)[0], **fields}


class NsxAdapterTests(unittest.TestCase):
    def setUp(self):
        self.domain = "/infra/domains/default"
        self.group = self.domain + "/groups/workloads"
        self.ip_group = self.domain + "/groups/remote"
        self.segment = "/infra/segments/workload-vlan"
        self.port = self.segment + "/ports/nic1"
        self.policy = self.domain + "/security-policies/application"
        self.emergency = self.domain + "/security-policies/emergency"
        self.service = "/infra/services/https"
        self.metadata = {"manager_id": "manager-a", "domain": "default", "manager_type": "local", "collected_at": "2026-10-30T00:00:00Z"}
        self.vm = {"resource_type": "VirtualMachine", "id": "inventory-1", "external_id": "vm-1", "display_name": "duplicate-name", "host_id": "host-1"}
        self.vif = {"resource_type": "VirtualNetworkInterface", "external_id": "vif-1", "owner_vm_id": "vm-1",
            "device_name": "Network adapter 1", "lport_attachment_id": "attachment-1", "host_id": "host-1",
            "ip_address_info": [{"ip_addresses": ["192.0.2.5", "2001:db8::5"]}]}
        self.rule = resource("Rule", self.policy + "/rules/allow-web", sequence_number=10, source_groups=[self.group],
            destination_groups=[self.ip_group], services=[self.service], action="ALLOW", scope=["ANY"], direction="OUT", disabled=False,
            ip_protocol="IPV4_IPV6", rule_id=101)
        self.block = resource("Rule", self.emergency + "/rules/block-ssh", sequence_number=10, source_groups=["ANY"],
            destination_groups=["ANY"], services=[], service_entries=[{"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP", "destination_ports": ["22"]}],
            action="DROP", scope=["ANY"], direction="IN_OUT", disabled=False)
        self.collection = {
            "domains": paged([resource("Domain", self.domain)]),
            "groups": paged([resource("Group", self.group, expression=[{"resource_type": "Condition", "member_type": "VirtualMachine", "key": "Name", "operator": "EQUALS", "value": "duplicate-name"}]),
                              resource("Group", self.ip_group, group_type=["IPAddress"], expression=[{"resource_type": "IPAddressExpression", "ip_addresses": ["198.51.100.0/24", "203.0.113.8-203.0.113.11"]}])]),
            "policies": paged([resource("SecurityPolicy", self.policy, category="Application", sequence_number=10, stateful=True, scope=[self.group], rule_count=1),
                               resource("SecurityPolicy", self.emergency, category="Emergency", sequence_number=20, stateful=True, scope=[self.group], rule_count=1)]),
            "services": paged([resource("Service", self.service, service_entries=[{"resource_type": "L4PortSetServiceEntry", "l4_protocol": "TCP", "destination_ports": ["443", "8443-8444"]}])]),
            "virtual_machines": paged([self.vm, {"resource_type": "VirtualMachine", "id": "inventory-2", "external_id": "vm-2", "display_name": "duplicate-name"}]),
            "vifs": paged([self.vif, {"resource_type": "VirtualNetworkInterface", "external_id": "vif-2", "owner_vm_id": "inventory-2",
                "lport_attachment_id": "attachment-2", "ip_address_info": [{"ip_addresses": ["192.0.2.6"]}]}]),
            "segments": paged([resource("Segment", self.segment, vlan_ids=["100"])]),
            "segment_ports": {self.segment: paged([resource("SegmentPort", self.port, attachment={"id": "attachment-1"}),
                resource("SegmentPort", self.segment + "/ports/nic2", attachment={"id": "attachment-2"})])},
            "group_virtual_machines": {self.group: paged([self.vm])},
            "rulebases": {self.policy: paged([self.rule]), self.emergency: paged([self.block])}}

    def translate(self, vm="vm-1", vif=None):
        return translate_policy(self.metadata, self.collection, vm_external_id=vm, vif_external_id=vif)

    def supported_rules(self):
        rules = self.translate()["policies"]
        for rule in rules:
            rule["selectors_complete"] = rule["details"]["translated_conditions_complete"]
        return rules

    def verdict(self, rules, port=443, vif="vif-1", direction="OUT"):
        return evaluate_policy(rules, "unknown", "192.0.2.5", "198.51.100.10", "tcp", port, complete=True,
                               source_port=50000, vif_external_id=vif, traffic_direction=direction)

    def test_vm_identity_not_display_name_and_vlan_attachment(self):
        result = self.translate()
        self.assertEqual(result["target"]["vm_external_id"], "vm-1")
        self.assertEqual(result["target"]["external_id"], "vif-1")
        self.assertEqual(result["target"]["segment_port"]["path"], self.port)
        self.assertTrue(result["interfaces"][0]["config"]["attachment_verified"])
        self.assertTrue(result["policies"][-1]["details"]["translated_conditions_complete"])
        self.assertEqual(self.translate(vm="vm-2")["policies"], [])

    def test_category_order_and_native_rule_identity(self):
        rules = self.translate()["policies"]
        self.assertEqual([r["rule_id"] for r in rules], [self.block["path"], self.rule["path"]])
        self.assertEqual([r["position"] for r in rules], [1, 2])
        self.assertTrue(all(r["details"]["statefulness"] == "stateful" for r in rules))
        self.assertEqual(rules[-1]["details"]["native_rule_id"], 101)

    def test_vnic_scope_and_direction_are_required_beyond_ip_match(self):
        rules = self.supported_rules()
        self.assertEqual(self.verdict(rules)["decision"], "allow")
        self.assertEqual(self.verdict(rules, port=22)["decision"], "deny")
        self.assertEqual(self.verdict(rules, vif=None)["decision"], "unknown")
        self.assertEqual(self.verdict(rules, direction=None)["decision"], "unknown")
        self.assertEqual(self.verdict(rules, direction="IN")["decision"], "unknown")
        self.assertEqual(self.verdict(rules, vif="vif-2")["decision"], "unknown")

    def test_vm_group_addresses_come_from_native_members_and_vifs(self):
        rule = self.translate()["policies"][-1]
        self.assertEqual({s["value"] for s in rule["selectors"] if s["role"] == "source"}, {"192.0.2.5/32", "2001:db8::5/128"})
        self.assertEqual({s["value"] for s in rule["selectors"] if s["role"] == "destination"}, {"198.51.100.0/24", "203.0.113.8/30"})

    def test_missing_member_or_ip_bindings_do_not_become_any(self):
        self.collection["group_virtual_machines"] = {}
        result = self.translate()
        self.assertIsNone(result["policies"][-1]["details"]["scope_applies_to_selected_vif"])
        self.assertFalse(any(s["role"] == "source" for s in result["policies"][-1]["selectors"]))
        self.collection["group_virtual_machines"][self.group] = paged([self.vm])
        self.vif["ip_address_info"] = []
        self.assertFalse(any(s["role"] == "source" for s in self.translate()["policies"][-1]["selectors"]))

    def test_ip_only_applied_to_is_unresolved_without_broad_fallback(self):
        for policy in self.collection["policies"][0]["results"]:
            policy["scope"] = [self.ip_group]
        result = self.translate()
        self.assertEqual(result["capacity"]["known_applicable_enabled_rules"], 0)
        self.assertEqual(result["capacity"]["unknown_scope_enabled_rules"], 2)
        self.assertEqual(result["capacity"]["broad_scope_enabled_rules"], 0)
        self.assertTrue(all(not r["details"]["workload_condition"]["complete"] for r in result["policies"]))

    def test_mixed_generic_group_can_match_addresses_but_not_establish_scope(self):
        mixed_path = self.domain + "/groups/mixed"
        mixed = resource("Group", mixed_path, expression=[
            {"resource_type": "ExternalIDExpression", "member_type": "VirtualMachine", "external_ids": ["vm-1"]},
            {"resource_type": "ConjunctionOperator", "conjunction_operator": "OR"},
            {"resource_type": "IPAddressExpression", "ip_addresses": ["10.0.0.5"]}])
        self.collection["groups"][0]["results"].append(mixed)
        self.collection["groups"][0]["result_count"] += 1
        self.rule["source_groups"] = [mixed_path]
        rule = self.translate()["policies"][-1]
        self.assertIn("10.0.0.5/32", {s["value"] for s in rule["selectors"] if s["role"] == "source"})
        for policy in self.collection["policies"][0]["results"]:
            policy["scope"] = [mixed_path]
        self.assertTrue(all(not r["details"]["workload_condition"]["complete"] for r in self.translate()["policies"]))
        mixed["group_type"] = ["IPAddress"]
        self.assertFalse(self.translate()["policies"][-1]["details"]["translated_conditions_complete"])

    def test_policy_scope_precedes_rule_scope_and_filters_other_vms(self):
        self.rule["scope"] = [self.ip_group]
        self.assertTrue(self.translate()["policies"][-1]["details"]["scope_applies_to_selected_vif"])
        self.collection["group_virtual_machines"][self.group] = paged([self.collection["virtual_machines"][0]["results"][1]])
        self.assertEqual(self.translate()["policies"], [])

    def test_capacity_counts_native_broad_scope_without_guessing_limit(self):
        for policy in self.collection["policies"][0]["results"]:
            policy["scope"] = ["ANY"]
        result = self.translate()
        self.assertEqual(result["capacity"]["known_applicable_enabled_rules"], 2)
        self.assertEqual(result["capacity"]["broad_scope_enabled_rules"], 2)
        self.assertIsNone(result["capacity"]["limit"])
        self.assertIsNone(result["capacity"]["realized_rule_count"])
        self.assertTrue(any("footprint" in f["reason"] for f in result["findings"]))

    def test_broad_policy_specific_rule_scope_never_silently_broadens(self):
        for policy in self.collection["policies"][0]["results"]:
            policy["scope"] = ["ANY"]
        self.rule["scope"] = [self.group]
        result = self.translate()
        rule = result["policies"][-1]
        self.assertIsNone(rule["details"]["scope_applies_to_selected_vif"])
        self.assertFalse(rule["details"]["broad_dfw_scope"])
        self.assertTrue(any("no broad fallback" in reason for reason in rule["details"]["unresolved"]))

    def test_multinic_vm_requires_explicit_native_nic_identity(self):
        second = deepcopy(self.vif)
        second["external_id"] = "vif-1b"
        second["lport_attachment_id"] = "attachment-1b"
        self.collection["vifs"][0]["results"].append(second)
        self.collection["vifs"][0]["result_count"] += 1
        with self.assertRaises(ValueError):
            self.translate()
        self.assertEqual(self.translate(vif="vif-1")["target"]["external_id"], "vif-1")
        combined = translate_vm(self.metadata, self.collection, vm_external_id="vm-1")
        self.assertEqual({i["native_id"] for i in combined["interfaces"]}, {"vif-1", "vif-1b"})
        self.assertEqual(len(combined["capacity"]), 2)
        self.assertEqual(len({r["enforcement_point"] for r in combined["policies"]}), 2)

    def test_missing_attachment_keeps_end_to_end_unknown(self):
        self.vif.pop("lport_attachment_id")
        result = self.translate()
        self.assertFalse(result["policies"][-1]["details"]["workload_condition"]["complete"])
        self.assertFalse(result["interfaces"][0]["config"]["attachment_verified"])

    def test_duplicate_order_and_mixed_statefulness_preserve_uncertainty(self):
        policies = self.collection["policies"][0]["results"]
        policies[1]["category"] = "Application"
        policies[1]["sequence_number"] = 10
        policies[1]["stateful"] = False
        rules = self.translate()["policies"]
        self.assertTrue(all(r["details"]["statefulness"] == "unknown" for r in rules))
        self.assertTrue(all(not r["details"]["translated_conditions_complete"] for r in rules))

    def test_nested_services_exclusion_and_unsupported_profiles(self):
        nested = "/infra/services/nested"
        self.collection["services"][0]["results"].append(resource("Service", nested, service_entries=[{
            "resource_type": "NestedServiceServiceEntry", "nested_service_path": self.service}]))
        self.collection["services"][0]["result_count"] += 1
        self.rule["services"] = [nested]
        self.rule["destinations_excluded"] = True
        self.assertTrue(all(s["negated"] for s in self.translate()["policies"][-1]["selectors"] if s["role"] == "destination"))
        self.rule["context_profiles"] = ["/infra/context-profiles/l7"]
        self.assertFalse(self.translate()["policies"][-1]["details"]["translated_conditions_complete"])

    def test_ip_family_filter_survives_normalized_conditions(self):
        self.rule["ip_protocol"] = "IPV6"
        self.assertEqual(self.verdict(self.supported_rules())["decision"], "unknown")

    def test_cursor_truncation_duplicates_counts_and_foreign_paths_fail(self):
        for value in ([{"results": [], "cursor": "next"}], [{"results": [], "result_count": 1}],
                      [{"results": [], "cursor": "same"}, {"results": [], "cursor": "same"}]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                list_results(value)
        self.rule["path"] = "/infra/domains/foreign/security-policies/x/rules/allow-web"
        with self.assertRaises(ValueError):
            self.translate()

    def test_two_typed_submissions_validate_and_remain_partial(self):
        requests = normalized_submissions(self.metadata, self.collection, "lab", "vm-asset", vm_external_id="vm-1")
        self.assertEqual([r["data_type"] for r in requests], ["policy", "interface"])
        for request in requests:
            normalize(request["data_type"], request["payload"])
            self.assertEqual(request["completeness"], "partial")
        self.assertEqual(self.verdict(self.translate()["policies"])["decision"], "unknown")

    def test_cli_reads_native_pages_and_requires_vm_identity(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="nsx-test-", dir=repo) as directory:
            root = Path(directory)
            (root / "metadata.json").write_text(json.dumps(self.metadata))
            for key, filename in (("domains", "domains"), ("groups", "groups"), ("policies", "security-policies"),
                ("services", "services"), ("virtual_machines", "virtual-machines"), ("vifs", "vifs"), ("segments", "segments")):
                for i, page in enumerate(self.collection[key]):
                    (root / (filename + "-" + str(i) + ".json")).write_text(json.dumps(page))
            for path, pages in self.collection["rulebases"].items():
                (root / ("policy-" + path.rsplit("/", 1)[-1] + "-rules-0.json")).write_text(json.dumps(pages[0]))
            (root / "group-workloads-vms-0.json").write_text(json.dumps(self.collection["group_virtual_machines"][self.group][0]))
            (root / "segment-workload-vlan-ports-0.json").write_text(json.dumps(self.collection["segment_ports"][self.segment][0]))
            result = subprocess.run([sys.executable, str(repo / "examples/ansible/nsx/normalize.py"), str(root),
                "--vm-external-id", "vm-1", "--namespace", "lab", "--external-device-id", "vm-asset"],
                capture_output=True, text=True, check=True)
            requests = json.loads(result.stdout)
            self.assertEqual(len(requests), 2)
            for request in requests:
                normalize(request["data_type"], request["payload"])
