from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from navis_api.normalized_adapter import normalize
from navis_common.checkpoint_adapter import normalized_submission, normalized_submissions, pages, translate_management
from navis_common.policy_selectors import evaluate_ordered_layers


def paged(key, values, **attrs):
    return [{key: values, "from": 1 if values else 0, "to": len(values), "total": len(values), **attrs}]


class CheckPointAdapterTests(unittest.TestCase):
    def setUp(self):
        self.domain = {"uid": "domain-a", "name": "Domain A"}
        self.metadata = {"management_id": "management-a", "domain_uid": "domain-a", "collected_at": "2026-10-30T00:00:00Z"}
        objects = [
            {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
            {"uid": "accept", "name": "Accept", "type": "RulebaseAction"},
            {"uid": "drop", "name": "Drop", "type": "RulebaseAction"},
            {"uid": "inline-action", "name": "Apply Layer", "type": "RulebaseAction"},
            {"uid": "targets", "name": "Policy Targets", "type": "Global"},
            {"uid": "client", "name": "same-name", "type": "host", "ipv4-address": "192.0.2.5"},
            {"uid": "server", "name": "same-name", "type": "host", "ipv4-address": "198.51.100.10"},
            {"uid": "network", "name": "net", "type": "network", "subnet4": "192.0.2.0", "mask-length4": 24},
            {"uid": "range", "name": "range", "type": "address-range", "ipv4-address-first": "203.0.113.8", "ipv4-address-last": "203.0.113.11"},
            {"uid": "v6", "name": "v6", "type": "host", "ipv6-address": "2001:db8::5"},
            {"uid": "group", "name": "clients", "type": "group", "members": ["client", "network", "range", "v6"]},
            {"uid": "https", "name": "HTTPS", "type": "service-tcp", "port": "443", "source-port": ">1023"},
            {"uid": "dns", "name": "DNS", "type": "service-udp", "port": "53"},
            {"uid": "services", "name": "services", "type": "service-group", "members": ["https", "dns"]},
        ]
        self.gateway = {"uid": "gateway-a", "name": "Firewall", "type": "simple-gateway", "domain": self.domain}
        self.package = {"uid": "package-a", "name": "Policy", "type": "package", "domain": self.domain,
                        "installation-targets": ["gateway-a"], "access-layers": [{"uid": "layer-a"}, {"uid": "layer-b"}]}
        self.layers = [{"uid": name, "type": "access-layer", "domain": self.domain, "implicit-cleanup-action": "drop"}
                       for name in ("layer-a", "layer-b", "inline")]
        self.parent = self.rule("parent", source=["client"], action="inline-action", **{"inline-layer": "inline"})
        self.child = self.rule("child", service=["https"])
        self.second = self.rule("second", service=["https"])
        self.collection = {"objects": paged("objects", objects), "gateways": paged("objects", [self.gateway]),
            "packages": paged("packages", [self.package]), "package_details": {"package-a": self.package},
            "layers": self.layers, "rulebases": {
                "layer-a": paged("rulebase", [{"type": "access-section", "uid": "section", "rulebase": [self.parent]}], uid="layer-a"),
                "layer-b": paged("rulebase", [self.second], uid="layer-b"),
                "inline": paged("rulebase", [self.child], uid="inline")}}

    def rule(self, uid, **changes):
        return {"uid": uid, "name": uid, "type": "access-rule", "enabled": True,
            "source": ["any"], "destination": ["server"], "service": ["any"], "action": "accept",
            "vpn": ["any"], "time": ["any"], "content": ["any"], "install-on": ["targets"], **changes}

    def translate(self):
        return translate_management(self.metadata, self.collection, package_uid="package-a", gateway_uid="gateway-a")

    def supported_layers(self):
        result = self.translate()
        def enable(rules):
            for rule in rules:
                rule["selectors_complete"] = rule["details"]["translated_conditions_complete"]
                if "inline_rules" in rule["details"]:
                    enable(rule["details"]["inline_rules"])
                    rule["details"]["inline_complete"] = True
        layers = [result["layers"][key] for key in result["ordered_layers"]]
        for layer in layers:
            layer["complete"] = True
            enable(layer["rules"])
        return layers

    def verdict(self, layers, source="192.0.2.5", port=443):
        return evaluate_ordered_layers(layers, source, "198.51.100.10", "tcp", port, source_port=50000)

    def test_domain_gateway_package_order_and_native_identity(self):
        result = self.translate()
        self.assertEqual(result["ordered_layers"], ["layer-a", "layer-b"])
        rules = result["policies"]
        self.assertEqual([r["rule_id"] for r in rules], ["parent", "implicit-cleanup:layer-a", "second", "implicit-cleanup:layer-b"])
        self.assertEqual(rules[0]["details"]["ordered_layer_position"], 1)
        self.assertEqual(rules[2]["details"]["ordered_layer_position"], 2)
        self.assertEqual(rules[0]["details"]["inline_layer_uid"], "inline")
        self.assertEqual(rules[0]["selectors"][0]["value"], "192.0.2.5/32")
        self.assertEqual(rules[0]["selectors"][1]["value"], "198.51.100.10/32")
        self.assertTrue(all(r["details"]["statefulness"] == "stateful" for r in rules))

    def test_inline_parent_gate_child_cleanup_and_leaf_path(self):
        layers = self.supported_layers()
        self.assertEqual(self.verdict(layers)["decision"], "allow")
        self.assertEqual(self.verdict(layers, port=22)["decision"], "deny")
        self.assertEqual(self.verdict(layers, source="192.0.2.6")["decision"], "deny")
        self.assertEqual(self.verdict(layers)["layers"][0]["rule_path"], ["parent", "child"])

    def test_accept_in_first_ordered_layer_does_not_bypass_second(self):
        self.second["action"] = "drop"
        result = self.verdict(self.supported_layers())
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(len(result["layers"]), 2)

    def test_unknown_cleanup_and_missing_inline_remain_unknown(self):
        self.layers[2].pop("implicit-cleanup-action")
        self.assertEqual(self.verdict(self.supported_layers(), port=22)["decision"], "unknown")
        self.collection["rulebases"].pop("inline")
        result = self.translate()
        self.assertTrue(any("not collected" in reason for reason in result["policies"][0]["details"]["unresolved"]))

    def test_negation_groups_ranges_ipv6_and_service_groups(self):
        self.parent.pop("inline-layer")
        self.parent.update(source=["group"], **{"source-negate": True}, service=["services"], action="accept")
        rule = self.translate()["policies"][0]
        addresses = [s for s in rule["selectors"] if s["role"] == "source"]
        self.assertEqual({s["value"] for s in addresses}, {"192.0.2.5/32", "192.0.2.0/24", "203.0.113.8/30", "2001:db8::5/128"})
        self.assertTrue(all(s["negated"] for s in addresses))
        services = [s["value"] for s in rule["selectors"] if s["role"] == "service"]
        self.assertEqual({s["protocol"] for s in services}, {"tcp", "udp"})
        self.assertEqual(services[0]["source_port_start"], 1024)

    def test_unresolved_alternative_removes_entire_role(self):
        self.parent["source"] = ["client", "missing"]
        rule = self.translate()["policies"][0]
        self.assertFalse(any(s["role"] == "source" for s in rule["selectors"]))
        self.assertFalse(rule["details"]["translated_conditions_complete"])

    def test_cyclic_groups_inline_layers_and_dynamic_objects(self):
        objects = self.collection["objects"][0]["objects"]
        next(o for o in objects if o["uid"] == "group")["members"] = ["group"]
        self.parent["source"] = ["group"]
        self.assertFalse(self.translate()["policies"][0]["details"]["translated_conditions_complete"])
        self.parent["source"] = ["client"]
        self.child["inline-layer"] = "layer-a"
        result = self.translate()
        self.assertTrue(any("cyclic" in reason for f in result["findings"] for reason in [f["reason"]]))

    def test_install_on_filters_gateway_and_domain_isolation(self):
        foreign = {"uid": "other-gateway", "type": "simple-gateway", "domain": self.domain}
        self.collection["objects"][0]["objects"].append(foreign)
        self.collection["objects"][0]["total"] += 1
        self.collection["objects"][0]["to"] += 1
        self.parent["install-on"] = ["other-gateway"]
        self.assertEqual(self.translate()["policies"][0]["rule_id"], "implicit-cleanup:layer-a")
        self.package["domain"] = {"uid": "other-domain"}
        with self.assertRaises(ValueError):
            self.translate()

    def test_pagination_gaps_overlap_totals_and_rulebase_identity_fail(self):
        bad = [{"objects": [{"uid": "x"}], "from": 2, "to": 2, "total": 2}]
        with self.assertRaises(ValueError):
            pages(bad, "objects")
        self.collection["objects"][0]["total"] += 1
        with self.assertRaises(ValueError):
            self.translate()
        self.collection["objects"][0]["total"] -= 1
        self.collection["rulebases"]["layer-a"][0]["uid"] = "layer-b"
        with self.assertRaises(ValueError):
            self.translate()

    def test_normalized_policy_preserves_nested_conditions_and_stays_partial(self):
        request = normalized_submission(self.metadata, self.collection, "lab", "firewall-asset", package_uid="package-a", gateway_uid="gateway-a")
        normalize("policy", request["payload"])
        self.assertEqual(request["source"]["external_device_id"], "firewall-asset")
        self.assertEqual(request["completeness"], "partial")
        raw = self.translate()
        layers = [raw["layers"][key] for key in raw["ordered_layers"]]
        self.assertEqual(self.verdict(layers)["decision"], "unknown")

    def nat_rule(self, **changes):
        objects = self.collection["objects"][0]["objects"]
        if not any(o["uid"] == "original" for o in objects):
            objects.append({"uid": "original", "name": "Original", "type": "Global"})
            objects.append({"uid": "alt-tcp", "name": "Alt TCP", "type": "service-tcp", "port": "8443"})
            self.collection["objects"] = paged("objects", objects)
        rule = {"uid": "nat-a", "type": "nat-rule", "enabled": True, "method": "static", "auto-generated": False,
            "original-source": "client", "original-destination": "server", "original-service": "https",
            "translated-source": "original", "translated-destination": "original", "translated-service": "original",
            "install-on": ["targets"], **changes}
        self.collection["nat"] = paged("rulebase", [rule])
        return rule

    def test_manual_static_nat_and_original_marker(self):
        rule = self.nat_rule(**{"translated-source": "server"})
        nat = self.translate()["nat"][0]
        self.assertEqual(nat["translation_kind"], "source")
        self.assertEqual(nat["translation"], {"address": "198.51.100.10"})
        self.assertTrue(nat["details"]["translated_conditions_complete"])
        self.assertFalse(nat["details"]["packet_stage_verified"])
        self.assertEqual(nat["processing_stage"], "checkpoint_management_nat_stage_unverified")
        rule.update(**{"translated-source": "original", "translated-destination": "client", "translated-service": "alt-tcp"})
        nat = self.translate()["nat"][0]
        self.assertEqual(nat["translation_kind"], "destination")
        self.assertEqual(nat["translation"], {"address": "192.0.2.5", "port": 8443})

    def test_automatic_and_hide_nat_do_not_become_fixed_first_match_translations(self):
        rule = self.nat_rule(**{"auto-generated": True, "translated-source": "server"})
        nat = self.translate()["nat"][0]
        self.assertEqual(nat["translation_kind"], "unsupported")
        self.assertEqual(nat["translation"], {})
        rule.update(**{"auto-generated": False, "method": "hide"})
        self.assertEqual(self.translate()["nat"][0]["translation_kind"], "unsupported")

    def test_no_nat_and_separate_policy_nat_submissions_validate(self):
        self.nat_rule()
        self.assertEqual(self.translate()["nat"][0]["translation_kind"], "no_nat")
        requests = normalized_submissions(self.metadata, self.collection, "lab", "asset001", package_uid="package-a", gateway_uid="gateway-a")
        self.assertEqual([r["data_type"] for r in requests], ["policy", "nat"])
        for request in requests:
            normalize(request["data_type"], request["payload"])
            self.assertEqual(request["completeness"], "partial")

    def test_cross_domain_objects_and_unknown_rule_conditions_remain_unresolved(self):
        client = next(o for o in self.collection["objects"][0]["objects"] if o["uid"] == "client")
        client["domain"] = {"uid": "different-domain", "name": "Other Domain"}
        self.parent["future-condition"] = "unknown"
        rule = self.translate()["policies"][0]
        self.assertTrue(any("cross-domain" in reason for reason in rule["details"]["unresolved"]))
        self.assertTrue(any("future-condition" in reason for reason in rule["details"]["unresolved"]))

    def test_cli_reads_native_collector_layout(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="checkpoint-test-", dir=repo) as directory:
            root = Path(directory)
            for filename, data in (("metadata", self.metadata), ("objects", self.collection["objects"]),
                                   ("gateways", self.collection["gateways"]), ("packages", self.collection["packages"]),
                                   ("access-layers", paged("access-layers", self.layers)), ("package-package-a", self.package)):
                (root / (filename + ".json")).write_text(json.dumps(data), encoding="utf-8")
            for layer in self.layers:
                (root / ("layer-" + layer["uid"] + ".json")).write_text(json.dumps(layer), encoding="utf-8")
                (root / ("access-" + layer["uid"] + ".json")).write_text(json.dumps(self.collection["rulebases"][layer["uid"]]), encoding="utf-8")
            result = subprocess.run([sys.executable, str(repo / "examples/ansible/checkpoint/normalize.py"), str(root),
                "--package-uid", "package-a", "--gateway-uid", "gateway-a", "--namespace", "lab", "--external-device-id", "asset001"],
                capture_output=True, text=True, check=True)
            request = json.loads(result.stdout)[0]
            normalize("policy", request["payload"])
            self.assertEqual(request["completeness"], "partial")
