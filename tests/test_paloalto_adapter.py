import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

from navis_api.normalized_adapter import normalize
from navis_common.paloalto_adapter import normalized_submissions, translate_config
from navis_common.policy_selectors import evaluate_policy, evaluate_rule


class PaloAltoAdapterTests(unittest.TestCase):
    def setUp(self):
        self.xml = (Path(__file__).parent / "fixtures" / "paloalto-running-config.xml").read_text()
        self.meta = {"serial": "test-fw", "collected_at": "2026-10-30T00:00:00Z"}

    def translate(self, xml=None, vsys="vsys1"):
        return translate_config(self.xml if xml is None else xml, self.meta,
                                device_entry="localhost.localdomain", vsys=vsys)

    def modify_rule(self, change, name="allow-web"):
        root = ET.fromstring(self.xml)
        rule = next(r for r in root.findall(".//vsys/entry/rulebase/security/rules/entry") if r.get("name") == name)
        change(rule)
        return ET.tostring(root, encoding="unicode")

    def test_order_identity_actions_disabled_and_statefulness(self):
        rules = self.translate()["policies"]
        self.assertEqual([r["rule_id"] for r in rules[:4]], ["block-client", "allow-web", "appid", "disabled"])
        self.assertEqual([r["position"] for r in rules], [1, 2, 3, 4, 5, 6])
        self.assertEqual(rules[0]["action"], "deny")
        self.assertEqual(rules[0]["details"]["native_action"], "reset-both")
        self.assertEqual(rules[0]["details"]["native_uuid"], "test-block")
        self.assertFalse(rules[3]["enabled"])
        self.assertTrue(rules[1]["details"]["translated_conditions_complete"])
        self.assertTrue(all(r["details"]["statefulness"] == "stateful" and not r["details"]["selectors_complete"] for r in rules))
        self.assertTrue(all(r["default_action"] == "unknown" for r in rules))

    def test_nested_groups_ranges_ipv6_and_vsys_isolation(self):
        rules = self.translate()["policies"]
        sources = {s["value"] for s in rules[1]["selectors"] if s["role"] == "source"}
        self.assertEqual(sources, {"192.0.2.5/32", "192.0.2.8/30", "2001:db8::/64"})
        other = self.translate(vsys="vsys2")["policies"]
        self.assertEqual(len(other), 3)
        self.assertEqual(other[0]["selectors"][0]["value"], "203.0.113.1/32")
        self.assertNotEqual(rules[0]["enforcement_point"], other[0]["enforcement_point"])

    def test_service_ranges_and_source_ports_match_common_model(self):
        rule = self.translate()["policies"][1]
        services = [s["value"] for s in rule["selectors"] if s["role"] == "service"]
        self.assertEqual([(s["destination_port_start"], s["destination_port_end"]) for s in services], [(443, 443), (8443, 8444)])
        args = (rule["selectors"], "192.0.2.8", "198.51.100.10", "tcp")
        self.assertTrue(evaluate_rule(*args, 8444, source_port=50000, source_zone="trust", destination_zone="untrust"))
        self.assertFalse(evaluate_rule(*args, 8445, source_port=50000, source_zone="trust", destination_zone="untrust"))
        self.assertFalse(evaluate_rule(*args, 443, source_port=80, source_zone="trust", destination_zone="untrust"))
        self.assertFalse(evaluate_rule(*args, 443, source_port=50000, source_zone="untrust", destination_zone="trust"))
        self.assertIsNone(evaluate_rule(*args, 443, source_zone="trust", destination_zone="untrust"))

    def test_appid_application_default_is_not_guessed_as_tcp_443_or_any(self):
        rule = self.translate()["policies"][2]
        self.assertFalse(rule["details"]["translated_conditions_complete"])
        self.assertTrue(rule["details"]["application_condition"]["application_default"])
        self.assertTrue(any("application-default" in reason for reason in rule["details"]["unresolved"]))
        self.assertIsNone(rule["details"]["application_condition"]["applications"])

    def test_nested_udp_service_and_any_source_port(self):
        root = ET.fromstring(self.xml)
        groups = root.find("result/config/shared/service-group")
        group = ET.SubElement(groups, "entry", name="outer")
        members = ET.SubElement(group, "members")
        ET.SubElement(members, "member").text = "inner"
        group = ET.SubElement(groups, "entry", name="inner")
        ET.SubElement(ET.SubElement(group, "members"), "member").text = "dns"
        rule = root.find(".//vsys/entry/rulebase/security/rules/entry")
        rule.find("service/member").text = "outer"
        translated = self.translate(ET.tostring(root, encoding="unicode"))["policies"][0]
        options = {"source_zone": "trust", "destination_zone": "untrust"}
        self.assertTrue(evaluate_rule(translated["selectors"], "192.0.2.5", "198.51.100.10", "udp", 53, **options))
        self.assertFalse(evaluate_rule(translated["selectors"], "192.0.2.5", "198.51.100.10", "tcp", 53, **options))
        # A cycle must remove the whole service role, never turn it into any.
        members.find("member").text = "outer"
        translated = self.translate(ET.tostring(root, encoding="unicode"))["policies"][0]
        self.assertFalse(any(s["role"] == "service" for s in translated["selectors"]))
        self.assertTrue(any("cyclic service" in reason for reason in translated["details"]["unresolved"]))

    def test_negation_applies_to_whole_expanded_group(self):
        xml = self.modify_rule(lambda r: ET.SubElement(r, "negate-source").__setattr__("text", "yes"))
        rule = self.translate(xml)["policies"][1]
        self.assertTrue(all(s["negated"] for s in rule["selectors"] if s["role"] == "source"))
        args = (rule["selectors"],)
        options = {"source_port": 50000, "source_zone": "trust", "destination_zone": "untrust"}
        self.assertFalse(evaluate_rule(*args, "192.0.2.5", "198.51.100.10", "tcp", 443, **options))
        self.assertTrue(evaluate_rule(*args, "203.0.113.5", "198.51.100.10", "tcp", 443, **options))

    def test_unknown_alternative_does_not_leave_narrowed_partial_group(self):
        xml = self.modify_rule(lambda r: ET.SubElement(r.find("source"), "member").__setattr__("text", "missing"))
        rule = self.translate(xml)["policies"][1]
        self.assertFalse(any(s["role"] == "source" for s in rule["selectors"]))
        self.assertFalse(rule["details"]["translated_conditions_complete"])

    def test_fqdn_dynamic_and_cycles_are_unresolved(self):
        for name in ("dns-name", "dynamic", "missing"):
            with self.subTest(name=name):
                xml = self.modify_rule(lambda r: setattr(r.find("source/member"), "text", name))
                self.assertFalse(self.translate(xml)["policies"][1]["details"]["translated_conditions_complete"])
        root = ET.fromstring(self.xml)
        group = root.find(".//vsys/entry/address-group/entry/static/member")
        group.text = "nested"
        rule = self.translate(ET.tostring(root, encoding="unicode"))["policies"][1]
        self.assertTrue(any("cyclic" in reason for reason in rule["details"]["unresolved"]))

    def test_colliding_shared_and_local_objects_do_not_guess_precedence(self):
        root = ET.fromstring(self.xml)
        entry = ET.SubElement(root.find("result/config/shared/address"), "entry", name="client")
        ET.SubElement(entry, "ip-netmask").text = "192.0.2.99"
        rule = self.translate(ET.tostring(root, encoding="unicode"))["policies"][0]
        self.assertFalse(any(s["role"] == "source" for s in rule["selectors"]))
        self.assertTrue(any("collision" in reason for reason in rule["details"]["unresolved"]))

    def test_schedule_target_rule_type_and_unknown_fields_remain_unresolved(self):
        def modify(rule):
            ET.SubElement(rule, "schedule").text = "office-hours"
            ET.SubElement(rule, "target")
            ET.SubElement(rule, "rule-type").text = "intrazone"
            ET.SubElement(rule, "future-condition").text = "value"
        rule = self.translate(self.modify_rule(modify))["policies"][1]
        self.assertEqual(len(rule["details"]["unresolved"]), 2)
        self.assertEqual(rule["details"]["zone_relation"], "intrazone")

    def test_zones_and_normalized_envelopes(self):
        submissions = normalized_submissions(self.xml, self.meta, "lab", "asset001",
                                            device_entry="localhost.localdomain", vsys="vsys1")
        self.assertEqual([s["data_type"] for s in submissions], ["policy", "security_zone", "nat", "interface", "route"])
        for submission in submissions:
            self.assertEqual(submission["source"]["external_device_id"], "asset001")
            self.assertEqual(submission["completeness"], "partial")
            normalize(submission["data_type"], submission["payload"])
        zones = submissions[1]["payload"]["entries"]
        self.assertEqual(zones[0]["interfaces"], ["ethernet1/1", "ethernet1/1.10"])
        rule = submissions[0]["payload"]["entries"][0]
        verdict = evaluate_policy([rule], "unknown", "192.0.2.5", "198.51.100.10", "tcp", 443,
                                  complete=False, source_port=50000, source_zone="trust", destination_zone="untrust")
        self.assertEqual(verdict["decision"], "unknown")

    def test_bad_xml_api_failure_missing_scope_and_duplicates_fail(self):
        for xml in ("<broken", '<response status="error"><result/></response>',
                    '<!DOCTYPE config><config/>', '<response status="success"><result><security/></result></response>',
                    self.xml.replace('name="vsys1"', 'name="wrong"'),
                    self.xml.replace('name="allow-web"', 'name="block-client"')):
            with self.subTest(xml=xml[:40]), self.assertRaises(ValueError):
                self.translate(xml)

    def test_empty_rulebase_preserves_separate_documented_zone_defaults(self):
        root = ET.fromstring(self.xml)
        root.find(".//vsys/entry/rulebase/security/rules").clear()
        result = self.translate(ET.tostring(root, encoding="unicode"))
        self.assertEqual([r["details"]["zone_relation"] for r in result["policies"]], ["intrazone", "interzone"])
        self.assertEqual([r["action"] for r in result["policies"]], ["allow", "deny"])
        self.assertEqual(result["coverage"], "partial")

    def test_cli_uses_collection_metadata_and_returns_valid_requests(self):
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="paloalto-test-", dir=repo) as directory:
            root = Path(directory)
            (root / "test-fw").mkdir()
            (root / "test-fw" / "running-config.xml").write_text(self.xml)
            (root / "metadata.json").write_text(json.dumps({"collected_at": self.meta["collected_at"], "firewall_serials": ["test-fw"]}))
            result = subprocess.run([sys.executable, str(repo / "examples/ansible/paloalto/normalize.py"), str(root),
                "--serial", "test-fw", "--vsys", "vsys1", "--device-entry", "localhost.localdomain",
                "--namespace", "lab", "--external-device-id", "asset001"], capture_output=True, text=True, check=True)
            requests = json.loads(result.stdout)
            self.assertEqual(len(requests), 5)
            for request in requests:
                normalize(request["data_type"], request["payload"])
