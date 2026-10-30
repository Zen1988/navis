from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from navis_api.normalized_adapter import normalize
from navis_common.nat import Packet
from navis_common.paloalto_adapter import translate_config, normalized_submissions
from navis_common.policy_pipeline import evaluate_original_address_pipeline
from navis_common.policy_selectors import evaluate_policy
from navis_common.trace import expand_flows


def security(name, *, source="any", destination="any", from_zone="any", to_zone="any", app="any", service="any", action="allow"):
    rule = ET.Element("entry", name=name)
    for field, value in (("source", source), ("destination", destination), ("from", from_zone),
                         ("to", to_zone), ("application", app), ("service", service)):
        ET.SubElement(ET.SubElement(rule, field), "member").text = value
    ET.SubElement(rule, "action").text = action
    return rule


def add_rule(scope, phase, kind, rule):
    path = scope
    for part in (phase, kind, "rules"):
        child = path.find(part)
        if child is None:
            child = ET.SubElement(path, part)
        path = child
    path.append(rule)


class PaloAltoExtendedTests(unittest.TestCase):
    def setUp(self):
        folder = Path(__file__).parent / "fixtures"
        self.root = ET.fromstring((folder / "paloalto-running-config.xml").read_text())
        self.catalog = (folder / "paloalto-applications.xml").read_text()
        self.meta = {"serial": "test-fw", "collected_at": "2026-10-30T00:00:00Z"}
        self.device = self.root.find("result/config/devices/entry")
        self.scope = self.device.find("vsys/entry")

    def xml(self):
        return ET.tostring(self.root, encoding="unicode")

    def translate(self, **evidence):
        return translate_config(self.xml(), self.meta, device_entry="localhost.localdomain", vsys="vsys1", **evidence)

    def panorama(self):
        config = ET.Element("config")
        shared = ET.SubElement(config, "shared")
        groups = ET.SubElement(ET.SubElement(ET.SubElement(config, "devices"), "entry", name="panorama"), "device-group")
        parent = ET.SubElement(groups, "entry", name="parent")
        child = ET.SubElement(groups, "entry", name="child")
        dev = ET.SubElement(ET.SubElement(child, "devices"), "entry", name="test-fw")
        ET.SubElement(ET.SubElement(dev, "vsys"), "entry", name="vsys1")
        for label, scope in (("shared", shared), ("parent", parent), ("child", child)):
            add_rule(scope, "pre-rulebase", "security", security(label + "-pre"))
            add_rule(scope, "post-rulebase", "security", security(label + "-post"))
        return config, parent, child

    def test_panorama_pre_local_post_order_and_scope_identity(self):
        config, parent, child = self.panorama()
        hierarchy = '<response status="success"><result><dg-hierarchy><dg name="parent"><dg name="child"/></dg></dg-hierarchy></result></response>'
        result = self.translate(panorama_xml=ET.tostring(config, encoding="unicode"), hierarchy_xml=hierarchy)
        names = [r["details"]["native_name"] for r in result["policies"]]
        self.assertEqual(names[:3], ["shared-pre", "parent-pre", "child-pre"])
        self.assertEqual(names[3:7], ["block-client", "allow-web", "appid", "disabled"])
        self.assertEqual(names[7:10], ["child-post", "parent-post", "shared-post"])
        self.assertEqual(names[-2:], ["intrazone-default", "interzone-default"])
        self.assertEqual(result["inheritance"], "panorama_hierarchy")
        self.assertEqual(len({r["rule_id"] for r in result["policies"]}), len(names))
        self.assertEqual([r["position"] for r in result["policies"]], list(range(1, 13)))

    def test_pushed_pre_post_and_explicit_target_filtering(self):
        pushed = ET.Element("panorama")
        scope = ET.SubElement(ET.SubElement(pushed, "vsys"), "entry", name="vsys1")
        add_rule(scope, "pre-rulebase", "security", security("inherited"))
        excluded = security("other-firewall")
        ET.SubElement(ET.SubElement(ET.SubElement(excluded, "target"), "devices"), "entry", name="other")
        add_rule(scope, "pre-rulebase", "security", excluded)
        add_rule(scope, "post-rulebase", "security", security("after-local"))
        result = self.translate(pushed_xml=ET.tostring(pushed, encoding="unicode"))
        names = [r["details"]["native_name"] for r in result["policies"]]
        self.assertEqual(names[0], "inherited")
        self.assertEqual(names[-3], "after-local")
        self.assertNotIn("other-firewall", names)
        self.assertEqual(result["inheritance"], "firewall_pushed")

    def test_hierarchy_missing_membership_and_duplicate_sources_fail(self):
        config, _, _ = self.panorama()
        xml = ET.tostring(config, encoding="unicode")
        with self.assertRaises(ValueError):
            self.translate(panorama_xml=xml)
        with self.assertRaises(ValueError):
            self.translate(panorama_xml=xml, hierarchy_xml='<dg-hierarchy><dg name="parent"/></dg-hierarchy>')
        with self.assertRaises(ValueError):
            self.translate(panorama_xml=xml, pushed_xml="<panorama/>")

    def test_default_override_uses_lowest_scope_and_zone_relation(self):
        override = ET.fromstring('<entry name="intrazone-default"><action>deny</action></entry>')
        add_rule(self.scope, "rulebase", "default-security-rules", override)
        rules = self.translate()["policies"][-2:]
        self.assertEqual(rules[0]["action"], "deny")
        supported = [{**r, "selectors_complete": True} for r in rules]
        result = evaluate_policy(supported, "unknown", "192.0.2.5", "192.0.2.6", "tcp", 443,
                                 complete=True, source_zone="trust", destination_zone="trust")
        self.assertEqual(result["decision"], "deny")
        self.assertEqual(evaluate_policy(supported, "unknown", "192.0.2.5", "192.0.2.6", "tcp", 443, complete=True)["decision"], "unknown")

    def application_rule(self, **evidence):
        return next(r for r in self.translate(applications_xml=self.catalog, **evidence)["policies"] if r["details"]["native_name"] == "appid")

    def app_verdict(self, rule, application, port, protocol="tcp"):
        # Completeness is explicitly enabled only for this isolated supported
        # rule test, never inferred for a collected policy snapshot.
        return evaluate_policy([{**rule, "selectors_complete": True}], "deny", "192.0.2.1", "198.51.100.1", protocol,
            port, complete=True, application=application)["decision"]

    def test_appid_identity_and_application_default_pairing(self):
        rule = self.application_rule()
        self.assertTrue(rule["details"]["translated_conditions_complete"])
        self.assertEqual(self.app_verdict(rule, "ssl", 443), "allow")
        self.assertEqual(self.app_verdict(rule, "ssl", 8443), "deny")
        self.assertEqual(self.app_verdict(rule, "database", 443), "deny")
        self.assertEqual(self.app_verdict(rule, None, 443), "unknown")
        self.assertEqual(expand_flows("192.0.2.1", "198.51.100.1", "tcp", 443, application="ssl")[0].application, "ssl")

    def test_application_group_keeps_each_app_paired_with_its_ports(self):
        group = ET.SubElement(ET.SubElement(self.scope, "application-group"), "entry", name="business")
        members = ET.SubElement(group, "members")
        for name in ("ssl", "database"):
            ET.SubElement(members, "member").text = name
        self.scope.find("rulebase/security/rules/entry[@name='appid']/application/member").text = "business"
        rule = self.application_rule()
        self.assertEqual(self.app_verdict(rule, "database", 5432), "allow")
        self.assertEqual(self.app_verdict(rule, "database", 5433, "udp"), "allow")
        self.assertEqual(self.app_verdict(rule, "ssl", 5432), "deny")
        self.assertEqual(self.app_verdict(rule, "database", 443), "deny")

    def test_dynamic_application_defaults_and_filters_are_not_widened(self):
        member = self.scope.find("rulebase/security/rules/entry[@name='appid']/application/member")
        member.text = "negotiated"
        rule = self.application_rule()
        self.assertEqual(self.app_verdict(rule, "negotiated", 50000), "unknown")
        member.text = "dynamic-apps"
        ET.SubElement(ET.SubElement(self.scope, "application-filter"), "entry", name="dynamic-apps")
        rule = self.application_rule()
        self.assertFalse(rule["details"]["translated_conditions_complete"])

    def test_predefined_application_container_expands_functions(self):
        catalog = ET.fromstring(self.catalog)
        container = ET.SubElement(catalog.find("result/application"), "entry", name="suite")
        functions = ET.SubElement(container, "functions")
        ET.SubElement(functions, "member").text = "ssl"
        ET.SubElement(functions, "member").text = "database"
        self.catalog = ET.tostring(catalog, encoding="unicode")
        self.scope.find("rulebase/security/rules/entry[@name='appid']/application/member").text = "suite"
        rule = self.application_rule()
        self.assertEqual(self.app_verdict(rule, "ssl", 443), "allow")
        self.assertEqual(self.app_verdict(rule, "database", 5432), "allow")
        self.assertEqual(self.app_verdict(rule, "ssl", 5432), "deny")

    def test_bad_application_condition_cannot_bypass_normalized_validation(self):
        rule = self.application_rule()
        rule["details"]["application_condition"]["default_services"][0]["end"] = 70000
        with self.assertRaises(ValueError):
            normalize("policy", {"entries": [rule]})

    def test_inherited_nat_order_and_unresolved_raw_object_overrides(self):
        config, parent, child = self.panorama()
        for label, scope in (("parent", parent), ("child", child)):
            nat = ET.Element("entry", name="same-name")
            for field in ("from", "to", "source", "destination"):
                ET.SubElement(ET.SubElement(nat, field), "member").text = "any"
            ET.SubElement(nat, "service").text = "any"
            add_rule(scope, "pre-rulebase", "nat", nat)
            address = ET.SubElement(ET.SubElement(scope, "address"), "entry", name="conflict")
            ET.SubElement(address, "ip-netmask").text = "10.0.0.1" if label == "parent" else "10.0.0.2"
        add_rule(child, "pre-rulebase", "security", security("conflicting-address", source="conflict"))
        hierarchy = '<dg-hierarchy><dg name="parent"><dg name="child"/></dg></dg-hierarchy>'
        result = self.translate(panorama_xml=ET.tostring(config, encoding="unicode"), hierarchy_xml=hierarchy)
        self.assertEqual([n["details"]["scope"] for n in result["nat"]], ["device-group:parent", "device-group:child"])
        self.assertNotEqual(result["nat"][0]["rule_id"], result["nat"][1]["rule_id"])
        rule = next(r for r in result["policies"] if r["details"]["native_name"] == "conflicting-address")
        self.assertFalse(rule["details"]["translated_conditions_complete"])
        self.assertFalse(any(s["role"] == "source" for s in rule["selectors"]))

    def nat_rule(self, name, source="any", destination="any", from_zone="trust", to_zone="untrust", service="any"):
        rule = ET.Element("entry", name=name)
        for field, value in (("source", source), ("destination", destination), ("from", from_zone), ("to", to_zone)):
            ET.SubElement(ET.SubElement(rule, field), "member").text = value
        ET.SubElement(rule, "service").text = service
        add_rule(self.scope, "rulebase", "nat", rule)
        return rule

    def test_static_source_destination_combined_and_no_nat(self):
        self.nat_rule("exempt")
        source = self.nat_rule("snat", source="client")
        ET.SubElement(ET.SubElement(ET.SubElement(source, "source-translation"), "static-ip"), "translated-address").text = "198.51.100.99"
        destination = self.nat_rule("dnat")
        node = ET.SubElement(destination, "destination-translation")
        ET.SubElement(node, "translated-address").text = "10.1.0.10"
        ET.SubElement(node, "translated-port").text = "8443"
        combined = self.nat_rule("combined", source="client")
        ET.SubElement(ET.SubElement(ET.SubElement(combined, "source-translation"), "static-ip"), "translated-address").text = "198.51.100.99"
        ET.SubElement(ET.SubElement(combined, "destination-translation"), "translated-address").text = "10.1.0.10"
        entries = self.translate()["nat"]
        self.assertEqual([e["translation_kind"] for e in entries], ["no_nat", "source", "destination", "combined"])
        self.assertEqual(entries[2]["translation"], {"address": "10.1.0.10", "port": 8443})
        self.assertTrue(all(e["details"]["translated_conditions_complete"] for e in entries))
        normalize("nat", {"entries": entries})

    def test_dynamic_pat_and_bidirectional_static_nat_remain_explicit(self):
        rule = self.nat_rule("pat")
        ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(rule, "source-translation"), "dynamic-ip-and-port"), "translated-address"), "member").text = "198.51.100.99"
        rule = self.nat_rule("bidirectional", source="client")
        node = ET.SubElement(ET.SubElement(rule, "source-translation"), "static-ip")
        ET.SubElement(node, "translated-address").text = "198.51.100.99"
        ET.SubElement(node, "bi-directional").text = "yes"
        entries = self.translate()["nat"]
        self.assertEqual(entries[0]["translation_kind"], "unsupported")
        self.assertEqual(entries[0]["translation"], {})
        self.assertTrue(all(not e["details"]["translated_conditions_complete"] for e in entries))

    def test_dnat_pipeline_matches_original_addresses_with_post_nat_zone(self):
        nat = self.nat_rule("publish", destination="203.0.113.10", from_zone="untrust", service="https")
        node = ET.SubElement(nat, "destination-translation")
        ET.SubElement(node, "translated-address").text = "10.1.0.10"
        ET.SubElement(node, "translated-port").text = "8443"
        add_rule(self.scope, "rulebase", "security", security("publish-policy", destination="203.0.113.10",
            from_zone="untrust", to_zone="trust", service="https"))
        result = self.translate()
        nats = [{**n, "selectors_complete": True} for n in result["nat"]]
        policies = [{**p, "selectors_complete": True} for p in result["policies"] if p["details"]["native_name"] == "publish-policy"]
        def zones(address):
            return {"status": "resolved", "zone": "trust" if address == "10.1.0.10" else "untrust"}
        packet = Packet("192.0.2.99", "203.0.113.10", "tcp", 443, 50000)
        assessment = evaluate_original_address_pipeline(packet, nats, policies, zones,
            source_zone="untrust", nat_complete=True, policy_complete=True)
        self.assertEqual(assessment["decision"], "allow")
        self.assertEqual(assessment["packet"].destination, "10.1.0.10")
        self.assertEqual(assessment["packet"].destination_port, 8443)
        self.assertEqual(assessment["nat_destination_zone"], "untrust")
        self.assertEqual(assessment["policy_destination_zone"], "trust")
        unresolved = evaluate_original_address_pipeline(packet, result["nat"], policies, zones,
            source_zone="untrust", nat_complete=False, policy_complete=True)
        self.assertEqual(unresolved["decision"], "unknown")

    def add_network(self):
        network = ET.fromstring('''<network><interface><ethernet>
          <entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.1/24"/></ip><units>
            <entry name="ethernet1/1.10"><tag>10</tag><ip><entry name="10.10.0.1/24"/></ip></entry>
          </units></layer3></entry>
          <entry name="ethernet1/2"><layer3><ip><entry name="198.51.100.1/24"/></ip></layer3></entry>
          <entry name="ethernet1/3"><layer3><ip><entry name="203.0.113.1/24"/></ip></layer3></entry>
        </ethernet></interface><virtual-router><entry name="default"><interface>
          <member>ethernet1/1</member><member>ethernet1/1.10</member><member>ethernet1/2</member></interface>
          <routing-table><ip><static-route>
            <entry name="default"><destination>0.0.0.0/0</destination><interface>ethernet1/2</interface><nexthop><ip-address>198.51.100.254</ip-address></nexthop></entry>
            <entry name="blackhole"><destination>10.255.0.0/16</destination><nexthop><discard/></nexthop></entry>
            <entry name="recursive"><destination>10.2.0.0/16</destination><nexthop><ip-address>192.0.2.2</ip-address></nexthop></entry>
            <entry name="next-vr"><destination>10.3.0.0/16</destination><nexthop><next-vr>other</next-vr></nexthop></entry>
          </static-route></ip></routing-table></entry>
          <entry name="other"><interface><member>ethernet1/3</member></interface></entry>
        </virtual-router></network>''')
        self.device.append(network)

    def test_configured_interfaces_vrf_static_discard_and_recursive_routes(self):
        self.add_network()
        result = self.translate()
        self.assertEqual({i["native_id"] for i in result["interfaces"]}, {"ethernet1/1", "ethernet1/1.10", "ethernet1/2"})
        self.assertTrue(all(i["vrf"] == "default" for i in result["interfaces"]))
        sub = next(i for i in result["interfaces"] if i["native_id"] == "ethernet1/1.10")
        self.assertEqual(sub["parent"], "ethernet1/1")
        self.assertEqual(sub["vlans"], [10])
        self.assertEqual(len(result["routes"]), 3)
        discard = next(r for r in result["routes"] if r["route_type"] == "discard")
        self.assertIsNone(discard["next_hop"])
        self.assertIsNone(discard["interface"])
        normalize("route", {"entries": result["routes"]})
        normalize("interface", {"entries": result["interfaces"]})
        self.assertTrue(any(r["native_id"] == "next-vr" and r["unresolved"] for r in result["route_candidates"]))

    def test_active_rib_preserves_ecmp_and_excludes_inactive_or_foreign_vr(self):
        self.add_network()
        routes = '''<response status="success"><result>
          <entry><virtual-router>default</virtual-router><destination>0.0.0.0/0</destination><flags>AS</flags><nexthop>198.51.100.254</nexthop><interface>ethernet1/2</interface></entry>
          <entry><virtual-router>default</virtual-router><destination>0.0.0.0/0</destination><flags>AS</flags><nexthop>198.51.100.253</nexthop><interface>ethernet1/2</interface></entry>
          <entry><virtual-router>default</virtual-router><destination>192.0.2.0/24</destination><flags>AC</flags><nexthop>0.0.0.0</nexthop><interface>ethernet1/1</interface></entry>
          <entry><virtual-router>default</virtual-router><destination>10.0.0.0/8</destination><flags>S</flags><nexthop>198.51.100.250</nexthop><interface>ethernet1/2</interface></entry>
          <entry><virtual-router>other</virtual-router><destination>203.0.113.0/24</destination><flags>AC</flags><nexthop>0.0.0.0</nexthop><interface>ethernet1/3</interface></entry>
        </result></response>'''
        result = self.translate(routes_xml=routes)
        self.assertEqual(len(result["routes"]), 3)
        self.assertEqual(sum(r["destination"] == "0.0.0.0/0" for r in result["routes"]), 2)
        self.assertTrue(all(r["details"]["evidence"] == "active_rib" for r in result["routes"]))
        self.assertEqual(result["routes"][-1]["route_type"], "connected")
        self.assertEqual(result["coverage"], "partial")
        normalize("route", {"entries": result["routes"]})

    def test_all_five_submission_types_validate_with_new_evidence(self):
        self.add_network()
        self.nat_rule("exempt")
        requests = normalized_submissions(self.xml(), self.meta, "lab", "asset001", device_entry="localhost.localdomain",
            vsys="vsys1", applications_xml=self.catalog)
        self.assertEqual({r["data_type"] for r in requests}, {"policy", "security_zone", "nat", "interface", "route"})
        for request in requests:
            self.assertEqual(request["completeness"], "partial")
            normalize(request["data_type"], request["payload"])
