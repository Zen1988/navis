import unittest
from navis_common.aci_adapter import adapt_interfaces, fabric_evidence_submission, label_match, normalized_policy_submission, translate_inventory, translate_semantics
from navis_api.normalized_adapter import normalize


class AciAdapterTests(unittest.TestCase):
    def test_cisco_label_matching_table_and_missing_evidence(self):
        cases = [([], [], "All", True), (["x", "y"], ["x"], "All", True),
                 (["x"], ["x", "y"], "All", False), (["x"], ["y"], "AtLeastOne", False),
                 (["x"], [], "None", True), ([], ["x"], "None", False),
                 (["x", "y"], ["x", "y"], "AtMostOne", False),
                 (["x"], ["y"], "AtMostOne", False), ([], [], "AtMostOne", True)]
        for provider, consumer, mode, expected in cases:
            with self.subTest(provider=provider, consumer=consumer, mode=mode):
                self.assertEqual(label_match(provider, consumer, mode), expected)
        self.assertIsNone(label_match(None, [], "All"))
        self.assertIsNone(label_match([], [], "unknown"))
    def setUp(self):
        self.meta = {"fabric_id": "fabric-a", "collected_at": "2026-01-01T00:00:00Z"}
        self.node = "topology/pod-1/node-101"
        self.dn = self.node + "/sys/phys-[eth1/1]"
        self.physical = [[{"l1PhysIf": {"attributes": {"dn": self.dn, "id": "eth1/1", "adminSt": "up"}}}]]
        self.oper = [[{"ethpmPhysIf": {"attributes": {"dn": self.dn + "/phys", "operSt": "up"}}}]]

    def adapt(self, identities=None):
        return adapt_interfaces(self.meta, self.physical, self.oper, "lab", identities if identities is not None else {self.node: "asset001"})

    def test_native_pages_produce_valid_ingestion(self):
        result = self.adapt()[0]
        self.assertEqual(result["source"]["external_device_id"], "asset001")
        self.assertEqual(result["completeness"], "partial")
        entry = normalize("interface", result["payload"])[0]
        self.assertEqual(entry["operational_state"], "up")
        self.assertEqual(entry["addresses"], [])

    def test_unknown_identity_and_duplicate_are_rejected(self):
        with self.assertRaises(ValueError):
            self.adapt({})
        self.physical[0].append(self.physical[0][0])
        with self.assertRaises(ValueError):
            self.adapt()

    def test_missing_operational_state_is_not_invented(self):
        self.oper = [[]]
        self.assertNotIn("operational_state", self.adapt()[0]["payload"]["entries"][0])

    def test_inventory_preserves_contract_and_unresolved_targets(self):
        contract = "uni/tn-a/brc-web"
        subject = contract + "/subj-http"
        relation = subject + "/rssubjFiltAtt-http"
        classes = {"vzBrCP": [[{"vzBrCP": {"attributes": {"dn": contract, "scope": "context"}}}]],
                   "vzSubj": [[{"vzSubj": {"attributes": {"dn": subject}}}]],
                   "vzRsSubjFiltAtt": [[{"vzRsSubjFiltAtt": {"attributes": {"dn": relation, "tDn": "uni/tn-a/flt-http"}}}]]}
        inventory = translate_inventory(self.meta, classes)
        self.assertEqual(len(inventory["objects"]), 3)
        self.assertIn({"kind": "contains", "source": contract, "target": subject}, inventory["relationships"])
        self.assertEqual(inventory["unresolved"][0]["target"], "uni/tn-a/flt-http")
        self.assertIn("uribv4Route", inventory["missing_classes"])

    def test_invalid_or_duplicate_native_objects_fail(self):
        classes = {"fabricNode": [[{"fabricNode": {"attributes": {"dn": "same"}}},
                                    {"fabricNode": {"attributes": {"dn": "same"}}}]]}
        with self.assertRaises(ValueError):
            translate_inventory(self.meta, classes)

    def test_route_and_contract_evidence_translation(self):
        route = "topology/pod-1/node-101/sys/uribv4/dom-example/db-rt/rt-[192.0.2.0/24]"
        contract = "uni/tn-a/brc-web"
        subject, flt = contract + "/subj-http", "uni/tn-a/flt-http"
        epg = "uni/tn-a/ap-app/epg-client"
        def mo(cls, dn, **attrs):
            return {cls: {"attributes": {"dn": dn, **attrs}}}
        classes = {
            "uribv4Route": [[mo("uribv4Route", route, prefix="192.0.2.0/24")]],
            "uribv4Nexthop": [[mo("uribv4Nexthop", route + "/nh-[1]", addr="192.0.2.1", **{"if": "eth1/1", "vrf": "a"})]],
            "vzBrCP": [[mo("vzBrCP", contract, scope="context")]],
            "vzSubj": [[mo("vzSubj", subject)]],
            "vzFilter": [[mo("vzFilter", flt)]],
            "vzEntry": [[mo("vzEntry", flt + "/e-web", prot="tcp", dFromPort="443", dToPort="443")]],
            "vzRsSubjFiltAtt": [[mo("vzRsSubjFiltAtt", subject + "/rsf-http", tDn=flt, action="permit")]],
            "fvAEPg": [[mo("fvAEPg", epg)]],
            "fvCEp": [[mo("fvCEp", epg + "/cep-test", ip="192.0.2.5")]],
            "fvRsCons": [[mo("fvRsCons", epg + "/rscons-web", tDn=contract)]],
        }
        result = translate_semantics(translate_inventory(self.meta, classes))
        self.assertEqual(result["routes"][0]["next_hops"][0]["address"], "192.0.2.1")
        self.assertEqual(result["contracts"][0]["consumers"], [epg])
        self.assertEqual(result["contracts"][0]["subjects"][0]["filters"][0]["entries"][0]["attributes"]["dFromPort"], "443")
        entry = result["contracts"][0]["subjects"][0]["filters"][0]["entries"][0]
        self.assertEqual(entry["destination_ports"], {"start": 443, "end": 443})
        self.assertEqual(entry["protocol"], "tcp")
        self.assertEqual(result["contracts"][0]["status"], "unverified")

    def test_name_reference_resolves_only_without_shared_ambiguity(self):
        def mo(cls, dn, **attrs):
            return {cls: {"attributes": {"dn": dn, **attrs}}}
        epg = "uni/tn-a/ap-app/epg-client"
        contract = "uni/tn-a/brc-web"
        relation = epg + "/rscons-web"
        classes = {"fvAEPg": [[mo("fvAEPg", epg)]],
                   "fvRsCons": [[mo("fvRsCons", relation, tnVzBrCPName="web")]],
                   "vzBrCP": [[mo("vzBrCP", contract, name="web")]]}
        result = translate_semantics(translate_inventory(self.meta, classes))
        self.assertEqual(result["contracts"][0]["consumers"], [epg])
        classes["vzBrCP"][0].append(mo("vzBrCP", "uni/tn-common/brc-web", name="web"))
        result = translate_semantics(translate_inventory(self.meta, classes))
        self.assertTrue(any("ambiguous" in x["reason"] for x in result["findings"]))
        self.assertTrue(all(not c["consumers"] for c in result["contracts"]))

    def test_epg_bridge_vrf_endpoint_relationships(self):
        def mo(cls, dn, **attrs):
            return {cls: {"attributes": {"dn": dn, **attrs}}}
        bd, vrf = "uni/tn-a/BD-db", "uni/tn-a/ctx-blue"
        epg = "uni/tn-a/ap-app/epg-db"
        endpoint = epg + "/cep-001122334455"
        classes = {
            "fvCtx": [[mo("fvCtx", vrf, name="blue")]],
            "fvBD": [[mo("fvBD", bd, name="db")]],
            "fvRsCtx": [[mo("fvRsCtx", bd + "/rsctx", tnFvCtxName="blue")]],
            "fvSubnet": [[mo("fvSubnet", bd + "/subnet-[10.0.0.1/24]", ip="10.0.0.1/24")]],
            "fvAEPg": [[mo("fvAEPg", epg, name="db")]],
            "fvRsBd": [[mo("fvRsBd", epg + "/rsbd", tnFvBDName="db")]],
            "fvCEp": [[mo("fvCEp", endpoint, mac="00:11:22:33:44:55")]],
            "fvIp": [[mo("fvIp", endpoint + "/ip-[10.0.0.5]", addr="10.0.0.5")]],
            "fvRsCEpToPathEp": [[mo("fvRsCEpToPathEp", endpoint + "/rspath", tDn="topology/pod-1/paths-101/pathep-[eth1/1]")]],
        }
        result = translate_semantics(translate_inventory(self.meta, classes))
        self.assertEqual(result["bridge_domains"][0]["vrf"], vrf)
        self.assertEqual(result["bridge_domains"][0]["subnets"][0]["gateway"], "10.0.0.1/24")
        group = result["endpoint_groups"][0]
        self.assertEqual(group["bridge_domain"], bd)
        self.assertEqual(group["endpoints"][0]["addresses"], ["10.0.0.5"])
        self.assertEqual(group["endpoints"][0]["status"], "observed_unverified")

    def test_fabric_evidence_ingestion_envelope(self):
        inventory = translate_inventory(self.meta, {"l1PhysIf": self.physical})
        submission = fabric_evidence_submission(inventory, "lab", "fabric-a")
        self.assertEqual(submission["data_type"], "topology")
        self.assertEqual(submission["completeness"], "partial")
        self.assertEqual(submission["payload"]["inventory"]["objects"][0]["dn"], self.dn)
        with self.assertRaises(ValueError):
            fabric_evidence_submission(inventory, "lab", "")

    def test_external_epg_contract_and_l3out_mapping(self):
        def mo(cls, dn, **attrs):
            return {cls: {"attributes": {"dn": dn, **attrs}}}
        out, vrf = "uni/tn-a/out-external", "uni/tn-a/ctx-blue"
        ext, node = out + "/instP-remote", out + "/lnodep-leaf"
        contract, subject = "uni/tn-a/brc-web", "uni/tn-a/brc-web/subj-web"
        epg, flt = "uni/tn-a/ap-app/epg-server", "uni/tn-a/flt-web"
        classes = {
            "fvCtx": [[mo("fvCtx", vrf, name="blue")]],
            "l3extOut": [[mo("l3extOut", out, name="external")]],
            "l3extRsEctx": [[mo("l3extRsEctx", out + "/rsectx", tDn=vrf)]],
            "l3extInstP": [[mo("l3extInstP", ext, name="remote")]],
            "l3extSubnet": [[mo("l3extSubnet", ext + "/extsubnet-[203.0.113.0/24]", ip="203.0.113.0/24", scope="import-security")]],
            "l3extLNodeP": [[mo("l3extLNodeP", node)]],
            "l3extRsNodeL3OutAtt": [[mo("l3extRsNodeL3OutAtt", node + "/rsnodeL3OutAtt-[x]", tDn="topology/pod-1/node-101")]],
            "l3extRsCons": [[mo("l3extRsCons", ext + "/rscons-web", tDn=contract)]],
            "fvAEPg": [[mo("fvAEPg", epg)]],
            "fvCEp": [[mo("fvCEp", epg + "/cep-test", ip="192.0.2.5")]],
            "fvRsProv": [[mo("fvRsProv", epg + "/rsprov-web", tDn=contract)]],
            "vzBrCP": [[mo("vzBrCP", contract)]],
            "vzSubj": [[mo("vzSubj", subject)]],
            "vzRsSubjFiltAtt": [[mo("vzRsSubjFiltAtt", subject + "/rsf", tDn=flt, action="permit")]],
            "vzFilter": [[mo("vzFilter", flt)]],
            "vzEntry": [[mo("vzEntry", flt + "/e-web", prot="tcp", dFromPort="443", dToPort="443")]],
        }
        result = translate_semantics(translate_inventory(self.meta, classes))
        external = result["external_networks"][0]
        self.assertEqual(external["vrf"], vrf)
        self.assertEqual(external["external_epgs"][0]["subnets"][0]["prefix"], "203.0.113.0/24")
        self.assertEqual(external["node_profiles"][0]["nodes"][0]["target"], "topology/pod-1/node-101")
        self.assertEqual(result["policy_candidates"][0]["source_epg"], ext)
        self.assertEqual(result["policy_candidates"][0]["destination_epg"], epg)
        self.assertEqual(result["policy_candidates"][0]["consumer_epg"], ext)
        self.assertEqual(result["policy_candidates"][0]["provider_epg"], epg)
        self.assertEqual(result["policy_candidates"][0]["candidate_action"], "allow")
        self.assertEqual(result["policy_candidates"][0]["endpoint_roles"], "contract_roles_not_packet_direction")
        self.assertEqual(result["policy_candidates"][0]["status"], "unverified")
        self.assertIsNone(result["policy_candidates"][0]["provider_subject_label_match"])
        self.assertIn("label matching evidence incomplete", result["policy_candidates"][0]["unresolved"])
        request = normalized_policy_submission(translate_inventory(self.meta, classes), "lab", "fabric-a")
        entry = normalize("policy", request["payload"])[0]
        self.assertEqual(request["completeness"], "partial")
        self.assertEqual(entry["action"], "allow")
        self.assertEqual(entry["selectors"][0]["value"], "203.0.113.0/24")
        self.assertEqual(entry["selectors"][1]["value"], "192.0.2.5/32")
        self.assertEqual(entry["selectors"][2]["value"]["destination_port_start"], 443)
        self.assertEqual(entry["details"]["selector_source"], "aci_observations")
        self.assertEqual(entry["details"]["candidate"]["consumer_epg"], ext)
        from navis_common.policy_selectors import evaluate_policy
        selectors = [*entry["selectors"][:2], {"role": "service", "kind": "service", "negated": False,
                     "value": {"protocol": "tcp", "start": 443, "end": 443}}]
        verdict = evaluate_policy([{**entry, "selectors": selectors, "selectors_complete": False}], "unknown", "203.0.113.10", "192.0.2.5", "tcp", 443, complete=False)
        self.assertEqual(verdict["decision"], "unknown")

    def test_subject_label_comparison(self):
        def mo(cls, dn, **attrs):
            return {cls: {"attributes": {"dn": dn, **attrs}}}
        contract, flt = "uni/tn-a/brc-web", "uni/tn-a/flt-web"
        subject = contract + "/subj-web"
        prov, cons = "uni/tn-a/ap-a/epg-p", "uni/tn-a/ap-a/epg-c"
        rp, rc = prov + "/rsprov-web", cons + "/rscons-web"
        classes = {"vzBrCP": [[mo("vzBrCP", contract)]],
                   "vzSubj": [[mo("vzSubj", subject, provMatchT="All", consMatchT="All")]],
                   "vzFilter": [[mo("vzFilter", flt)]],
                   "vzEntry": [[mo("vzEntry", flt + "/entry", prot="tcp")]],
                   "vzRsSubjFiltAtt": [[mo("vzRsSubjFiltAtt", subject + "/rsf", tDn=flt)]],
                   "fvAEPg": [[mo("fvAEPg", prov), mo("fvAEPg", cons)]],
                   "fvRsProv": [[mo("fvRsProv", rp, tDn=contract, matchT="All")]],
                   "fvRsCons": [[mo("fvRsCons", rc, tDn=contract)]],
                   "vzProvLbl": [[]], "vzConsLbl": [[]], "vzException": [[]],
                   "vzProvSubjLbl": [[mo("vzProvSubjLbl", subject + "/ps", name="p"), mo("vzProvSubjLbl", rp + "/ps", name="p")]],
                   "vzConsSubjLbl": [[mo("vzConsSubjLbl", subject + "/cs", name="c"), mo("vzConsSubjLbl", rc + "/cs", name="c")]]}
        candidate = translate_semantics(translate_inventory(self.meta, classes))["policy_candidates"][0]
        self.assertTrue(candidate["epg_label_match"])
        self.assertTrue(candidate["provider_subject_label_match"])
        self.assertTrue(candidate["consumer_subject_label_match"])
        self.assertEqual(candidate["status"], "unverified")
        self.assertIsNone(candidate["candidate_action"])
        self.assertIn("filter action unresolved", candidate["unresolved"])

    def test_directional_contract_and_route_context(self):
        def mo(cls, dn, **attrs):
            return {cls: {"attributes": {"dn": dn, **attrs}}}
        contract = "uni/tn-a/brc-web"
        subject = contract + "/subj-web"
        term, flt = subject + "/intmnl", "uni/tn-a/flt-web"
        route = "topology/pod-1/node-101/sys/uribv6/dom-vrf/rt-[2001:db8::/64]"
        classes = {"vzBrCP": [[mo("vzBrCP", contract)]],
                   "vzSubj": [[mo("vzSubj", subject, revFltPorts="yes")]],
                   "vzInTerm": [[mo("vzInTerm", term)]],
                   "vzRsFiltAtt": [[mo("vzRsFiltAtt", term + "/rsf", tDn=flt, priorityOverride="level1")]],
                   "vzFilter": [[mo("vzFilter", flt)]],
                   "vzEntry": [[mo("vzEntry", flt + "/e-web", prot="tcp")]],
                   "uribv6Route": [[mo("uribv6Route", route, prefix="2001:db8::/64")]],
                   "uribv6Nexthop": [[mo("uribv6Nexthop", route + "/nh-1", addr="2001:db8::1", vrf="blue")]]}
        result = translate_semantics(translate_inventory(self.meta, classes))
        filt = result["contracts"][0]["subjects"][0]["filters"][0]
        self.assertEqual(filt["direction"], "vzInTerm")
        self.assertEqual(filt["priority_override"], "level1")
        self.assertEqual(result["routes"][0]["node"], "topology/pod-1/node-101")
        self.assertEqual(result["routes"][0]["next_hops"][0]["vrf"], "blue")
