import unittest

from navis_api.normalized_adapter import normalize, validate_selectors
from navis_common.aci_adapter import translate_inventory, translate_semantics, normalized_policy_submission
from navis_common.policy_selectors import evaluate_rule, evaluate_policy


class AciDirectionTranslationTests(unittest.TestCase):
    def inventory(self, *, reverse="yes", stateful="yes", flags="unspecified", terminal=None):
        def mo(cls, dn, **attrs):
            return {cls: {"attributes": {"dn": dn, **attrs}}}
        contract, flt = "uni/tn-a/brc-https", "uni/tn-a/flt-https"
        subject = contract + "/subj-https"
        client, server = "uni/tn-a/ap-app/epg-client", "uni/tn-a/ap-app/epg-server"
        attrs = {} if reverse is None else {"revFltPorts": reverse}
        classes = {
            "fvAEPg": [[mo("fvAEPg", client), mo("fvAEPg", server)]],
            "fvCEp": [[mo("fvCEp", client + "/cep-c", ip="10.0.0.5"),
                       mo("fvCEp", server + "/cep-s", ip="10.0.0.6")]],
            "fvRsCons": [[mo("fvRsCons", client + "/rscons", tDn=contract)]],
            "fvRsProv": [[mo("fvRsProv", server + "/rsprov", tDn=contract)]],
            "vzBrCP": [[mo("vzBrCP", contract, scope="context")]],
            "vzSubj": [[mo("vzSubj", subject, **attrs)]],
            "vzFilter": [[mo("vzFilter", flt)]],
            "vzEntry": [[mo("vzEntry", flt + "/e-https", etherT="ip", prot="tcp",
                            sFromPort="1024", sToPort="65535", dFromPort="443", dToPort="443",
                            tcpRules=flags, stateful=stateful)]],
        }
        if terminal:
            term = subject + ("/intmnl" if terminal == "vzInTerm" else "/outtmnl")
            classes[terminal] = [[mo(terminal, term)]]
            classes["vzRsFiltAtt"] = [[mo("vzRsFiltAtt", term + "/rsf", tDn=flt, action="deny")]]
        else:
            classes["vzRsSubjFiltAtt"] = [[mo("vzRsSubjFiltAtt", subject + "/rsf", tDn=flt, action="permit")]]
        return translate_inventory({"fabric_id": "fabric-a", "collected_at": "2026-10-30T00:00:00Z"}, classes)

    def rules(self, **kwargs):
        inventory = self.inventory(**kwargs)
        entries = normalize("policy", normalized_policy_submission(inventory, "lab", "fabric-a")["payload"])
        return {e["details"]["candidate"]["packet_direction"]: e for e in entries}

    def test_bidirectional_port_swap_and_stateless_ack_condition(self):
        rules = self.rules()
        self.assertEqual(set(rules), {"consumer_to_provider", "provider_to_consumer"})
        forward, reverse = rules["consumer_to_provider"], rules["provider_to_consumer"]
        self.assertNotEqual(forward["rule_id"], reverse["rule_id"])
        for entry in rules.values():
            self.assertEqual(entry["details"]["statefulness"], "stateless")
            self.assertFalse(entry["details"]["selectors_complete"])
        self.assertTrue(evaluate_rule(forward["selectors"], "10.0.0.5", "10.0.0.6", "tcp", 443, source_port=50000, tcp_flags=["syn"]))
        selectors = reverse["selectors"]
        self.assertTrue(evaluate_rule(selectors, "10.0.0.6", "10.0.0.5", "tcp", 50000, source_port=443, tcp_flags=["syn", "ack"]))
        self.assertFalse(evaluate_rule(selectors, "10.0.0.6", "10.0.0.5", "tcp", 50000, source_port=443, tcp_flags=["syn"]))
        self.assertFalse(evaluate_rule(selectors, "10.0.0.6", "10.0.0.5", "tcp", 50000, source_port=444, tcp_flags=["ack"]))
        self.assertIsNone(evaluate_rule(selectors, "10.0.0.6", "10.0.0.5", "tcp", 50000, source_port=443))
        self.assertIsNone(evaluate_rule(selectors, "10.0.0.6", "10.0.0.5", "tcp", 50000, tcp_flags=["ack"]))
        verdict = evaluate_policy([{**reverse, "selectors_complete": False}], "unknown", "10.0.0.6", "10.0.0.5", "tcp", 50000,
                                  source_port=443, tcp_flags=["ack"], complete=False)
        self.assertEqual(verdict["decision"], "unknown")

    def test_no_port_swap_and_no_ack_requirement(self):
        reverse = self.rules(reverse="no", stateful="no")["provider_to_consumer"]
        self.assertTrue(evaluate_rule(reverse["selectors"], "10.0.0.6", "10.0.0.5", "tcp", 443, source_port=50000, tcp_flags=["syn"]))
        self.assertFalse(evaluate_rule(reverse["selectors"], "10.0.0.6", "10.0.0.5", "tcp", 50000, source_port=443))

    def test_separate_terminals_do_not_generate_implicit_reverse_or_swap(self):
        for terminal, direction in (("vzInTerm", "consumer_to_provider"), ("vzOutTerm", "provider_to_consumer")):
            with self.subTest(terminal=terminal):
                rules = self.rules(terminal=terminal, stateful="no")
                self.assertEqual(set(rules), {direction})
                entry = rules[direction]
                self.assertEqual(entry["action"], "deny")
                service = next(s["value"] for s in entry["selectors"] if s["kind"] == "service")
                self.assertEqual(service["destination_port_start"], 443)
                self.assertEqual(service["source_port_start"], 1024)

    def test_missing_reverse_setting_does_not_invent_service(self):
        reverse = self.rules(reverse=None)["provider_to_consumer"]
        self.assertFalse(any(s["kind"] == "service" for s in reverse["selectors"]))
        self.assertIn("reverse filter port setting unresolved", reverse["details"]["candidate"]["unresolved"])

    def test_explicit_established_flags_are_preserved(self):
        forward = self.rules(flags="est", stateful="no")["consumer_to_provider"]
        self.assertTrue(evaluate_rule(forward["selectors"], "10.0.0.5", "10.0.0.6", "tcp", 443, source_port=50000, tcp_flags=["rst"]))
        self.assertFalse(evaluate_rule(forward["selectors"], "10.0.0.5", "10.0.0.6", "tcp", 443, source_port=50000, tcp_flags=["syn"]))

    def test_service_validation_rejects_incomplete_or_invalid_conditions(self):
        base = {"protocol": "tcp", "destination_port_start": 443, "destination_port_end": 443}
        for extra in ({"source_port_start": 1}, {"source_port_start": 100, "source_port_end": 99},
                      {"tcp_flags_all": ["bogus"]}, {"protocol": "udp", "tcp_flags_all": ["ack"]}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                validate_selectors([{"role": "service", "kind": "service", "value": {**base, **extra}, "negated": False}])

    def test_explicit_any_ports_and_zero_are_canonicalized(self):
        inventory = self.inventory()
        entry = next(o for o in inventory["objects"] if o["class"] == "vzEntry")
        entry["attributes"].update(sFromPort="unspecified", sToPort="unspecified", dFromPort="0", dToPort="0")
        candidate = translate_semantics(inventory)["directional_rules"][0]
        self.assertEqual(candidate["source_ports"], {"start": 0, "end": 65535})
        self.assertEqual(candidate["destination_ports"], {"start": 0, "end": 65535})


if __name__ == "__main__":
    unittest.main()
