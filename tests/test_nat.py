import unittest
from navis_common.nat import Packet, evaluate_nat, reverse_session_packet


class NatTests(unittest.TestCase):
    def test_destination_translation(self):
        packet = Packet("192.0.2.1", "198.51.100.10", "tcp", 443)
        rule = {"rule_id": "nat-1", "selectors_complete": True, "kind": "destination",
                "translation": {"address": "10.10.1.10", "port": 8443},
                "selectors": [{"role": "source", "kind": "any"},
                              {"role": "destination", "kind": "address", "value": "198.51.100.10/32"},
                              {"role": "service", "kind": "service", "value": {"protocol": "tcp", "start": 443, "end": 443}}]}
        result, evidence = evaluate_nat([rule], packet, complete=True)
        self.assertEqual((result.destination, result.destination_port, evidence["rule_id"]), ("10.10.1.10", 8443, "nat-1"))
        self.assertEqual(packet.destination, "198.51.100.10")
        rule["selectors_complete"] = False
        self.assertEqual(evaluate_nat([rule], packet, complete=True)[1]["status"], "unknown")

    def test_missing_coverage_is_unknown(self):
        self.assertEqual(evaluate_nat([], Packet("192.0.2.1", "198.51.100.10", "tcp", 443), complete=False)[1]["status"], "unknown")

    def test_combined_translation_uses_original_match(self):
        packet = Packet("192.0.2.1", "198.51.100.10", "tcp", 443)
        rule = {"rule_id": "both", "selectors_complete": True, "kind": "combined",
                "translation": {"source": {"address": "192.0.2.9"}, "destination": {"address": "10.0.0.5"}},
                "selectors": [{"role": "source", "kind": "address", "value": "192.0.2.1/32"},
                              {"role": "destination", "kind": "any"}, {"role": "service", "kind": "any"}]}
        result, evidence = evaluate_nat([rule], packet, complete=True)
        self.assertEqual((result.source, result.destination, evidence["status"]), ("192.0.2.9", "10.0.0.5", "translated"))

    def test_reverse_session_reverses_addresses_and_ports(self):
        original = Packet("192.0.2.1", "198.51.100.10", "tcp", 443, 50000)
        translated = Packet("192.0.2.9", "10.0.0.5", "tcp", 8443, 60000)
        translated_reply, original_reply = reverse_session_packet(original, translated)
        self.assertEqual((translated_reply.source, translated_reply.destination, translated_reply.source_port, translated_reply.destination_port), ("10.0.0.5", "192.0.2.9", 8443, 60000))
        self.assertEqual((original_reply.source, original_reply.destination, original_reply.source_port, original_reply.destination_port), ("198.51.100.10", "192.0.2.1", 443, 50000))
