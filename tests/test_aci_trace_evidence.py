import unittest
from navis_common.aci_trace_evidence import candidate_evidence


class AciTraceEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.payload = {"kind": "aci_fabric_evidence", "version": 1, "semantics": {
            "endpoint_groups": [{"native_id": "app", "endpoints": [{"addresses": ["192.0.2.5"]}]}],
            "external_networks": [{"external_epgs": [{"native_id": "external", "subnets": [
                {"prefix": "198.51.100.0/24", "scope": "export-rtctrl, import-security"}]}]}],
            "policy_candidates": [{"consumer_epg": "app", "provider_epg": "external", "protocol": "tcp", "candidate_action": "allow"}]}}

    def test_relevant_candidate_is_evidence_not_verdict(self):
        result = candidate_evidence([("snapshot", self.payload)], "192.0.2.5", "198.51.100.3", "tcp", 443)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["candidates"][0]["decision"], "unknown")
        self.assertEqual(result["candidates"][0]["packet_direction"], "unknown")
        self.assertFalse(result["truncated"])

    def test_reverse_is_not_lost_and_unrelated_is_not_included(self):
        reverse = candidate_evidence([("s", self.payload)], "198.51.100.3", "192.0.2.5", "tcp", 443)
        self.assertEqual(len(reverse["candidates"]), 1)
        self.assertEqual(candidate_evidence([("s", self.payload)], "192.0.2.5", "198.51.100.3", "udp", 443)["candidates"], [])

    def test_non_security_prefix_and_malformed_input(self):
        self.payload["semantics"]["external_networks"][0]["external_epgs"][0]["subnets"][0]["scope"] = "export-rtctrl"
        self.assertEqual(candidate_evidence([("s", self.payload)], "192.0.2.5", "198.51.100.3", "tcp", 443)["candidates"], [])
        self.payload["semantics"]["endpoint_groups"] = None
        self.assertEqual(candidate_evidence([("s", self.payload)], "192.0.2.5", "198.51.100.3", "tcp", 443)["candidates"], [])

    def test_translated_direction_is_used_instead_of_assuming_both_directions(self):
        semantics = self.payload["semantics"]
        semantics["directional_rules"] = [{**semantics["policy_candidates"][0],
            "packet_direction": "consumer_to_provider", "destination_ports": {"start": 443, "end": 443}}]
        forward = candidate_evidence([("s", self.payload)], "192.0.2.5", "198.51.100.3", "tcp", 443)
        self.assertEqual(forward["candidates"][0]["packet_direction"], "consumer_to_provider")
        self.assertEqual(candidate_evidence([("s", self.payload)], "198.51.100.3", "192.0.2.5", "tcp", 443)["candidates"], [])
        self.assertEqual(candidate_evidence([("s", self.payload)], "192.0.2.5", "198.51.100.3", "tcp", 22)["candidates"], [])
