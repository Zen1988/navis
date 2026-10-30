import unittest
from unittest.mock import Mock, patch

from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.nat import Packet
from navis_common.policy_pipeline import ORIGINAL_ADDRESS_STAGE


class PaloAltoTraceStageTests(unittest.TestCase):
    def nat(self, *, installed=True):
        cursor = Mock()
        cursor.fetchall.side_effect = [
            [("set", ORIGINAL_ADDRESS_STAGE, "paloalto:fw:vsys1", "snapshot", True)],
            [("complete" if installed else "partial", {"table_kind": "installed"})],
            [("rule", "publish", True, {"selectors_complete": True})],
            [("destination", {"address": "10.1.0.10", "port": 8443})],
            [("source", False, True, None, None, None, None, None, None, None, None, None),
             ("destination", False, False, "203.0.113.10/32", None, None, None, None, None, None, None, None),
             ("service", False, False, None, "tcp", 443, 443, 0, 65535, {}, None, None),
             ("source_zone", False, False, None, None, None, None, None, None, None, "source-zone", None),
             ("destination_zone", False, False, None, None, None, None, None, None, None, "destination-zone", None)],
        ]
        cursor.fetchone.side_effect = [("untrust",), ("untrust",)]
        packet = Packet("192.0.2.5", "203.0.113.10", "tcp", 443, 50000)
        with patch.object(PostgresTraceProcessor, "_routes", return_value=[{
                "prefix": "0.0.0.0/0", "route_type": "forward", "interface": "ethernet1/2"}]), \
             patch.object(PostgresTraceProcessor, "_zone_memberships", return_value={"ethernet1/2": ["untrust"]}):
            return PostgresTraceProcessor._nat(cursor, "build", "device", packet, dataset="dataset",
                                                vrf="default", ingress="ethernet1/2")

    def test_database_nat_read_resolves_pre_nat_zones(self):
        translated, evidence = self.nat()
        self.assertEqual(translated.destination, "10.1.0.10")
        self.assertEqual(translated.destination_port, 8443)
        self.assertEqual(evidence[0]["processing_stage"], ORIGINAL_ADDRESS_STAGE)

    def test_partial_rib_is_not_used_as_verified_fib_for_nat_zone(self):
        packet, evidence = self.nat(installed=False)
        self.assertEqual(packet.destination, "203.0.113.10")
        self.assertEqual(evidence[0]["status"], "unknown")

    def test_application_condition_survives_database_policy_read(self):
        condition = {"applications": ["ssl"], "any_application": False, "complete": True,
                     "application_default": True, "default_services": [
                         {"application": "ssl", "protocol": "tcp", "start": 443, "end": 443}]}
        for application, expected in (("ssl", "allow"), ("database", "deny"), (None, "unknown")):
            cursor = Mock()
            cursor.fetchall.side_effect = [
                [("set", "deny", "paloalto:fw:vsys1", "snapshot", "stateful", {}, True)],
                [("rule", "app-rule", "allow", True, {"selectors_complete": True, "application_condition": condition})],
                [(role, False, True, None, None, None, None, None, None, None, None, None)
                 for role in ("source", "destination", "service")],
            ]
            with patch.object(PostgresTraceProcessor, "_zone_memberships", return_value={}):
                result = PostgresTraceProcessor._policies(cursor, "build", "device",
                    Packet("192.0.2.1", "198.51.100.1", "tcp", 443, 50000), application=application)
            self.assertEqual(result[0]["decision"], expected)
