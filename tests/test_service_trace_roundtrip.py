import unittest
from unittest.mock import Mock, patch

from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.nat import Packet


class ServiceTraceRoundtripTests(unittest.TestCase):
    def trace(self, source_port, details):
        cursor = Mock()
        # Database projections: rule set, rule, then typed selectors. Coverage
        # is complete here to expose lost constraints as a false allow.
        cursor.fetchall.side_effect = [
            [("set", "deny", "aci-fabric:a", "snapshot", "stateless", {}, True)],
            [("rule", "https-return", "allow", True, {"selectors_complete": True})],
            [("source", False, True, None, None, None, None, None, None, None, None, None),
             ("destination", False, True, None, None, None, None, None, None, None, None, None),
             ("service", False, False, None, "tcp", 1024, 65535, None, None, 443, 443, details)],
        ]
        with patch.object(PostgresTraceProcessor, "_zone_memberships", return_value={}):
            return PostgresTraceProcessor._policies(cursor, "build", "device",
                Packet("10.0.0.6", "10.0.0.5", "tcp", 50000, source_port))[0]

    def test_database_source_port_condition_survives_read(self):
        self.assertEqual(self.trace(443, {})["decision"], "allow")
        self.assertEqual(self.trace(444, {})["decision"], "deny")
        self.assertEqual(self.trace(None, {})["decision"], "unknown")

    def test_tcp_flags_are_not_dropped_when_packet_flags_are_unavailable(self):
        result = self.trace(443, {"tcp_flags_all": ["ack"]})
        self.assertEqual(result["decision"], "unknown")
        self.assertEqual(result["statefulness"], "stateless")
