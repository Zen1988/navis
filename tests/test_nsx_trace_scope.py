import unittest
from unittest.mock import Mock, patch

from navis_api.trace_postgres import PostgresTraceProcessor
from navis_common.nat import Packet


class NsxTraceScopeTests(unittest.TestCase):
    def evaluate(self, ingress=None, egress=None, direction="OUT"):
        cursor = Mock()
        condition = {"vif_external_id": "vif-1", "direction": direction, "ip_protocol": "IPV4", "complete": True}
        cursor.fetchall.side_effect = [
            [("set", "unknown", "nsx-dfw:manager:vm:vif-1", "snapshot", "stateful", {}, True)],
            [("rule", "allow", "allow", True, {"selectors_complete": True, "workload_condition": condition})],
            [(role, False, True, None, None, None, None, None, None, None, None, None)
             for role in ("source", "destination", "service")],
        ]
        with patch.object(PostgresTraceProcessor, "_zone_memberships", return_value={}):
            return PostgresTraceProcessor._policies(cursor, "build", "vm-asset",
                Packet("192.0.2.5", "198.51.100.1", "tcp", 443, 50000), ingress, egress)[0]

    def test_selected_egress_nic_establishes_outbound_scope(self):
        self.assertEqual(self.evaluate(egress="vif-1")["decision"], "allow")
        self.assertEqual(self.evaluate(egress="vif-2")["decision"], "unknown")
        self.assertEqual(self.evaluate()["decision"], "unknown")

    def test_inbound_nic_does_not_match_outbound_rule(self):
        self.assertEqual(self.evaluate(ingress="vif-1")["decision"], "unknown")
        self.assertEqual(self.evaluate(ingress="vif-1", direction="IN")["decision"], "allow")
        self.assertEqual(self.evaluate(ingress="vif-1", egress="vif-1", direction="IN_OUT")["decision"], "unknown")
