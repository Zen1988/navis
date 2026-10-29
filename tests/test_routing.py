import unittest
from navis_common.routing import select_routes


class RouteSelectionTests(unittest.TestCase):
    def test_longest_prefix_and_multiple_paths(self):
        routes = [{"prefix": "0.0.0.0/0", "route_type": "forward"},
                  {"prefix": "172.20.0.0/23", "route_type": "forward"},
                  {"prefix": "172.20.1.0/24", "route_type": "forward"},
                  {"prefix": "172.20.1.0/24", "route_type": "forward"}]
        result = select_routes("172.20.1.25", routes, complete=True, table_kind="installed")
        self.assertEqual(len(result["routes"]), 2)
        self.assertTrue(all(route["prefix"] == "172.20.1.0/24" for route in result["routes"]))

    def test_missing_coverage_is_not_no_route(self):
        self.assertEqual(select_routes("10.0.0.1", [], complete=False, table_kind="installed")["status"], "unknown")
        self.assertEqual(select_routes("10.0.0.1", [], complete=True, table_kind="installed")["status"], "no_route")
        self.assertEqual(select_routes("10.0.0.1", [], complete=True, table_kind="candidate")["status"], "unknown")
