import unittest
from navis_common.routing import resolve_recursive, resolve_recursive_alternatives


class RecursiveRoutingTests(unittest.TestCase):
    def test_recursive_resolution_and_loop(self):
        routes = {"192.0.2.1": [{"prefix": "192.0.2.1/32", "route_type": "forward", "next_hop": "192.0.2.2"}],
                  "192.0.2.2": [{"prefix": "192.0.2.2/32", "route_type": "connected", "interface": "eth0"}]}
        lookup = lambda ip: (routes[ip], True, "installed")
        self.assertEqual(resolve_recursive("192.0.2.1", lookup)["interface"], "eth0")
        routes["192.0.2.2"][0] = {"prefix": "192.0.2.2/32", "route_type": "forward", "next_hop": "192.0.2.1"}
        self.assertEqual(resolve_recursive("192.0.2.1", lookup)["reason"], "recursive next-hop loop")

    def test_multiple_recursive_results(self):
        routes = [{"prefix": "192.0.2.0/24", "route_type": "forward", "interface": "a"},
                  {"prefix": "192.0.2.0/24", "route_type": "forward", "interface": "b"}]
        result = resolve_recursive_alternatives("192.0.2.1", lambda _: (routes, True, "installed"))
        self.assertEqual({item["interface"] for item in result["paths"]}, {"a", "b"})
