import unittest
from uuid import UUID

from navis_common import Action, AddressRange, DeviceEvidence, PolicyRule, evaluate_rules, mac_addresses_equal, match_device, normalize_mac, parse_address_selector


class AddressTests(unittest.TestCase):
    def test_policy_prefix_is_independent_of_interface_mask(self):
        selector = parse_address_selector("172.20.0.1/24")
        self.assertTrue(selector.contains("172.20.0.2"))
        self.assertFalse(selector.contains("172.20.1.2"))

    def test_range_and_ip_versions(self):
        selector = parse_address_selector("10.0.0.2 - 10.0.0.5")
        self.assertTrue(selector.contains("10.0.0.5"))
        self.assertFalse(selector.contains("::1"))
        with self.assertRaises(ValueError):
            parse_address_selector("10.0.0.5-10.0.0.2")

    def test_ipv6_prefix(self):
        self.assertTrue(parse_address_selector("2001:db8::1/64").contains("2001:db8::2"))


class MacTests(unittest.TestCase):
    def test_equivalent_formats_and_distinct_addresses(self):
        for value in ("AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "aabbccddeeff"):
            self.assertEqual(normalize_mac(value), "aa:bb:cc:dd:ee:ff")
            self.assertTrue(mac_addresses_equal(value, "aa:bb:cc:dd:ee:ff"))
        self.assertFalse(mac_addresses_equal("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:fe"))

    def test_rejects_invalid_or_partial_addresses(self):
        for value in ("aa:bb:cc:dd:ee", "aa:bb-cc:dd:ee:ff", "aabb.ccdd.eezz", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_mac(value)


class DeviceTests(unittest.TestCase):
    def test_identity_and_ambiguous_metadata(self):
        first, second = UUID(int=1), UUID(int=2)
        devices = [DeviceEvidence(first, frozenset({("cmdb", "42")}), "router", "edge", frozenset({"10.0.0.1"})),
                   DeviceEvidence(second, frozenset(), "router", "edge", frozenset({"10.0.0.1"}))]
        args = dict(platform="router", display_name="edge", addresses=frozenset({"10.0.0.1"}), devices=devices)
        self.assertEqual(match_device(namespace="cmdb", external_id="42", **args).device_id, first)
        result = match_device(namespace=None, external_id=None, **args)
        self.assertEqual((result.status, result.device_id, result.candidates), ("review", None, (first, second)))
        self.assertTrue(result.requires_confirmation)

    def test_conflicting_mappings_never_auto_merge(self):
        devices = [DeviceEvidence(UUID(int=i), frozenset({("cmdb", "42")})) for i in (1, 2)]
        result = match_device(namespace="cmdb", external_id="42", platform=None, display_name=None, addresses=frozenset(), devices=devices)
        self.assertEqual(result.status, "ambiguous")
        self.assertIsNone(result.device_id)
        self.assertTrue(result.requires_confirmation)


class PolicyTests(unittest.TestCase):
    def test_first_match_and_default(self):
        any_source = parse_address_selector("0.0.0.0/0")
        destination = parse_address_selector("172.20.0.1/24")
        rules = [PolicyRule("deny-1", any_source, destination, "tcp", 443, Action.DENY),
                 PolicyRule("allow-2", any_source, destination, "tcp", 443, Action.ALLOW)]
        result = evaluate_rules(rules, source="10.0.0.1", destination="172.20.0.2", protocol="TCP", destination_port=443, default=Action.UNKNOWN)
        self.assertEqual((result.action, result.rule_id), (Action.DENY, "deny-1"))
        result = evaluate_rules(rules, source="10.0.0.1", destination="172.20.1.2", protocol="tcp", destination_port=443, default=Action.UNKNOWN)
        self.assertEqual((result.action, result.rule_id), (Action.UNKNOWN, None))

    def test_invalid_input_even_without_rules(self):
        with self.assertRaises(ValueError):
            evaluate_rules([], source="bad", destination="10.0.0.1", protocol="tcp", destination_port=443, default=Action.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
