import unittest
from navis_common.trace import expand_flows


class TraceExpansionTests(unittest.TestCase):
    def test_expands_and_deduplicates(self):
        flows = expand_flows("10.0.0.1, 10.0.0.2;10.0.0.1", "10.1.0.1;10.1.0.2", "TCP", 443)
        self.assertEqual(len(flows), 4)
        self.assertEqual((flows[0].source, flows[0].destination, flows[0].protocol), ("10.0.0.1", "10.1.0.1", "tcp"))

    def test_rejects_bad_input_and_excessive_expansion(self):
        for args in [("10.0.0.1,", "10.0.0.2", "tcp", 443), ("bad", "10.0.0.2", "tcp", 443), ("10.0.0.1", "10.0.0.2", "icmp", 443)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                expand_flows(*args)
        with self.assertRaises(ValueError):
            expand_flows("10.0.0.1,10.0.0.2", "10.0.0.3,10.0.0.4", "tcp", max_flows=3)


if __name__ == "__main__":
    unittest.main()
