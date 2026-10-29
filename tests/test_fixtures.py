import json
import unittest
from pathlib import Path
from navis_api.normalized_adapter import normalize


class FixtureTests(unittest.TestCase):
    def test_normalized_fixtures(self):
        root = Path(__file__).resolve().parents[1] / "examples" / "ansible" / "fixtures"
        files = sorted(root.glob("normalized-*.json"))
        self.assertEqual(len(files), 6)
        for path in files:
            with self.subTest(path=path.name):
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(data["adapter"]["input_format"], "normalized-json")
                self.assertTrue(normalize(data["data_type"], data["payload"]))
