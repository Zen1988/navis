import re
from pathlib import Path
import tomllib
import unittest

from navis_common.version import VERSION
from navis_api.main import app


class ReleaseVersionTests(unittest.TestCase):
    def test_package_api_and_default_container_version_share_release(self):
        self.assertRegex(VERSION, r'^\d+\.\d+\.\d+$')
        project = tomllib.loads(Path('pyproject.toml').read_text())
        self.assertEqual(project['tool']['setuptools']['dynamic']['version']['attr'], 'navis_common.version.VERSION')
        self.assertEqual(app.version, VERSION)
        container = Path('Dockerfile').read_text()
        self.assertEqual(re.search(r'^ARG NAVIS_VERSION=(.+)$', container, re.M).group(1), VERSION)


if __name__ == '__main__':
    unittest.main()
