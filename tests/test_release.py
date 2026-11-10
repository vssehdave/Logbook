"""Versions that must move together: the package and the Claude Code plugin that ships in the same repository."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestVersionsAgree(unittest.TestCase):
    @unittest.skipUnless((ROOT / "pyproject.toml").exists() and (ROOT / ".claude-plugin" / "plugin.json").exists(), "not a source checkout")
    def test_the_plugin_has_the_package_version(self):
        """Claude Code updates a plugin only when its version changes, so a fix to the plugin that keeps the old version never reaches anyone who has it installed."""
        package = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))["version"]
        self.assertEqual(plugin, package, "bump .claude-plugin/plugin.json together with pyproject.toml")


if __name__ == "__main__":
    unittest.main()
