"""setup looks at the coding agents installed on the machine, with their versions, and not only at files already in the repository."""
from __future__ import annotations

import os
import subprocess
import unittest
from unittest import mock

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from getlogbook import install  # noqa: E402


def fake_run(versions):
    def run(cmd, **kw):
        name = os.path.basename(cmd[0]).split(".")[0]
        if name not in versions:
            raise OSError(name)
        return subprocess.CompletedProcess(cmd, 0, stdout=versions[name] + "\nmore text\n", stderr="")
    return run


def on_path(*names):
    return lambda name: f"/bin/{name}" if name in names else None


class TestInstalledAgents(T.CliRepo):
    def online(self):
        env = {k: v for k, v in os.environ.items() if k != "LOGBOOK_OFFLINE"}
        return mock.patch.dict(os.environ, env, clear=True)

    def test_each_agent_on_the_path_is_found_with_its_version(self):
        with self.online(), mock.patch("shutil.which", on_path("claude", "codex")), mock.patch("subprocess.run", fake_run({"claude": "2.1.322 (Claude Code)", "codex": "codex-cli 0.9"})):
            found = install.installed_agents()
        self.assertEqual(found, {"claude-code": ("claude", "2.1.322 (Claude Code)"), "agents-md": ("codex", "codex-cli 0.9")})

    def test_an_agent_that_will_not_say_its_version_is_still_found(self):
        with self.online(), mock.patch("shutil.which", on_path("gemini")), mock.patch("subprocess.run", fake_run({})):
            self.assertEqual(install.installed_agents(), {"gemini": ("gemini", "version unknown")})

    def test_offline_looks_at_nothing(self):
        with mock.patch("shutil.which", on_path("claude")):
            self.assertEqual(install.installed_agents(), {})

    def test_detect_adds_what_is_installed_to_what_the_repo_shows_and_falls_back_to_claude_code(self):
        with mock.patch.object(install, "installed_agents", lambda: {"agents-md": ("codex", "1"), "gemini": ("gemini", "1")}):
            self.assertEqual(install.detect(self.d), ["claude-code", "agents-md", "gemini"] if (self.d / "CLAUDE.md").exists() else ["agents-md", "gemini"])
        with mock.patch.object(install, "installed_agents", lambda: {}):
            self.assertEqual(install.detect(self.d), ["claude-code"])

    def test_setup_says_what_it_found_and_when_claude_code_cannot_take_the_plugin(self):
        with mock.patch.object(install, "installed_agents", lambda: {"claude-code": ("claude", "1.0.3 (Claude Code)")}), mock.patch.object(install, "plugin_state", lambda: "unavailable"):
            code, text = self.run_cli("setup", "--yes", "--agent", "claude-code")
        self.assertEqual(code, 0, text)
        self.assertIn("coding agents found on this machine: claude-code (1.0.3 (Claude Code))", text)
        self.assertIn("cannot install plugins", text)


if __name__ == "__main__":
    unittest.main()
