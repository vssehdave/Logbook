"""A command run at a terminal in a clone that is not set up offers setup once; a hook or script only gets a hint and nothing is written."""
from __future__ import annotations

import io
import unittest
from unittest import mock

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from getlogbook import cli, install  # noqa: E402


class Terminal(io.StringIO):
    def isatty(self):
        return True


class TestFirstRun(T.CliRepo):
    def at_terminal(self, answer):
        return mock.patch("sys.stdin", Terminal(answer)), mock.patch.object(cli, "_interactive", lambda: True)

    def hooks(self):
        return install.git_hook_installed(self.r, "post-commit")

    def test_a_script_or_a_hook_is_never_asked_anything_and_nothing_is_written(self):
        code, text = self.run_cli("status")
        self.assertEqual(code, 0, text)
        self.assertNotIn("not set up", text)
        self.assertFalse(self.hooks())
        self.assertFalse(self.r.cfg().get("setup_declined"))

    def test_a_person_at_a_terminal_is_offered_setup_and_a_yes_applies_it(self):
        a, b = self.at_terminal("y\n")
        with a, b:
            code, text = self.run_cli("status")
        self.assertIn("not set up in this clone", text)
        self.assertTrue(self.hooks())
        self.assertIn("you:", text, "the command the person ran still ran")

    def test_a_no_is_remembered_and_the_command_still_runs(self):
        a, b = self.at_terminal("n\n")
        with a, b:
            _, text = self.run_cli("status")
        self.assertFalse(self.hooks())
        self.assertTrue(self.r.cfg().get("setup_declined"))
        self.assertIn("not be asked again", text)
        self.assertIn("you:", text)
        a, b = self.at_terminal("y\n")
        with a, b:
            _, again = self.run_cli("status")
        self.assertNotIn("not set up", again, "never asked twice")
        self.assertFalse(self.hooks())

    def test_taking_it_out_on_purpose_means_do_not_ask_again(self):
        self.run_cli("setup", "--yes", "--agent", "agents-md")
        self.assertTrue(self.hooks())
        self.run_cli("uninstall", "--yes", "--agent", "agents-md")
        self.assertFalse(self.hooks())
        self.assertTrue(self.r.cfg().get("setup_declined"))


if __name__ == "__main__":
    unittest.main()
