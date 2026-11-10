"""One-command setup and removal (project scope): git hook, agent hooks, the skill, and the always-on rules block.

Everything it edits is backed up first, written atomically (through a symlink to its target), and removed again by
`uninstall`. Existing files are only ever changed between our own markers, or by merging our hook entries.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from importlib import resources
from pathlib import Path

from . import capture, sync
from . import git as g
from .store import atomic_write

BEGIN, END = "<!-- logbook:start -->", "<!-- logbook:end -->"
SKILL_MARK = "managed-by: logbook"


def asset(name):
    return resources.files("getlogbook").joinpath("agent", name).read_text(encoding="utf-8")


def with_block(text, block):
    wrapped = f"{BEGIN}\n{block.strip()}\n{END}"
    if BEGIN in text and END in text[text.index(BEGIN):]:
        a = text.index(BEGIN)
        b = text.index(END, a) + len(END)
        return text[:a] + wrapped + text[b:]
    return (text.rstrip("\n") + "\n\n" if text.strip() else "") + wrapped + "\n"


def without_block(text):
    if BEGIN not in text or END not in text[text.index(BEGIN):]:
        return text
    a = text.index(BEGIN)
    b = text.index(END, a) + len(END)
    out = text[:a].rstrip("\n") + "\n" + text[b:].lstrip("\n")
    return out if out.strip() else ""


def read_text(path):
    """(text with LF newlines, newline style used on disk). Missing file: ('', LF)."""
    path = Path(path)
    if not path.exists():
        return "", "\n"
    raw = path.read_bytes().decode("utf-8", "replace")
    return raw.replace("\r\n", "\n"), ("\r\n" if "\r\n" in raw else "\n")


def backup(folder, path):
    path = Path(path)
    if path.exists():
        d = Path(folder)
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, d / f"{time.strftime('%Y%m%d-%H%M%S')}-{path.name}.bak")


def write_through(backups, path, text, newline="\n"):
    """Back up (into the folder `backups`), then atomically write. A symlinked file is written at its target, so the link survives."""
    real = Path(os.path.realpath(path))
    backup(backups, real)
    if not text:
        real.unlink(missing_ok=True)
        return
    atomic_write(real, text.replace("\n", newline) if newline != "\n" else text)


# ---- the plan -----------------------------------------------------------------------------------------------
class Step:
    def __init__(self, label, path, old, new, newline="\n", skill=False):
        self.label, self.path, self.old, self.new, self.newline, self.skill = label, Path(path), old, new, newline, skill

    @property
    def verb(self):
        if self.old == self.new:
            return "unchanged"
        return "remove" if not self.new else "create" if not self.old else "update"

    def apply(self, backups):
        if self.verb != "unchanged":
            write_through(backups, self.path, self.new, self.newline)
            if self.skill and self.new:
                (self.path.parent / ".logbook-version").write_text(_version(), encoding="utf-8")
            if self.skill and not self.new:
                (self.path.parent / ".logbook-version").unlink(missing_ok=True)
                for folder in (self.path.parent, self.path.parent.parent):
                    if folder.exists() and not any(folder.iterdir()):  # only folders we made and left empty
                        folder.rmdir()
                    else:
                        break


PLUGIN, MARKETPLACE = "logbook@logbook", "vssehdave/Logbook"


def _claude(*args, timeout=120):
    try:
        p = subprocess.run(["claude", *args], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return p.returncode, p.stdout


def claude_version():
    """The installed Claude Code's version line; '' when there is no `claude` command (or LOGBOOK_OFFLINE is set)."""
    if os.environ.get("LOGBOOK_OFFLINE") or not shutil.which("claude"):
        return ""
    rc, out = _claude("--version", timeout=15)
    lines = out.strip().splitlines()
    return lines[0][:40] if rc == 0 and lines else "version unknown"


def git_version():
    """(major, minor) of the installed git, or None when there is none."""
    try:
        p = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"(\d+)\.(\d+)", p.stdout)
    return (int(m.group(1)), int(m.group(2))) if m else None


def plugin_state():
    """'installed'; 'outdated' (a different version than this package); 'missing'; or 'unavailable' (no `claude` command, one too old to have plugins, or LOGBOOK_OFFLINE)."""
    if os.environ.get("LOGBOOK_OFFLINE") or not shutil.which("claude"):
        return "unavailable"
    rc, listed = _claude("plugin", "list", "--json", timeout=30)
    if rc != 0:
        return "unavailable"
    try:
        mine = [p for p in json.loads(listed) if isinstance(p, dict) and p.get("id") == PLUGIN]
    except ValueError:
        mine = [{}] if PLUGIN in listed else []
    if not mine:
        return "missing"
    have, want = str(mine[0].get("version") or ""), _version()
    return "outdated" if have and want != "unknown" and have != want else "installed"


def plugin_install():
    """Add the marketplace (a repeat is harmless), then install the plugin, or update it when it is another version. True when it is current afterwards."""
    state = plugin_state()
    _claude("plugin", "marketplace", "add", MARKETPLACE)
    if state == "outdated":
        _claude("plugin", "marketplace", "update", "logbook")
        _claude("plugin", "update", PLUGIN)
    else:
        _claude("plugin", "install", PLUGIN)
    return plugin_state() == "installed"


def _version():
    try:
        from importlib.metadata import version
        return version("getlogbook")
    except Exception:
        return "unknown"


def _block_step(root, rel, remove, label):
    path = Path(root) / rel
    old, nl = read_text(path)
    new = without_block(old) if remove else with_block(old, asset("rules.md"))
    return Step(label, path, old, new, nl)


def claude_home():
    """The folder Claude Code reads the person's own settings from: CLAUDE_CONFIG_DIR, else ~/.claude."""
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def wiring(remove=False, pretool=True):
    """The Claude Code side, written once into the person's Claude folder so it holds for every repository: the hooks, the always-on rules and the skill. The hooks do
    nothing in a repository that has not been set up. The skill is last so a half-finished install never leaves a dangling skill."""
    home = claude_home()
    sp = home / "settings.json"
    old, nl = read_text(sp)
    _, cur = capture.install_claude(sp, pretool=pretool, write=False, remove=remove)
    new = json.dumps(cur, indent=2) + "\n" if cur else ""
    steps = [Step("agent hooks (SessionStart, UserPromptSubmit, Stop, ...)", sp, old, new, nl),
             _block_step(home, "CLAUDE.md", remove, "always-on rules in CLAUDE.md")]
    kp = home / "skills" / "logbook" / "SKILL.md"
    kold, knl = read_text(kp)
    knew = "" if remove else asset("skill.md")
    if kold and SKILL_MARK not in kold:  # someone else's file of the same name: never overwrite or delete it
        if not remove:
            raise SystemExit(f"logbook: {kp} exists and is not managed by logbook; move it aside first")
        knew = kold
    steps.append(Step("the logbook skill", kp, kold, knew, knl, skill=True))
    return steps


def apply_wiring(steps):
    backups = claude_home() / "logbook-backups"
    for s in steps:
        s.apply(backups)


def wiring_state():
    """'installed', 'partial', 'missing' (or 'conflict' when a skill of someone else's is in the way) for the Claude wiring."""
    try:
        done = [s.verb == "unchanged" for s in wiring()]
    except SystemExit:
        return "conflict"
    return "installed" if all(done) else "partial" if any(done) else "missing"


def git_hook_installed(repo, name="post-commit"):
    try:
        f = capture._hooks_dir(repo) / name
        return f.exists() and capture.MARK_BEGIN in f.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False


GIT_HOOKS = (("post-commit", "git post-commit hook (saves a log after each commit in ask and auto mode)"),
             ("pre-push", "git pre-push hook (a reminder of unshared notes; never blocks)"),
             ("post-merge", "git post-merge hook (a pull also fetches shared logs; never pushes)"))


def describe_repo(repo, remove=False):
    """Lines that say what `setup` (or `uninstall --repo`) changes in this repository: its git hooks."""
    lines = []
    for name, what in GIT_HOOKS:
        hook = git_hook_installed(repo, name)
        verb = ("remove" if hook else "unchanged") if remove else ("unchanged" if hook else "create")
        lines.append(f"  {verb:<10} {what}")
    return lines


def apply_repo(repo, remove=False):
    if remove:
        capture.uninstall_git_hook(repo)
        capture.uninstall_pre_push_hook(repo)
        capture.uninstall_pull_hooks(repo)
    else:
        capture.install_commit_hook(repo)
        capture.install_pre_push_hook(repo)
        capture.install_pull_hooks(repo)
        if "origin" in sync.remotes(repo):  # so a plain `git pull` also brings teammates' notes
            sync.ensure_fetch_config(repo)
