"""One-command setup and removal (project scope): git hook, agent hooks, the skill, and the always-on rules block.

Everything it edits is backed up first, written atomically (through a symlink to its target), and removed again by
`uninstall`. Existing files are only ever changed between our own markers, or by merging our hook entries.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from importlib import resources
from pathlib import Path

from . import capture, sync
from . import git as g
from .store import atomic_write

TARGETS = ("claude-code", "agents-md", "copilot", "gemini", "cursor")
BEGIN, END = "<!-- logbook:start -->", "<!-- logbook:end -->"
CURSOR_HEAD = "---\ndescription: Logbook shared repo memory\nalwaysApply: true\n---\n"
SKILL_MARK = "managed-by: logbook"


def asset(name):
    return resources.files("getlogbook").joinpath("agent", name).read_text(encoding="utf-8")


def detect(root):
    """Agents this repo already shows signs of; Claude Code if there is no sign of any."""
    root = Path(root)
    found = []
    if (root / ".claude").exists() or (root / "CLAUDE.md").exists():
        found.append("claude-code")
    if (root / "AGENTS.md").exists():
        found.append("agents-md")
    if (root / ".github" / "copilot-instructions.md").exists():
        found.append("copilot")
    if (root / "GEMINI.md").exists():
        found.append("gemini")
    if (root / ".cursor").exists():
        found.append("cursor")
    return found or ["claude-code"]


# ---- text helpers -------------------------------------------------------------------------------------------
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


def backup(repo, path):
    path = Path(path)
    if path.exists():
        d = repo.cdir / "backups"
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, d / f"{time.strftime('%Y%m%d-%H%M%S')}-{path.name}.bak")


def write_through(repo, path, text, newline="\n"):
    """Back up, then atomically write. A symlinked file is written at its target, so the link survives."""
    real = Path(os.path.realpath(path))
    backup(repo, real)
    if not text:
        real.unlink(missing_ok=True)
        return
    atomic_write(real, text.replace("\n", newline) if newline != "\n" else text)


# ---- the plan -----------------------------------------------------------------------------------------------
class Step:
    def __init__(self, label, path, old, new, newline="\n", skill=False, agent=False):
        self.label, self.path, self.old, self.new, self.newline, self.skill, self.agent = label, Path(path), old, new, newline, skill, agent

    @property
    def verb(self):
        if self.old == self.new:
            return "unchanged"
        return "remove" if not self.new else "create" if not self.old else "update"

    def apply(self, repo):
        if self.verb != "unchanged":
            write_through(repo, self.path, self.new, self.newline)
            if self.skill and self.new:
                (self.path.parent / ".logbook-version").write_text(_version(), encoding="utf-8")
            if self.agent and not self.new and self.path.parent.exists() and not any(self.path.parent.iterdir()):
                self.path.parent.rmdir()  # the agents folder, only if we made it and left it empty
            if self.skill and not self.new:
                (self.path.parent / ".logbook-version").unlink(missing_ok=True)
                for folder in (self.path.parent, self.path.parent.parent, self.path.parent.parent.parent):
                    if folder.exists() and not any(folder.iterdir()):  # only folders we made and left empty
                        folder.rmdir()
                    else:
                        break


def _version():
    try:
        from importlib.metadata import version
        return version("getlogbook")
    except Exception:
        return "unknown"


def _block_step(root, rel, remove, label, repo_cfg=None):
    path = Path(root) / rel
    old, nl = read_text(path)
    new = without_block(old) if remove else with_block(old, asset("rules.md"))
    return Step(label, path, old, new, nl)


def plan(repo, targets, remove=False, pretool=True):
    """Steps in the order they are applied; the skill is last so a half-finished install never leaves a dangling skill."""
    root = repo.root
    steps = []
    for t in targets:
        if t == "claude-code":
            sp = root / ".claude" / "settings.local.json"
            old, nl = read_text(sp)
            _, cur = capture.install_claude(repo, sp, pretool=pretool, write=False, remove=remove)
            new = json.dumps(cur, indent=2) + "\n" if cur else ""
            steps.append(Step("agent hooks (SessionStart, UserPromptSubmit, Stop, ...)", sp, old, new, nl))
            steps.append(_block_step(root, "CLAUDE.md", remove, "always-on rules in CLAUDE.md"))
            kp = root / ".claude" / "skills" / "logbook" / "SKILL.md"
            kold, knl = read_text(kp)
            knew = "" if remove else asset("skill.md")
            if kold and SKILL_MARK not in kold:  # someone else's file of the same name: never overwrite or delete it
                if not remove:
                    raise SystemExit(f"logbook: {kp} exists and is not managed by logbook; move it aside first")
                knew = kold
            steps.append(Step("the logbook skill", kp, kold, knew, knl, skill=True))
            ap = root / ".claude" / "agents" / "logbook-scribe.md"
            aold, anl = read_text(ap)
            if aold and SKILL_MARK in aold:  # 0.0.5 pre-releases installed a scribe agent; it is gone, so setup and uninstall remove ours (never someone else's)
                steps.append(Step("remove the old logbook-scribe agent", ap, aold, "", anl, agent=True))
        elif t == "agents-md":
            steps.append(_block_step(root, "AGENTS.md", remove, "always-on rules in AGENTS.md"))
        elif t == "copilot":
            steps.append(_block_step(root, ".github/copilot-instructions.md", remove, "always-on rules in copilot-instructions.md"))
        elif t == "gemini":
            steps.append(_block_step(root, "GEMINI.md", remove, "always-on rules in GEMINI.md"))
        elif t == "cursor":
            cp = root / ".cursor" / "rules" / "logbook.mdc"
            old, nl = read_text(cp)
            new = "" if remove else CURSOR_HEAD + BEGIN + "\n" + asset("rules.md").strip() + "\n" + END + "\n"
            steps.append(Step("Cursor rule", cp, old, new, nl))
    return steps


def git_hook_installed(repo, name="post-commit"):
    try:
        f = capture._hooks_dir(repo) / name
        return f.exists() and capture.MARK_BEGIN in f.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False


def describe(repo, targets, remove=False, pretool=True):
    """Lines that say what would change."""
    lines = []
    for name, what in (("post-commit", "git post-commit hook (records commits)"),
                       ("pre-push", "git pre-push hook (a reminder of unshared notes; never blocks)"),
                       ("post-merge", "git post-merge hook (a pull also fetches shared logs; never pushes)")):
        hook = git_hook_installed(repo, name)
        verb = ("remove" if hook else "unchanged") if remove else ("unchanged" if hook else "create")
        lines.append(f"  {verb:<10} {what}")
    for s in plan(repo, targets, remove, pretool):
        rel = os.path.relpath(s.path, repo.root)
        lines.append(f"  {s.verb:<10} {rel}  ({s.label})")
    return lines


def apply(repo, targets, remove=False, pretool=True):
    steps = plan(repo, targets, remove, pretool)
    if remove:
        capture.uninstall_git_hook(repo)
        capture.uninstall_pre_push_hook(repo)
        capture.uninstall_pull_hooks(repo)
    else:
        capture.install_git_hook(repo)
        capture.install_pre_push_hook(repo)
        capture.install_pull_hooks(repo)
        if "origin" in sync.remotes(repo):  # so a plain `git pull` also brings teammates' notes
            sync.ensure_fetch_config(repo)
    for s in steps:
        s.apply(repo)
    return steps


def status(repo):
    """{target: 'installed' | 'partial' | 'missing'} for the doctor."""
    out = {}
    for t in TARGETS:
        try:
            done = [s.verb == "unchanged" for s in plan(repo, [t], remove=False)]
        except SystemExit:
            out[t] = "conflict"
            continue
        out[t] = "installed" if all(done) else "partial" if any(done) else "missing"
    return out
