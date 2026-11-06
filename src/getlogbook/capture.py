"""Capture: the hook entry point and the git hook installers.

Design rules:
  * A hook queues a small record or starts a detached process. No model, no network, < 100 ms.
  * A hook never fails the agent: everything is caught, logged to errors.log, exit code 0.
  * Nothing is written for a session or a commit by itself: the observer records what happened and `logbook log` saves it.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import git as g
from .entry import BODY_FIELDS, LEVELS, Entry, from_json, new_id
from .store import Repo, atomic_write

MARK_BEGIN, MARK_END = "# >>> logbook >>>", "# <<< logbook <<<"
CLAUDE_EVENTS = ["SessionStart", "UserPromptSubmit", "Stop", "PreCompact", "SessionEnd"]


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ---- entries made by people/agents ---------------------------------------------------------------------------
def writer():
    """Who is writing a note: "agent-written" from inside an agent's session, else "user-written". Claude Code puts its session id in the
    environment of the commands it runs, which a person in their own terminal does not have. LOGBOOK_WRITER=agent|user says it outright (another
    agent, or a person running a command through an agent).  shortcut: only Claude Code is recognised by itself; others set LOGBOOK_WRITER."""
    forced = os.environ.get("LOGBOOK_WRITER", "").strip().lower()
    if forced in ("agent", "user"):
        return "agent-written" if forced == "agent" else "user-written"
    return "agent-written" if os.environ.get("CLAUDE_CODE_SESSION_ID") else "user-written"


def make_entry(repo, kind, topic, body, paths=None, provenance=None, via="cli", supersedes=(), sha=None, level="", sources=(), checks=None, status=None):
    from . import tree
    body = {k: str(v)[:2000] for k, v in body.items() if k in BODY_FIELDS and v}
    e = Entry(id=new_id(), kind=kind, topic=topic[:200], body=body, provenance=provenance or writer(), captured_via=via,
              supersedes=list(supersedes), created=now(), level=level if level in LEVELS else "", sources=list(sources), v=2, checks=checks, status=status,
              display=repo.cfg().get("display", "") if repo.attribution() == "named" else "")
    e.anchor = tree.anchor_for(repo, sha=sha, paths=paths, with_base=True)  # sha: note about an earlier commit
    repo.add_private(e)
    return e


# ---- locks and detached processes ---------------------------------------------------------------------------------
@contextlib.contextmanager
def _lock(path, timeout=1.0, stale=10):
    """Tiny cross-platform lock (O_EXCL file, taken over once it is `stale` seconds old). Yields False if it could not be taken in `timeout` seconds.
    A holder that works for longer than `stale` (a model call) must pass a larger value, or a second process takes the lock over while it still runs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    end, fd = time.time() + timeout, None
    while time.time() < end:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > stale:
                    path.unlink()
            except OSError:
                pass
            time.sleep(0.02)
    try:
        yield fd is not None
    finally:
        if fd is not None:
            os.close(fd)
            try:
                path.unlink()
            except OSError:
                pass


def spawn_detached(args, cwd):
    if os.environ.get("LOGBOOK_NO_SPAWN"):  # tests
        return
    kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, cwd=str(cwd))
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        try:  # escape the agent's job object if allowed, otherwise fall back
            subprocess.Popen(args, creationflags=flags | 0x01000000, **kw)  # CREATE_BREAKAWAY_FROM_JOB
        except OSError:
            subprocess.Popen(args, creationflags=flags, **kw)
    else:
        subprocess.Popen(args, start_new_session=True, **kw)


def _observe(repo, cfg, flush, end=False):
    """Start an observer pass for the current branch if its queue holds anything. A flush also takes a batch too small to be worth a call by itself.
    In auto mode a savepoint (`logbook log`, which observes first) starts instead when a commit follows enough new observations, or when the session ends."""
    from . import observer, running, savepoint, worker
    if not (worker.is_on(cfg) and worker.available()):
        return
    branch, head = running.branch_now(repo)
    run = running.Running(repo, branch)
    if repo.publish_mode() == "auto" and branch != "HEAD" and (savepoint.due(repo, branch, head) or (end and (savepoint.own(run) or run.pending_bytes()))):
        spawn_detached([cfg.get("interpreter") or sys.executable, "-m", "getlogbook", "log", "--quiet"], repo.root)
    elif run.pending_bytes() > 0:
        observer.spawn_pass(repo, branch, flush=flush)


def handle_hook(event, agent, raw):
    """Entry point for `logbook capture`. Returns text for stdout (may be ''). Never raises."""
    repo = None
    if os.environ.get("LOGBOOK_WORKER"):  # the worker's own claude run: nothing Logbook does may react to it
        return ""
    try:
        payload = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
        repo = Repo(payload.get("cwd") or ".")
        cfg = repo.cfg()
        if not cfg.get("user"):
            return ""
        out = ""
        if event == "Permission":  # PreToolUse on Bash: allow, ask or deny a logbook command from the publish mode; no opinion on anything else
            from . import permissions
            ti = payload.get("tool_input")
            return permissions.hook_output(str(ti.get("command", "")) if isinstance(ti, dict) else "", repo.publish_mode())
        if event in ("PostToolUse", "PostToolUseFailure"):  # queue the tool use for the observer: no model, no git process
            from . import observer
            observer.on_tool_use(repo, payload)
            return ""
        if event in ("UserPromptSubmit", "Stop"):  # what the person typed and the agent's final reply: the conversation behind the next log
            from . import convo
            convo.record(repo, event, payload)
        if event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
            from . import recall  # only the prompt-time hooks need retrieval; Stop/SessionEnd stay lean
            from . import worker as worker_mod
            files = []
            ti = payload.get("tool_input")
            if event == "PreToolUse" and isinstance(ti, dict) and ti.get("file_path"):
                try:
                    files = [Path(ti["file_path"]).resolve().relative_to(repo.root.resolve()).as_posix()]
                except (ValueError, OSError):
                    files = []
            sid = str(payload.get("session_id", ""))
            text = recall.digest(repo, event, payload.get("prompt", ""), files, sid)
            if event == "SessionStart":  # merged branches whose logs are still private: the agent (not the observer) publishes them
                from . import branches
                text = "\n".join(x for x in (text, branches.reminder(repo, repo.publish_mode())) if x)
            note = worker_mod.pause_notice(repo) if event in ("SessionStart", "UserPromptSubmit") and worker_mod.enabled(repo) else None
            out = recall.hook_json(event, "\n".join(x for x in (text, note[1] if note else "") if x), note[0] if note else "")
        if event in ("Stop", "SessionEnd"):  # prompt-time hooks stay read-only and fast
            _observe(repo, cfg, flush=event == "SessionEnd", end=event == "SessionEnd")
            if event == "Stop":
                from . import savepoint
                out = savepoint.ask_block(repo, payload)
        if event == "SessionStart":
            _observe(repo, cfg, flush=True)  # tool uses a crashed session left in the queue
        return out
    except Exception as ex:  # a hook must never break the agent
        try:
            (repo.error if repo else (lambda m: None))(f"capture {event}: {ex!r}")
        except Exception:
            pass
        return ""


def _sid(sid):
    return "".join(c for c in sid if c.isalnum() or c in "-_")[:80] or "nosession"


# ---- installers ---------------------------------------------------------------------------------------------
def _py(repo):
    return (repo.cfg().get("interpreter") or sys.executable).replace("\\", "/")


def _hooks_dir(repo):
    return Path(g.run(["rev-parse", "--path-format=absolute", "--git-path", "hooks"], repo.root).strip())


def _strip_hook_block(f):
    """Remove our marked block from a hook file; delete the file if nothing but the shebang is left."""
    if not (f.exists() and MARK_BEGIN in f.read_text(encoding="utf-8")):
        return
    t = f.read_text(encoding="utf-8")
    a, _, rest = t.partition(MARK_BEGIN)
    _, _, b = rest.partition(MARK_END)
    left = (a + b.lstrip("\n")).rstrip("\n") + "\n"
    if left.strip() in ("", "#!/bin/sh"):
        f.unlink()
    else:
        f.write_text(left, encoding="utf-8", newline="\n")


def uninstall_git_hook(repo):
    f = _hooks_dir(repo) / "post-commit"
    _strip_hook_block(f)
    return f


def install_pre_push_hook(repo):
    """A reminder on stderr of notes that are still private, or published but not pushed. It never blocks a push and never shares
    anything: `logbook publish` and `logbook sync` are the only ways notes leave this clone."""
    hooks = _hooks_dir(repo)
    hooks.mkdir(parents=True, exist_ok=True)
    f = hooks / "pre-push"
    block = f'{MARK_BEGIN}\n"{_py(repo)}" -m getlogbook queue --hook >&2 || true\n{MARK_END}\n'
    _strip_hook_block(f)  # replace the 0.0.3 block, which also pushed notes, rather than keep it
    text = f.read_text(encoding="utf-8") if f.exists() else "#!/bin/sh\n"
    f.write_text(text.rstrip("\n") + "\n" + block, encoding="utf-8", newline="\n")  # chain, never overwrite
    with contextlib.suppress(OSError):
        f.chmod(f.stat().st_mode | 0o111)
    return f


def uninstall_pre_push_hook(repo):
    f = _hooks_dir(repo) / "pre-push"
    _strip_hook_block(f)
    return f


PULL_HOOKS = ("post-merge", "post-rewrite")  # what `git pull` runs after a merge or a rebase


def install_pull_hooks(repo):
    """After a pull, fetch the shared logs in the background (a pull-only sync: it never pushes). Chained after any hook already there."""
    for name in PULL_HOOKS:
        f = _hooks_dir(repo) / name
        f.parent.mkdir(parents=True, exist_ok=True)
        _strip_hook_block(f)
        text = f.read_text(encoding="utf-8") if f.exists() else "#!/bin/sh\n"
        block = f'{MARK_BEGIN}\n"{_py(repo)}" -m getlogbook post-merge >/dev/null 2>&1 || true\n{MARK_END}\n'
        f.write_text(text.rstrip("\n") + "\n" + block, encoding="utf-8", newline="\n")
        with contextlib.suppress(OSError):
            f.chmod(f.stat().st_mode | 0o111)


def uninstall_pull_hooks(repo):
    for name in PULL_HOOKS:
        _strip_hook_block(_hooks_dir(repo) / name)


def claude_snippet(repo, pretool=False):
    py = _py(repo)
    mk = lambda ev: [{"hooks": [{"type": "command", "command": f'"{py}" -m getlogbook capture --event {ev} --agent claude-code'}]}]
    hooks = {ev: mk(ev) for ev in CLAUDE_EVENTS}
    hooks["PreToolUse"] = [{"matcher": "Bash", **mk("Permission")[0]}]
    for ev in ("PostToolUse", "PostToolUseFailure"):  # every tool use goes to the observer's queue; async so the agent never waits for it
        hooks[ev] = [{"matcher": "*", "hooks": [{**mk(ev)[0]["hooks"][0], "async": True}]}]
    if pretool:
        hooks["PreToolUse"].append({"matcher": "Read|Edit|Write|MultiEdit", **mk("PreToolUse")[0]})
    return {"hooks": hooks}


# 0.0.4 wrote these allow rules into settings.local.json. Permissions now come from the PreToolUse hook (permissions.py), so install removes
# them again: a leftover rule would let a command through without the hook's say.
OLD_ALLOW = ("Bash(logbook note:*)", "Bash(logbook ask:*)", "Bash(logbook context:*)", "Bash(logbook cites:*)", "Bash(logbook log:*)",
         "Bash(logbook status:*)", "Bash(logbook summarize:*)", "Bash(logbook backfill:*)")


def install_claude(repo, path=None, pretool=False, write=False, remove=False):
    path = Path(path or repo.root / ".claude" / "settings.local.json")  # local: it holds a machine-specific interpreter path
    try:
        cur = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError:
        raise SystemExit(f"logbook: {path} is not valid JSON; refusing to touch it")
    hooks = cur.setdefault("hooks", {})
    snippet = claude_snippet(repo, pretool)["hooks"]
    for ev, entries in list(hooks.items()):  # always drop our previous entries so install is idempotent
        keep = [e for e in entries if "getlogbook capture" not in json.dumps(e)]
        if keep:
            hooks[ev] = keep
        else:
            del hooks[ev]
    if not remove:
        for ev, entries in snippet.items():
            hooks.setdefault(ev, []).extend(entries)
    if not hooks:
        cur.pop("hooks")
    perms = cur.setdefault("permissions", {})
    allow = perms.get("allow", [])
    if isinstance(allow, list):  # the allow list is the person's own: only our old exact entries are touched
        allow = [x for x in allow if x not in OLD_ALLOW]
        if allow:
            perms["allow"] = allow
        else:
            perms.pop("allow", None)
    if not perms:
        cur.pop("permissions")
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, json.dumps(cur, indent=2))
    return path, cur
