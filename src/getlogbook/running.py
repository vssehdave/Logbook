"""The running log: what the observer has collected on one branch since the last savepoint, and the queue of tool events still waiting to be observed.

Plain files under `.git/logbook/running/<branch>/`, private, never shared:

    queue.jsonl         one line per tool use, appended by a hook (no model, no git process)
    cursor              how many bytes of the queue the observer has already read
    observations.jsonl  what the observer wrote down: one JSON object per line

A branch that has no running log yet starts from the main line's: its observations are copied once, and keep the branch they were made on, so a savepoint on the new
branch can tell its own observations from the inherited ones.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time

from .store import atomic_write

MAX_INPUT = 600  # characters of a tool's input kept in the queue
MAX_OUTPUT = 1200  # characters of its output
QUEUE_LIMIT = 2_000_000  # bytes: a queue nobody reads (the observer is off) stops growing here
SKIP_TOOLS = frozenset(("Skill", "TodoWrite", "ToolSearch", "ExitPlanMode", "EnterPlanMode"))
_OWN = re.compile(r"^\s*(?:\S*[\\/])?(?:get)?logbook(?:\.exe)?\b", re.I)  # a Logbook command in the shell: not something to remember


def slug(branch):
    """A folder name for a branch: readable, and different for `feature/x` and `feature_x`."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", branch)[:60] + "-" + hashlib.sha1(branch.encode("utf-8")).hexdigest()[:6]


def branch_now(repo):
    """(branch, HEAD sha) read from the files in .git with no process, so a hook can afford it. ('HEAD', sha) when detached."""
    gitdir = repo.root / ".git"
    try:
        if gitdir.is_file():  # a linked worktree: .git is a pointer to its own git dir
            m = re.match(r"gitdir:\s*(.+)", gitdir.read_text(encoding="utf-8").strip())
            gitdir = (repo.root / m.group(1).strip()) if m else gitdir
        head = (gitdir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return "HEAD", ""
    if not head.startswith("ref: "):
        for d in ("rebase-merge", "rebase-apply"):  # mid-rebase HEAD is detached: the branch being rebased is named in the state folder
            try:
                name = (gitdir / d / "head-name").read_text(encoding="utf-8").strip()
                return (name[len("refs/heads/"):] if name.startswith("refs/heads/") else name), head
            except OSError:
                pass
        return "HEAD", head
    ref = head[5:].strip()
    name = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
    try:
        return name, (repo.common / ref).read_text(encoding="utf-8").strip()
    except OSError:
        pass
    try:  # the branch may exist only in packed-refs
        for line in (repo.common / "packed-refs").read_text(encoding="utf-8").splitlines():
            if line.endswith(" " + ref):
                return name, line.split(" ", 1)[0]
    except OSError:
        pass
    return name, ""


def own(run):
    """The observations made on this run's branch since its last savepoint (those inherited from the parent branch are context, not part of its work)."""
    return [o for o in run.observations() if o.get("branch") == run.branch]


def flatten(resp):
    """A tool's response (a string, or a dict that differs per tool) as plain text."""
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        parts = [flatten(resp[k]) for k in ("stdout", "stderr", "output", "content", "text", "file", "result", "error") if resp.get(k)]
        return "\n".join(p for p in parts if p) or json.dumps(resp)[:MAX_OUTPUT]
    if isinstance(resp, list):
        return "\n".join(flatten(x) for x in resp)
    return "" if resp is None else str(resp)


def event_from_payload(payload, branch, head):
    """The queue line for a PostToolUse payload, or None when it is not worth observing (Logbook's own commands, bookkeeping tools)."""
    name = str(payload.get("tool_name") or "")
    ti = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    if not name or name in SKIP_TOOLS:
        return None
    if name == "Bash" and _OWN.match(str(ti.get("command", ""))):
        return None
    brief = json.dumps(ti, ensure_ascii=False) if ti else ""
    if name == "Bash":
        brief = str(ti.get("command", ""))
    elif ti.get("file_path"):
        brief = str(ti["file_path"]) + (": " + str(ti["new_string"])[:300] if ti.get("new_string") else "")
    return {"t": int(time.time()), "session": str(payload.get("session_id", ""))[:80], "prompt": str(payload.get("prompt_id", ""))[:40],
            "tool": name, "input": brief[:MAX_INPUT], "output": flatten(payload.get("tool_response")).strip()[:MAX_OUTPUT],
            "failed": payload.get("hook_event_name") == "PostToolUseFailure", "cwd": str(payload.get("cwd", ""))[:200], "branch": branch, "head": head}


class Running:
    def __init__(self, repo, branch):
        self.repo, self.branch = repo, branch
        self.dir = repo.cdir / "running" / slug(branch)
        self.queue, self.cursor, self.obs = self.dir / "queue.jsonl", self.dir / "cursor", self.dir / "observations.jsonl"

    # the queue ---------------------------------------------------------------
    def push(self, event):
        """Append one event. One write call on an O_APPEND file, so two sessions on the same branch cannot interleave a line. False when the queue is full."""
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            if self.queue.exists() and self.queue.stat().st_size > QUEUE_LIMIT:
                return False
        except OSError:
            return False
        fd = os.open(self.queue, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
        return True

    def offset(self):
        try:
            return int(self.cursor.read_text(encoding="utf-8").strip() or 0)
        except (OSError, ValueError):
            return 0

    def pending_bytes(self):
        try:
            return max(0, self.queue.stat().st_size - self.offset())
        except OSError:
            return 0

    def take(self, max_events, max_chars):
        """(events, offset after them): up to max_events whole lines past the cursor, stopping before the character budget is spent. At least one event."""
        try:
            with open(self.queue, "rb") as f:
                f.seek(self.offset())
                raw = f.read()
        except OSError:
            return [], self.offset()
        events, used, pos = [], 0, 0
        while pos < len(raw) and len(events) < max_events:
            end = raw.find(b"\n", pos)
            if end < 0:
                break  # a line still being written
            start, line = pos, raw[pos:end]
            pos = end + 1
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            size = len(ev.get("input", "")) + len(ev.get("output", ""))
            if events and used + size > max_chars:
                pos = start  # this one waits for the next batch
                break
            events.append(ev)
            used += size
        return events, self.offset() + pos

    def advance(self, offset):
        self.dir.mkdir(parents=True, exist_ok=True)
        atomic_write(self.cursor, str(offset))

    # the observations ----------------------------------------------------------
    def observations(self):
        out = []
        try:
            for line in self.obs.read_text(encoding="utf-8").splitlines():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
        except OSError:
            pass
        return out

    def add(self, records):
        if records:
            self.dir.mkdir(parents=True, exist_ok=True)
            with open(self.obs, "a", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def archive(self, savepoint_id, records):
        """The observations a savepoint covered, kept readable but out of the running log."""
        if records:
            d = self.dir / "archive"
            d.mkdir(parents=True, exist_ok=True)
            self.rewrite(records, d / f"{savepoint_id}.jsonl")

    def archived(self, savepoint_id):
        try:
            return [json.loads(x) for x in (self.dir / "archive" / f"{savepoint_id}.jsonl").read_text(encoding="utf-8").splitlines() if x.strip()]
        except (OSError, ValueError):
            return []

    def rewrite(self, records, path=None):
        atomic_write(path or self.obs, "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in records))

    def fork_from(self, parent):
        """A branch with no running log yet starts from its parent's observations. Done once, before the first observation is written."""
        if self.obs.exists() or not parent or parent == self.branch:
            return 0
        inherited = Running(self.repo, parent).observations()
        self.add(inherited)
        self.dir.mkdir(parents=True, exist_ok=True)
        if not inherited:
            self.obs.touch()  # so a later pass does not fork again
        return len(inherited)
