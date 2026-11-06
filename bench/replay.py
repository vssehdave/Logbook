"""Replay recorded Claude Code sessions through Logbook's real hooks, to see which logs and notes they would have produced.

    python bench/replay.py --source <repo> --sessions <folder of session .jsonl files> --work <empty scratch folder> [--fake] [--limit N] [--only id,id]

What it does, in a clone of <repo> so the real repository and its branches are never touched:
  * the clone's remote is a local bare repository, so nothing can be pushed anywhere;
  * every recorded session is turned into the hook calls it would have made (SessionStart, UserPromptSubmit per prompt, PostToolUse per tool use, Stop per turn,
    SessionEnd) and all sessions are fed in the order they happened;
  * the branch each line was recorded on is checked out in the clone at the newest commit the repository had at that time, and the git post-commit and post-merge
    hooks are called when it moves, so savepoints and publishing see commits the way they did;
  * detached processes (the observer pass, savepoint, tidy, publish) run at once in this process, like tests/test_day.py;
  * the model is the real `claude` unless --fake (a stub that answers one observation per batch, to check the plumbing).
It writes <work>/report.json and prints a summary. Dates in the result are replay time, not the recorded time.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
os.environ.pop("CLAUDE_CODE_SESSION_ID", None)  # the replay's notes are not "agent-written" because it is run from inside an agent
os.environ.pop("CLAUDECODE", None)

from getlogbook import capture, cli, hookmain, running, tidy, tree, worker  # noqa: E402
from getlogbook.store import Repo  # noqa: E402


def sh(*args, cwd, check=True):
    p = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and p.returncode:
        raise SystemExit(f"{' '.join(args)}: {p.stderr.strip()[:300]}")
    return p.stdout.strip()


def epoch(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


# ---- sessions -> hook calls ----------------------------------------------------------------------------------------------------
def session_events(path):
    """[(epoch, branch, event name, payload)] for one recorded session, in order. Sidechains (subagents) are skipped."""
    sid, evs, pending, last_text, open_turn, started, branch = path.stem, [], {}, "", False, False, ""

    def stop(ts):
        nonlocal open_turn
        if open_turn:
            evs.append((ts, branch, "Stop", {"last_assistant_message": last_text}))
            open_turn = False

    ts = 0.0
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not d.get("timestamp") or d.get("isSidechain"):
            continue
        ts, branch = epoch(d["timestamp"]), d.get("gitBranch") or branch
        content = (d.get("message") or {}).get("content")
        if d.get("type") == "user" and not d.get("isMeta"):
            if isinstance(content, str):
                stop(ts)
                if not started:
                    evs.append((ts, branch, "SessionStart", {}))
                    started = True
                evs.append((ts, branch, "UserPromptSubmit", {"prompt": content}))
                open_turn, last_text = True, ""
            elif isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("tool_use_id") in pending:
                        use = pending.pop(b["tool_use_id"])
                        evs.append((ts, branch, "PostToolUseFailure" if b.get("is_error") else "PostToolUse",
                                    {"tool_name": use["name"], "tool_input": use.get("input") or {}, "tool_response": b.get("content")}))
        elif d.get("type") == "assistant" and isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    pending[b["id"]] = b
                elif isinstance(b, dict) and b.get("type") == "text" and b.get("text", "").strip():
                    last_text = b["text"]
    stop(ts)
    if started:
        evs.append((ts, branch, "SessionEnd", {}))
    return [(t, b, e, {**p, "session_id": sid}) for t, b, e, p in evs]


# ---- the clone and its branches -------------------------------------------------------------------------------------------------
class Clone:
    def __init__(self, source, work, email):
        self.path = work / "clone"
        sh("git", "clone", "-q", "--no-hardlinks", str(source), str(self.path), cwd=work)
        sh("git", "config", "user.email", email, cwd=self.path)
        sh("git", "config", "user.name", sh("git", "config", "user.name", cwd=source, check=False) or "replay", cwd=self.path)
        bare = work / "origin.git"
        sh("git", "init", "-q", "--bare", str(bare), cwd=work)
        sh("git", "remote", "set-url", "origin", str(bare), cwd=self.path)  # nothing can reach the real remote from here
        self.lines = {}  # branch -> [(commit time, sha, subject)] oldest first
        self.at = {}  # branch -> sha it is checked out at

    def history(self, branch):
        if branch not in self.lines:
            ref = next((r for r in (f"origin/{branch}", branch, "origin/main", "main") if sh("git", "rev-parse", "--verify", "-q", r, cwd=self.path, check=False)), "main")
            out = sh("git", "log", "--first-parent", "--format=%ct %H %s", ref, cwd=self.path)
            rows = [(int(x.split(" ", 2)[0]), x.split(" ", 2)[1], x.split(" ", 2)[2] if x.count(" ") > 1 else "") for x in out.splitlines()]
            self.lines[branch] = sorted(rows)
        return self.lines[branch]

    def move(self, branch, ts):
        """Check the branch out at the newest commit that existed at `ts`. Returns the subject of the commit it moved to, or None when it did not move."""
        rows = self.history(branch)
        pick = next((r for r in reversed(rows) if r[0] <= ts), rows[0])
        if self.at.get("HEAD") == (branch, pick[1]):
            return None
        first = "HEAD" not in self.at or self.at["HEAD"][0] != branch and branch not in self.at
        sh("git", "checkout", "-q", "-f", "-B", branch, pick[1], cwd=self.path)
        moved = self.at.get(branch) not in (None, pick[1])
        self.at[branch] = pick[1]
        self.at["HEAD"] = (branch, pick[1])
        return pick[2] if moved and not first else None


# ---- the run -----------------------------------------------------------------------------------------------------------------------
def fake_model(prompt, model="haiku"):
    """A stand-in for the model: one observation for the first tool use of a batch, a plain savepoint, nothing for triage. Only to check the plumbing."""
    if "TOOL USES" in prompt:
        tool = prompt.split('tool="', 1)[1].split('"', 1)[0] if 'tool="' in prompt else "Tool"
        return (f"<observation><type>change</type><title>{tool} step {abs(hash(prompt)) % 10000}</title><subtitle>s</subtitle><facts><fact>{tool} ran</fact></facts>"
                f"<narrative>A {tool} step happened in this stretch of the session.</narrative></observation>"), 0.0, ""
    if "<savepoint>" in prompt:
        return "<savepoint><title>A stretch of work</title><completed>Things were done.</completed><learned>Something was learned.</learned></savepoint>", 0.0, ""
    return "NONE", 0.0, ""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--sessions", required=True, type=Path)
    ap.add_argument("--work", required=True, type=Path)
    ap.add_argument("--fake", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="stop after this many hook calls")
    ap.add_argument("--only", default="", help="comma-separated session id prefixes")
    ap.add_argument("--mode", default="auto", choices=["manual", "ask", "auto"])
    a = ap.parse_args(argv)
    a.source, a.sessions, a.work = a.source.resolve(), a.sessions.resolve(), a.work.resolve()
    a.work.mkdir(parents=True, exist_ok=True)
    if any(a.work.iterdir()):
        raise SystemExit(f"{a.work} is not empty")
    email = sh("git", "config", "user.email", cwd=a.source)

    events = []
    for p in sorted(a.sessions.glob("*.jsonl")):
        if a.only and not any(p.stem.startswith(x) for x in a.only.split(",")):
            continue
        events += session_events(p)
    events.sort(key=lambda e: e[0])
    if a.limit:
        events = events[:a.limit]
    print(f"{len(events)} hook calls from {len({e[3]['session_id'] for e in events})} sessions", file=sys.stderr)

    clone = Clone(a.source, a.work, email)
    os.chdir(clone.path)
    repo = Repo(clone.path)
    cfg = repo.init()
    repo.save_cfg({**cfg, "publish": a.mode, "worker_calls": 100000, "display": sh("git", "config", "user.name", cwd=clone.path), "interpreter": sys.executable})
    spawned, errors = [], []

    def spawn(args, cwd):  # a detached process, run at once
        spawned.append(list(args[3:]))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            try:
                cli.main(list(args[3:]))
            except SystemExit:
                pass
            except Exception as ex:  # a failure in one background step must not end the replay
                errors.append(f"{args[3:]}: {ex!r}")

    capture.spawn_detached = spawn
    if a.fake:
        worker.call_model = fake_model
        worker.available = lambda: True

    t0, done = time.time(), 0
    for ts, branch, event, payload in events:
        if branch and branch != "HEAD":
            subject = clone.move(branch, ts)
            if subject is not None:  # the branch moved to a newer commit: the git hooks fire
                hookmain.run(["post-commit"])
                if subject.startswith("Merge "):
                    hookmain.run(["post-merge"])
        out = capture.handle_hook(event, "claude-code", json.dumps({**payload, "cwd": str(clone.path), "hook_event_name": event}))
        done += 1
        if done % 100 == 0:
            print(f"  {done}/{len(events)} hook calls, {int(time.time() - t0)}s, {len(spawned)} background steps, {len(errors)} errors", file=sys.stderr, flush=True)
    for _ in range(3):  # whatever is still queued
        for br in {b for _, b, _, _ in events if b and b != "HEAD"}:
            spawn(["", "", "", "worker", "--drain", "--branch", br, "--flush"], clone.path)
    spawn(["", "", "", "publish", "--all", "--yes", "--no-push"], clone.path)

    entries = repo.load_private()
    shared = repo.load_shared()[0]
    led = worker.ledger(repo)
    report = {"hook_calls": done, "seconds": int(time.time() - t0), "background_steps": len(spawned), "errors": errors[:20],
              "private": {k: sum(1 for e in entries if e.kind == k) for k in ("log", "finding", "change", "summary")},
              "shared": {k: sum(1 for l in shared if l.entry.kind == k) for k in ("finding", "change", "summary", "log")}, "archived": len(list((repo.cdir / "archive").glob("*.json"))), "queue": len(repo.queued()),
              "model_calls": led["calls"], "cost_usd": round(led["cost"], 4), "branches": sorted({e.anchor.get("branch", "") for e in entries}),
              "clone": str(clone.path)}
    (a.work / "report.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
