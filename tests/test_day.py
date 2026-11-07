"""A working day, compressed, run through the real hooks and commands.

Two people share an origin. The first works through the day on three branches: sessions of tool uses, commits, the usage allowance filling up and a pause, a branch
merged and published, a pull, tidy, an old log folded. The second pulls and sees what was shared. The model is a fake `claude` placed first on PATH, so the real
subprocess call, its flags, the stream parsing and the quota pause are all exercised without spending anyone's allowance. After each stage the invariants a day of
use must keep are checked: no tool use lost or read twice, no observation duplicated, every log filed under a branch, the call ledger equal to the calls the fake saw,
nothing secret in anything sent to a model or shared, nothing the person's own commits could trip over.

`detached` processes (the observer pass, the savepoint, the tidy pass, the post-merge fetch) are run in-process at the moment the hook would have started them.
Set LOGBOOK_SRC to an installed build's site-packages to run the same day against that build.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from getlogbook import branches, capture, cli, hookmain, observer, recall, running, savepoint, tidy, tree, worker  # noqa: E402
from getlogbook import git as g  # noqa: E402
from getlogbook.store import Repo  # noqa: E402

SECRET = "sk-ant-api03-" + "Z" * 40
EMAIL = "dev.person@corp-example.com"

FAKE_CLAUDE = r'''
import json, os, re, sys
from pathlib import Path
d = Path(os.environ["FAKE_CLAUDE_DIR"])
prompt = sys.stdin.read()
n = (int((d / "calls.txt").read_text()) if (d / "calls.txt").exists() else 0) + 1
(d / "calls.txt").write_text(str(n))
with open(d / "prompts.jsonl", "a", encoding="utf-8") as f:
    f.write(json.dumps(prompt) + "\n")
usage = json.loads((d / "usage.json").read_text())
resets = usage.get("resets", 4102444800)
import time
time.sleep(usage.get("delay", 0))  # a slow model: the real one takes seconds, and a pass holds its lock all that time
if "quiet note-taker" in prompt:
    uses = re.findall(r'<tool_use n="(\d+)" tool="(\w+)"[^>]*>\ninput: ([^\n]*)', prompt)
    work = [u for u in uses if u[1] in ("Edit", "Bash", "Write") and "pytest" not in u[2]]
    if not work:
        text = '<skip reason="routine" />'
    else:
        tool, first = work[0][1], work[0][2][:70]
        text = (f"<observation><type>change</type><title>{tool} step {n}</title><subtitle>call {n}</subtitle><facts><fact>saw {len(uses)} tool uses</fact></facts>"
                f"<narrative>Call {n} saw {len(uses)} tool uses; the first change was: {first}</narrative><concepts><concept>what-changed</concept></concepts>"
                f"<files_read></files_read><files_modified><file>src/mod_{n % 5}.py</file></files_modified></observation>")
elif "You write the savepoint" in prompt:
    seen = len(re.findall(r"^\d+\. \[", prompt, re.M))
    text = (f"<savepoint><title>Work block {n}</title><request>Keep the day's work moving.</request><investigated>src/mod_0.py</investigated>"
            f"<learned>Block {n} covered {seen} observations.</learned><completed>Completed {seen} steps in block {n}.</completed><next_steps>More tomorrow.</next_steps></savepoint>")
elif "You keep a person's private log of coding sessions clean" in prompt:
    blocks = []
    for m in re.finditer(r"^entry (\S+) \(.*?(?=^entry |\Z)", prompt, re.M | re.S):
        if "probe" in m.group(0).lower():
            blocks.append(f"entry: {m.group(1)}\nverdict: junk\nreason: A probe session that left nothing a reader could use.")
    text = "\n---\n".join(blocks) or "NONE"
elif "keep a team's recorded notes true" in prompt:
    blocks = []
    for m in re.finditer(r"^note (\S+): .*?(?=^note |\Z)", prompt, re.M | re.S):
        later = re.search(r"later commit (\w+):", m.group(0))
        if later:
            blocks.append(f"status_of: {m.group(1)}\nstatus: resolved\ncommits: {later.group(1)}\nreason: A later commit reworked the files this note is about.")
            break
    text = "\n---\n".join(blocks) or "NONE"
else:
    text = "ok"
events = [{"type": "system", "subtype": "init"}]
if not usage.get("silent"):
    events.append({"type": "rate_limit_event", "rate_limit_info": {"status": "allowed", "rateLimitType": "five_hour", "utilization": usage["five_hour"], "resetsAt": resets,
                   "unifiedWindows": {"five_hour": {"utilization": usage["five_hour"], "resetsAt": resets}, "seven_day": {"utilization": usage.get("seven_day", 0.3), "resetsAt": resets + 86400}}}})
events.append({"type": "result", "is_error": False, "result": text, "total_cost_usd": 0.001})
print("\n".join(json.dumps(e) for e in events))
'''


class TestADay(unittest.TestCase):
    maxDiff = None

    # ---- the world ---------------------------------------------------------------------------------------
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lbday-", ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        root = self.root = Path(self.tmp.name)
        self.fake = root / "fake"
        self.fake.mkdir()
        script = self.fake / "fake_claude.py"
        script.write_text(FAKE_CLAUDE, encoding="utf-8")
        if os.name == "nt":
            (self.fake / "claude.cmd").write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n')
        else:
            exe = self.fake / "claude"
            exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
            exe.chmod(0o755)
        self.usage(0.10)
        env = {"PATH": str(self.fake) + os.pathsep + os.environ["PATH"], "FAKE_CLAUDE_DIR": str(self.fake)}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
        self.cwd0 = os.getcwd()
        self.addCleanup(os.chdir, self.cwd0)
        self.spawned = []
        p2 = mock.patch.object(capture, "spawn_detached", self.spawn)
        p2.start()
        self.addCleanup(p2.stop)
        p3 = mock.patch.object(observer, "MIN_BATCH", 4)  # this day is compressed to a few tool uses per pass; the real minimum (12) is tested on its own
        p3.start()
        self.addCleanup(p3.stop)
        self.rng = random.Random(7)
        self.fed = {}  # (person, branch) -> tool uses the hook should have queued
        self.prompt_outputs = []  # what each UserPromptSubmit hook said back

        origin = root / "origin.git"
        T.sh("git", "init", "-q", "--bare", "-b", "main", str(origin), cwd=root)
        self.A = self.clone("alice", "alice@example.com", origin, seed=True)
        self.B = self.clone("bob", "bob@example.com", origin)
        for d in (self.A, self.B):
            self.assertEqual(self.run_cli(d, "install", "--yes", "--agent", "claude-code")[0], 0)
        for d in (self.A, self.B):  # what setup writes is the person's local setup, not part of the shared work
            (d / ".git" / "info").mkdir(exist_ok=True)
            (d / ".git" / "info" / "exclude").write_text(".claude/\nCLAUDE.md\n", encoding="utf-8")
        for k, v in (("publish", "auto"), ("tidy", "auto"), ("worker_calls", "300")):
            self.run_cli(self.A, "config", k, v)
        self.run_cli(self.B, "config", "publish", "ask")
        self.ra, self.rb = Repo(self.A), Repo(self.B)

    def clone(self, name, email, origin, seed=False):
        d = self.root / name
        if seed:
            d.mkdir()
            T.sh("git", "init", "-q", "-b", "main", cwd=d)
        else:
            T.sh("git", "clone", "-q", "file://" + str(origin).replace("\\", "/"), str(d), cwd=self.root)
        T.sh("git", "config", "user.email", email, cwd=d)
        T.sh("git", "config", "user.name", name.title(), cwd=d)
        if seed:
            T.commit(d, "initial", {f"src/mod_{i}.py": f"VALUE = {i}\n" for i in range(5)} | {"README.md": "# shop\n"})
            T.sh("git", "remote", "add", "origin", "file://" + str(origin).replace("\\", "/"), cwd=d)
            T.sh("git", "push", "-q", "origin", "main", cwd=d)
        return d

    @contextlib.contextmanager
    def at(self, d):
        old = os.getcwd()
        os.chdir(d)
        try:
            yield
        finally:
            os.chdir(old)

    def run_cli(self, d, *args):
        buf = io.StringIO()
        with self.at(d), contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            try:
                code = cli.main(list(args))
            except SystemExit as ex:
                code = ex.code if isinstance(ex.code, int) else 1
        return code or 0, buf.getvalue()

    def spawn(self, args, cwd):
        """Run, at once and in this process, the command a hook would have started as a detached process."""
        self.spawned.append(list(args[3:]))
        self.run_cli(cwd, *args[3:])

    # ---- the fake model's knobs ------------------------------------------------------------------------------
    def usage(self, five, resets=None, **kw):
        (self.fake / "usage.json").write_text(json.dumps({"five_hour": five, "resets": resets or int(time.time()) + 4 * 3600, **kw}))

    def model_calls(self):
        p = self.fake / "calls.txt"
        return int(p.read_text()) if p.exists() else 0

    def prompts(self):
        p = self.fake / "prompts.jsonl"
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()] if p.exists() else []

    # ---- a person at work ---------------------------------------------------------------------------------------
    def hook(self, d, event, sid, **extra):
        return capture.handle_hook(event, "claude-code", json.dumps({"cwd": str(d), "session_id": sid, **extra}))

    def tool(self, d, sid, name, ti, response="ok", failed=False, counts=True):
        out = self.hook(d, "PostToolUseFailure" if failed else "PostToolUse", sid, tool_name=name, tool_input=ti, tool_response=response, hook_event_name="PostToolUse")
        if counts:
            key = (d.name, running.branch_now(Repo(d))[0])
            self.fed[key] = self.fed.get(key, 0) + 1
        return out

    def block(self, d, sid, i, edit=True):
        """One stretch of work: a prompt, a few reads, an edit, a test run, a stop."""
        files = sorted((d / "src").glob("*.py"))
        f = files[i % len(files)].relative_to(d).as_posix()
        self.prompt_outputs.append(self.hook(d, "UserPromptSubmit", sid, prompt=f"keep going on {f}"))
        self.tool(d, sid, "Read", {"file_path": f}, "VALUE = 1\n")
        self.tool(d, sid, "Grep", {"pattern": "VALUE"}, f"{f}:1:VALUE")
        if edit:
            (d / f).write_text(f"VALUE = {i}\n# edit {i} {self.rng.random()}\n")
            self.tool(d, sid, "Edit", {"file_path": f, "old_string": "VALUE", "new_string": f"VALUE_{i}"}, "updated")
        self.tool(d, sid, "Bash", {"command": "python -m pytest -q"}, "1 passed" if i % 4 else "1 failed")
        self.tool(d, sid, "Bash", {"command": f"echo {i} && cat config"}, f"API_KEY={SECRET} owner={EMAIL}" if i % 3 == 0 else "fine")
        self.tool(d, sid, "TodoWrite", {"todos": []}, "ok", counts=False)  # bookkeeping: never queued
        self.tool(d, sid, "Bash", {"command": "logbook status"}, "ok", counts=False)  # Logbook's own command: never queued
        self.hook(d, "Stop", sid)

    def commit(self, d, msg):
        T.sh("git", "add", "-A", cwd=d)
        T.sh("git", "commit", "-q", "-m", msg, cwd=d)
        return T.sh("git", "rev-parse", "HEAD", cwd=d)

    def tidy_up(self, d, msg="wrap up"):
        """What a person does before switching branches: commit what is left."""
        if T.sh("git", "status", "--porcelain", cwd=d):
            self.commit(d, msg)

    def session(self, d, sid, blocks, commit_every=2, start=0):
        self.hook(d, "SessionStart", sid)
        for i in range(start, start + blocks):
            self.block(d, sid, i)
            if (i - start) % commit_every == commit_every - 1:
                self.commit(d, f"work {sid} step {i}")
        self.hook(d, "SessionEnd", sid)
        self.tidy_up(d)

    # ---- what must always be true ---------------------------------------------------------------------------------
    def runs(self, repo):
        base = repo.cdir / "running"
        return [d for d in base.iterdir() if d.is_dir()] if base.exists() else []

    def lines(self, p):
        return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []

    def invariants(self, label, queue_drained=True):
        for who, d, repo in (("alice", self.A, self.ra), ("bob", self.B, self.rb)):
            seen_ids = set()
            for rd in self.runs(repo):
                queue = self.lines(rd / "queue.jsonl")
                cursor = int((rd / "cursor").read_text()) if (rd / "cursor").exists() else 0
                size = (rd / "queue.jsonl").stat().st_size if (rd / "queue.jsonl").exists() else 0
                self.assertLessEqual(cursor, size, f"{label}: {who} {rd.name} cursor beyond the queue")
                if queue_drained:
                    self.assertEqual(cursor, size, f"{label}: {who} {rd.name} left tool uses unobserved")
                branches_in_queue = {q["branch"] for q in queue}
                self.assertEqual(len(branches_in_queue), 1 if queue else 0, f"{label}: a queue holds one branch's tool uses")
                kept = self.lines(rd / "observations.jsonl")
                archived = [o for f in (rd / "archive").glob("*.jsonl") for o in self.lines(f)] if (rd / "archive").exists() else []
                ids = [o["id"] for o in kept + archived]
                self.assertEqual(len(ids), len(set(ids)), f"{label}: {who} {rd.name} has an observation twice")
                hashes = [o["hash"] for o in kept + archived if running.slug(o["branch"]) == rd.name]  # this branch's own; inherited ones repeat the parent's
                self.assertEqual(len(hashes), len(set(hashes)), f"{label}: {who} {rd.name} recorded the same observation twice")
                seen_ids |= set(ids)
            # every log is filed under a branch, and a commit it names is real
            for e in repo.all_entries():
                if e.entry.kind == "log":
                    self.assertTrue(e.entry.anchor.get("branch"), f"{label}: {who} has a log with no branch")
                    sha = e.entry.anchor.get("sha")
                    if sha and e.user == repo.user:  # a teammate's log may name a commit only their machine has
                        self.assertTrue(g.commit_exists(d, sha), f"{label}: {who}'s own log names a commit that is not there")
        # the ledger equals what the fake model saw
        led = worker.ledger(self.ra)
        self.assertEqual(led["calls"] + worker.ledger(self.rb)["calls"], self.model_calls(), f"{label}: ledger calls differ from the calls made")
        self.assertLessEqual(led["calls"], 300, f"{label}: over the daily call cap")
        # nothing secret was ever sent to a model
        for p in self.prompts():
            self.assertNotIn(SECRET, p, f"{label}: a secret reached the model")
            self.assertNotIn(EMAIL, p, f"{label}: an email reached the model")

    # ---- the day ----------------------------------------------------------------------------------------------------
    def test_a_day_of_use(self):
        A, B, ra, rb = self.A, self.B, self.ra, self.rb

        # 1. morning: a feature branch, a long session, commits, the observer keeping up, savepoints by themselves (auto mode)
        T.sh("git", "switch", "-q", "-c", "feat/a", cwd=A)
        self.assertEqual(self.hook(A, "SessionStart", "s0"), "", "nothing recorded yet: nothing said")
        self.session(A, "s1", 10, start=0)
        self.invariants("morning")
        run_a = running.Running(ra, "feat/a")
        self.assertEqual(run_a.pending_bytes(), 0)
        logs_a = [v for v in tree.all_views(ra)[0] if v["kind"] == "log" and v["branch"] == "feat/a"]
        self.assertGreaterEqual(len(logs_a), 1, "auto mode saved a log without anyone asking")
        self.assertTrue(any(v["sha"] for v in logs_a), "and one of them carries a commit")
        self.assertTrue(any(c[:1] == ["log"] for c in self.spawned), self.spawned)
        fed_a = self.fed[("alice", "feat/a")]
        self.assertEqual(sum(1 for q in self.lines(run_a.queue)), fed_a, "every tool use that counts was queued, and none that does not")

        # 2. the allowance fills up: nearly full, then full
        before = self.model_calls()
        self.usage(0.93)
        self.session(A, "s2", 3, start=10)
        self.assertGreater(self.model_calls(), before, "below the threshold the observer keeps working")
        self.assertFalse(worker.status(ra)["cooling_down"])
        self.usage(0.96)
        self.block(A, "s2", 13)
        self.block(A, "s2", 14)  # the call that sees 96% still does its work and starts the pause
        self.assertTrue(worker.status(ra)["cooling_down"], "at 96% the observer pauses")
        self.prompt_outputs += [self.hook(A, "UserPromptSubmit", "s2", prompt="and now?") for _ in range(3)]
        paused_calls = self.model_calls()
        for i in range(15, 19):
            self.block(A, "s2", i)
        self.assertEqual(self.model_calls(), paused_calls, "while paused no model is called")
        self.assertGreater(running.Running(ra, "feat/a").pending_bytes(), 0, "the tool uses wait in the queue")
        told = [json.loads(s)["systemMessage"] for s in self.prompt_outputs if s and "systemMessage" in s]
        self.assertEqual(len(told), 1, f"the person is told once about the pause, not on every prompt: {told}")
        self.assertIn("five-hour usage is 96%", told[0])
        self.invariants("paused", queue_drained=False)
        # time passes: the window resets
        self.usage(0.15)
        led = worker.ledger(ra)
        led["cooldown_until"] = 0
        worker.save(ra, led)
        self.hook(A, "SessionStart", "s3")  # a new session flushes what the paused one left in the queue
        self.assertEqual(running.Running(ra, "feat/a").pending_bytes(), 0, "after the reset the waiting tool uses are observed")
        self.invariants("resumed")

        probe = capture.make_entry(ra, "finding", "Probe: reply with only the word ok", {"what": "answered ok", "summary": "a one word reply"}, paths=["src/mod_0.py"],
                                   provenance="worker-written")
        self.assertEqual(probe.anchor["branch"], "feat/a")

        # 3. another branch from main, and the first one merged
        self.tidy_up(A)
        T.sh("git", "switch", "-q", "main", cwd=A)
        T.sh("git", "switch", "-q", "-c", "feat/b", cwd=A)
        self.session(A, "s4", 8, start=20)
        self.invariants("second branch")
        T.sh("git", "switch", "-q", "main", cwd=A)
        T.sh("git", "merge", "-q", "--no-ff", "-m", "Merge branch 'feat/a'", "feat/a", cwd=A)
        T.sh("git", "push", "-q", "origin", "main", cwd=A)
        with self.at(A):
            hookmain.run(["post-merge"])
        self.assertTrue(any(c[:2] == ["tidy", "--work"] for c in self.spawned), "a pull runs the tidy pass in tidy auto mode")
        self.assertTrue(any(c[:2] == ["publish", "--merged"] for c in self.spawned), "auto mode publishes a merged branch by itself, from the git hook")
        shared = ra.load_shared()[0]
        shared_ids = {l.entry.id for l in shared}
        self.assertTrue([l for l in shared if l.entry.kind == "finding" and l.entry.anchor.get("branch") == "feat/a"], "the merged branch's notes were published")
        self.assertFalse([l for l in shared if l.entry.kind == "log"], "and no log, ever: logs stay on this machine")
        self.assertNotIn(probe.id, shared_ids, "the throwaway session's note was not published")
        self.assertTrue((ra.cdir / "archive" / f"{probe.id}.json").exists(), "it was archived, not deleted")
        self.assertFalse([e for e in ra.queued() if e.anchor.get("branch") == "feat/a"], "everything tidy queued on the merged branch went out")
        self.assertNotIn("look merged", self.hook(A, "SessionStart", "s5"), "nothing is left on the merged branch to remind the agent about")
        self.assertIn("nothing to publish", self.run_cli(A, "publish", "--branch", "feat/a", "--yes")[1], "publishing again finds nothing and is harmless")
        self.assertTrue([e for e in ra.unpublished() if e.anchor.get("branch") == "feat/b"], "the open branch stays private")
        self.assertEqual(self.run_cli(A, "sync")[0], 0)

        # 4. the second person pulls and starts a session on main
        T.sh("git", "pull", "-q", "origin", "main", cwd=B)
        self.assertEqual(self.run_cli(B, "sync", "--fetch-only")[0], 0)
        start = self.hook(B, "SessionStart", "b1")
        self.assertNotIn("saved log", start, "alice's logs never reach bob")
        alice_private = {e.id for e in ra.load_private()}
        self.assertFalse(alice_private & {l.entry.id for l in rb.all_entries()}, "nothing alice kept private reaches bob")
        theirs = [l for l in rb.all_entries() if l.user == ra.user]
        self.assertTrue(theirs and all(l.entry.kind != "log" for l in theirs), "what bob has of alice's is notes")
        T.sh("git", "switch", "-q", "-c", "feat/c", cwd=B)
        self.session(B, "b2", 4, start=40)
        self.invariants("teammate")
        self.run_cli(B, "log")
        code, text = self.run_cli(B, "publish", "--all", "--yes")
        self.assertEqual(code, 0, text)
        self.assertEqual(self.run_cli(B, "sync")[0], 0)
        self.assertEqual(self.run_cli(A, "sync")[0], 0)
        n_shared = len(ra.load_shared()[0])
        self.assertEqual(self.run_cli(A, "sync")[0], 0)
        self.assertEqual(len(ra.load_shared()[0]), n_shared, "syncing twice changes nothing")

        # 5. tidy: notes whose files changed are judged; logs stay
        T.sh("git", "switch", "-q", "feat/b", cwd=A)
        for j in range(5):
            self.session(A, f"s6{j}", 2, start=60 + 3 * j, commit_every=1)
            self.run_cli(A, "log")
        self.assertTrue(any(c[:2] == ["tidy", "--work"] for c in self.spawned[-12:]), "tidy auto runs after a log is saved")
        logs = [v for v in tree.all_views(ra)[0] if v["kind"] == "log" and v["branch"] == "feat/b"]
        self.assertGreaterEqual(len(logs), 5, "every log is kept: nothing folds or archives a log")
        for v in logs:
            self.assertTrue((ra.cdir / "private" / f"{v['id']}.json").exists())
            for oid in v["sources"]:
                self.assertTrue((ra.cdir / "private" / f"{oid}.json").exists() or (ra.cdir / "archive" / f"{oid}.json").exists(),
                                "each covered observation is a note, or tidy archived it")
        _, said = self.run_cli(A, "note", "revenue module reads the value", "src/mod_1.py", "--evidence", "x")
        note_id = re.search(r"recorded (\S+)", said).group(1)
        T.commit(A, "rework mod_1 entirely", {"src/mod_1.py": "VALUE = 'reworked'\n"})
        self.assertEqual(self.run_cli(A, "tidy", "--work", "--quiet")[0], 0)
        judged = next(v for v in tree.all_views(ra)[0] if v["id"] == note_id)
        self.assertEqual(judged["status"], "resolved", "tidy auto judged the note whose file was reworked and stored the status")
        self.invariants("tidy")

        # 6. the end of the day
        self.hook(A, "SessionEnd", "s9")
        self.assertEqual(running.Running(ra, "feat/b").pending_bytes(), 0)
        before = (len(ra.all_entries()), self.model_calls())
        self.run_cli(A, "tidy", "--work", "--quiet")
        self.run_cli(A, "sync", "--fetch-only")
        self.assertEqual((len(ra.all_entries()),), before[:1], "tidy and sync twice more change nothing")
        self.invariants("end of day")
        led = worker.ledger(ra)
        self.assertEqual(round(led["cost"], 3), round(0.001 * led["calls"], 3), "the ledger's cost is the sum of the calls")
        status = self.run_cli(A, "worker", "--status")[1]
        self.assertIn("five-hour usage", status)
        # nothing secret in anything shared
        for l in ra.load_shared()[0] + rb.load_shared()[0]:
            blob = l.entry.to_json()
            self.assertNotIn(SECRET, blob)
            self.assertNotIn(EMAIL, blob)
        # the person's own git still works and the repo is sound
        self.tidy_up(A, "end of day")
        self.assertEqual(T.sh("git", "status", "--porcelain", cwd=A), "", "nothing Logbook did left the work tree dirty")
        T.sh("git", "fsck", "--no-progress", cwd=A)
        self.assertFalse([v for v in tree.all_views(ra)[0] if v["kind"] == "log" and v.get("status") in ("resolved", "in-progress")], "tidy never judges a saved log")
        # uninstall puts the files back and keeps the notes
        n_logs = len([e for e in ra.all_entries() if e.entry.kind == "log"])
        self.assertEqual(self.run_cli(A, "uninstall", "--yes")[0], 0)
        self.assertEqual(len([e for e in ra.all_entries() if e.entry.kind == "log"]), n_logs, "uninstalling keeps every log")

    # ---- passes that overlap ---------------------------------------------------------------------------------------------
    def test_passes_that_overlap_lose_and_double_nothing(self):
        """The detached processes a hook starts do overlap in real use: a pass from one Stop is still calling the model when the next hook, or the session end's
        savepoint, starts another. Run several at once, through the real subprocess call, and require that every tool use is observed exactly once."""
        import threading
        from getlogbook import observer
        d, repo = self.A, self.ra
        self.usage(0.10, delay=2.5)  # each call takes 2.5 s, so a pass of three calls outlasts the 5 s a savepoint used to wait
        T.sh("git", "switch", "-q", "-c", "feat/overlap", cwd=d)
        run = running.Running(repo, "feat/overlap")
        head = running.branch_now(repo)[1]
        for i in range(30):  # a backlog, queued without the hooks that would have drained it as it grew
            run.push(running.event_from_payload({"tool_name": "Edit", "tool_input": {"file_path": f"src/mod_{i % 5}.py", "new_string": f"v{i}"}, "tool_response": "ok",
                                                 "session_id": "ov", "hook_event_name": "PostToolUse"}, "feat/overlap", head))
        queued = len(self.lines(run.queue))
        done, errors = [], []

        def go(fn):
            try:
                done.append(fn())
            except Exception as ex:  # a thread must report, not vanish
                errors.append(repr(ex))
        jobs = [lambda: observer.drain(repo, "feat/overlap"), lambda: observer.drain(repo, "feat/overlap", flush=True),
                lambda: savepoint.save(repo, "feat/overlap"), lambda: observer.drain(repo, "feat/overlap", flush=True)]
        threads = [threading.Thread(target=go, args=(j,)) for j in jobs]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        self.assertEqual(errors, [])
        self.assertEqual(len(done), len(jobs), "every overlapping pass finished")
        saved = [r for r in done if isinstance(r, dict) and "saved" in r]
        self.assertEqual(len(saved), 1, f"the savepoint was not dropped by a pass that was running: {done}")
        self.assertEqual(run.pending_bytes(), 0, "and nothing is left in the queue")
        self.assertEqual(len(self.lines(run.queue)), queued, "no tool use was lost from the queue")
        ids = [o["id"] for o in self.lines(run.obs) + [o for f in (run.dir / "archive").glob("*.jsonl") for o in self.lines(f)]]
        self.assertEqual(len(ids), len(set(ids)), "no observation was written twice")
        self.invariants("overlap")

    # ---- the cost of being in the way ---------------------------------------------------------------------------------
    def test_the_hooks_stay_fast_and_the_real_entry_point_works(self):
        d = self.A
        T.sh("git", "switch", "-q", "-c", "feat/speed", cwd=d)
        started = time.perf_counter()
        for i in range(60):
            self.tool(d, "sp", "Edit", {"file_path": "src/mod_0.py", "new_string": f"x{i}"}, "ok")
        per_call = (time.perf_counter() - started) / 60
        self.assertLess(per_call, 0.25, f"a PostToolUse hook took {per_call:.3f}s on average in-process")
        payload = json.dumps({"cwd": str(d), "session_id": "sp", "tool_name": "Read", "tool_input": {"file_path": "README.md"}, "tool_response": "# shop", "hook_event_name": "PostToolUse"})
        env = dict(os.environ, PYTHONPATH=os.environ["PYTHONPATH"], LOGBOOK_NO_SPAWN="1")
        times = []
        for _ in range(5):
            t0 = time.perf_counter()
            p = subprocess.run([sys.executable, "-m", "getlogbook", "capture", "--event", "PostToolUse", "--agent", "claude-code"], input=payload, cwd=d, env=env,
                               capture_output=True, text=True)
            times.append(time.perf_counter() - t0)
            self.assertEqual(p.returncode, 0, p.stderr)
        self.assertLess(sorted(times)[len(times) // 2], 3.0, f"the real hook process took {times}")
        self.assertEqual(self.fed[("alice", "feat/speed")] + 5, len(self.lines(running.Running(self.ra, "feat/speed").queue)), "in-process and real-process hooks queue the same way")


if __name__ == "__main__":
    unittest.main()
