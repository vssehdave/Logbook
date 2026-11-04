"""End-to-end check of an installed `logbook` (PyPI, TestPyPI or a venv build) on local temp repos. Usage: python bench/e2e.py <path to logbook executable>. Prints PASS/FAIL per claim."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

LB = sys.argv[1]
PY = str(Path(LB).with_name("python.exe"))
root = Path(tempfile.mkdtemp(prefix="lb-e2e2-"))
fails = []


def sh(*a, cwd, inp=None, env=None):
    e = dict(os.environ, **(env or {}))
    r = subprocess.run(a, cwd=cwd, capture_output=True, text=True, input=inp, encoding="utf-8", env=e,
                       stdin=None if inp is not None else subprocess.DEVNULL)
    return r.returncode, (r.stdout + r.stderr)


def git(cwd, *a):
    rc, o = sh("git", *a, cwd=cwd)
    assert rc == 0, (a, o)
    return o.strip()


def lb(cwd, *a, inp=None, env=None):
    return sh(LB, *a, cwd=cwd, inp=inp, env=env)


def ok(cond, msg, detail=""):
    print(("PASS  " if cond else "FAIL  ") + msg + ("" if cond else "\n      " + str(detail)[:500]))
    if not cond:
        fails.append(msg)


def clone(name, email, display, remote):
    d = root / name
    git(root, "clone", "-q", "file://" + str(remote).replace("\\", "/"), str(d))
    git(d, "config", "user.email", email)
    git(d, "config", "user.name", display)
    return d


def commit(d, msg, files):
    for p, t in files.items():
        f = d / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(t)
    git(d, "add", "-A")
    git(d, "commit", "-q", "-m", msg)
    return git(d, "rev-parse", "HEAD")


def note(d, topic, paths, **kw):
    body = {"kind": "finding", "topic": topic, "summary": "total() adds refunded rows " + topic, "why": "no filter for " + topic,
            "wrong": "assumed refunds were excluded", "paths": paths, **kw}
    rc, o = lb(d, "note", "--json", inp=json.dumps(body))
    assert rc == 0, o
    import re
    return re.search(r"recorded (\S+)", o).group(1)  # the overlap hint prints other notes' ids first


remote = root / "remote.git"
git(root, "init", "-q", "--bare", str(remote))
seed = clone("seed", "alice@x.io", "Alice A.", remote)
commit(seed, "init", {"shop/revenue.py": "total = 1\n"})
git(seed, "push", "-q", "origin", "HEAD")
main = git(seed, "branch", "--show-current")
alice = clone("alice", "alice@x.io", "Alice A.", remote)
alice2 = clone("alice2", "alice@x.io", "Alice A.", remote)
bob = clone("bob", "bob@x.io", "Bob B.", remote)

print("version:", lb(root, "--help")[1].splitlines()[0][:60])

# --- setup ------------------------------------------------------------------------------------------------------------
rc, o = lb(alice, "setup", "--yes", "--agent", "agents-md")
ok(rc == 0, "setup runs", o)
ok((alice / ".git/hooks/pre-push").exists(), "pre-push hook installed")
hook = (alice / ".git/hooks/pre-push").read_text()
ok("sync" not in hook and "queue --hook" in hook, "the pre-push hook only reminds (it does not push notes)", hook)
ok("refs/logbook/log" in git(alice, "config", "--get-all", "remote.origin.fetch"), "fetch refspec added")

# --- note / publish / move --------------------------------------------------------------------------------------------
n1 = note(alice, "refund rounding", ["shop/revenue.py"])
rc, o = lb(alice, "publish")
ok(n1 in o and ("pass ids" in o or "nothing to publish" in o) and "Traceback" not in o, "bare publish lists the queue and does not crash (closed input)", o)
rc, o = lb(alice, "publish", n1, "--yes", "--keep")
ok(rc == 0 and (alice / ".git/logbook/private" / f"{n1}.json").exists(), "publish --keep leaves the private copy", o)
ok("already shared" in lb(alice, "publish", n1, "--yes")[1], "an already shared id is skipped")
n2 = note(alice, "tax export", ["shop/revenue.py"])
rc, o = lb(alice, "publish", n2, "--yes")
ok(rc == 0 and not (alice / ".git/logbook/private" / f"{n2}.json").exists(), "publish moves the note", o)

# --- git push does not send notes; logbook sync does -----------------------------------------------------------------
n3 = note(alice, "private idea", ["shop/revenue.py"])
rc, o = sh("git", "push", "origin", "HEAD", cwd=alice)
ok(rc == 0, "git push succeeds", o)
ok("not pushed yet" in o, "git push reminds that published notes are not pushed", o)
ok("refs/logbook/log/" not in git(alice, "ls-remote", "origin"), "git push did NOT send the notes")
rc, o = lb(alice, "sync")
ok(rc == 0 and "refs/logbook/log/" in git(alice, "ls-remote", "origin"), "logbook sync pushes the notes", o)
ref = git(alice, "for-each-ref", "--format=%(refname)", "refs/logbook")
tree = git(alice, "ls-tree", "-r", "--name-only", ref.split()[0])
ok(n3 not in tree and n1 in tree and n2 in tree, "the private note never left the machine", tree)
rc, o = sh("git", "push", "origin", "HEAD", cwd=alice)
ok("not pushed yet" not in o, "after sync there is nothing left to remind about", o)

# --- Bob reads: names, tree, citations ---------------------------------------------------------------------------------
rc, o = lb(bob, "setup", "--yes", "--agent", "agents-md")
sh("git", "pull", "-q", cwd=bob)
rc, o = lb(bob, "ask", "refund", "rounding")
ok(rc == 0 and "Alice A." in o, "Bob finds Alice's note with her name", o)
sha8 = git(bob, "rev-parse", "--short=8", "HEAD")
rc, o = lb(bob, "ask", f"note:{n1[:14]}")
ok(f"path: repo > branch:{main} > commit:{sha8} > note:{n1}" in o, "ask note:<id> shows the path from the root", o)
rc, o = lb(bob, "inject", "--prompt", "why is revenue wrong?", "--session", "chatA")
ok("[1]" in o and "source:" in o and "superscript" in o, "injected notes are numbered with a source line and the cite rule", o)
data = json.loads(lb(bob, "cites", "--session", "chatA", "--json")[1])
ok(data["sources"] and data["sources"][0]["expandable"] and data["mode"] == "ask", "cites --json: expandable teammate note and the mode", data)

# --- cites --where reads a Claude Code transcript -----------------------------------------------------------------------
proj = root / "claude" / "projects" / "p"
proj.mkdir(parents=True)


def trow(uuid, kind, text):
    return json.dumps({"type": kind, "uuid": uuid, "isSidechain": False, "message": {"role": kind, "content": [{"type": "text", "text": text}]}},
                      ensure_ascii=False, separators=(",", ":"))


(proj / "chatW.jsonl").write_text("\n".join([trow("u1", "user", "q"), trow("a1", "assistant", "Refunds counted² here."),
                                              trow("a2", "assistant", "Again² and ²².")]) + "\n", encoding="utf-8")
rc, o = lb(bob, "cites", "--where", "2", "--session", "chatW", env={"CLAUDE_CONFIG_DIR": str(root / "claude")})
hits = json.loads(o)["hits"] if rc == 0 else []
ok([h["uuid"] for h in hits] == ["a1", "a2"] and hits[0]["before"].endswith("Refunds counted"), "cites --where finds the answers that cite a number", o)

# --- publish modes --------------------------------------------------------------------------------------------------------
ok(lb(alice, "config", "publish")[1].strip() == "ask", "the default publish mode is ask")
lb(alice, "config", "publish", "never")
nn = note(alice, "never mode note", ["shop/revenue.py"])
rc, o = lb(alice, "publish", nn, "--yes")
ok(rc != 0 and (alice / ".git/logbook/private" / f"{nn}.json").exists(), "never refuses to publish", o)
lb(alice, "config", "publish", "auto")
rc, o = lb(alice, "note", "--json", inp=json.dumps({"kind": "finding", "topic": "auto note", "summary": "mail a@b.io about it", "why": "w", "paths": ["shop/revenue.py"]}))
ok("published (auto mode)" in o, "auto publishes a note as it is written", o)
ok(not any("auto note" in p.read_text() for p in (alice / ".git/logbook/private").glob("*.json")), "auto moved it out of the private log")
lb(alice, "config", "publish", "ask")

# --- the file-overwrite hole ----------------------------------------------------------------------------------------------
victim = bob / "victim.txt"
victim.write_text("precious\n")
code = ("from getlogbook.store import Repo\nfrom getlogbook.entry import Entry, new_id\nr = Repo('.')\n"
        "e = Entry(id=new_id(), kind='finding', topic='evil', body={'summary': 's', 'why': 'w evil'}, display='Mallory', "
        "created='2026-11-03T09:00:00', anchor={'sha': '--output=victim.txt', 'subject': 'x', 'paths': ['shop/revenue.py'], 'names': ['revenue']})\n"
        "r._write_ref('refs/logbook/log/' + 'd' * 10 + '/000000', {f'entries/{e.id}.json': e.to_json().encode()}, 'x', None)\n"
        "c = r.cfg(); c['trusted'] = ['d' * 10]; r.save_cfg(c)\n")
rc, o = sh(PY, "-c", code, cwd=bob)
ok(rc == 0, "a hostile shared note (sha is --output=victim.txt) was planted", o)
lb(bob, "inject", "--prompt", "why is revenue wrong? evil", "--session", "chatE")
lb(bob, "cites", "--session", "chatE")
lb(bob, "ask", "evil")
lb(bob, "log")
ok(victim.read_text() == "precious\n", "reading the hostile note did not overwrite a file", victim.read_text())

# --- same person, two machines; purge beats merge ---------------------------------------------------------------------------
lb(alice2, "setup", "--yes", "--agent", "agents-md")
sh("git", "pull", "-q", cwd=alice2)
n4 = note(alice2, "second machine", ["shop/revenue.py"])
lb(alice2, "publish", n4, "--yes")
rc, o = lb(alice2, "sync")
ok(rc == 0, "sync from the second machine merges and pushes (hooks installed)", o)
lb(alice, "sync")
ok(n4 in lb(alice, "ask", "second", "machine")[1], "the first machine sees the second machine's note")
lb(alice, "purge", n1, "--push")
lb(alice2, "sync")
ok(n1 not in lb(alice2, "ask", "refund", "rounding")[1], "a purged note does not come back through the other machine")

# --- squash, drafts, checks, demo, old names ----------------------------------------------------------------------------------
git(alice, "switch", "-q", "-c", "feat/tax")
n5 = note(alice, "tax before commit", ["shop/revenue.py"])
commit(alice, "feat: tax", {"shop/revenue.py": "total = 2\n"})
git(alice, "switch", "-q", main)
git(alice, "merge", "-q", "--squash", "feat/tax")
git(alice, "commit", "-q", "-m", "feat: tax (#7)")
git(alice, "branch", "-D", "feat/tax")
ok("squash" in lb(alice, "ask", f"note:{n5}")[1], "a note with no commit follows a squash once the branch is gone")
commit(alice, "wip: half done", {"shop/other.py": "x = 1\n"})
ok("half done" not in lb(alice, "log")[1] and "half done" in lb(alice, "log", "-v")[1], "wip commits are folded out of the log")
rc, o = lb(alice, "status", "--check")
ok("fail" not in o.lower().replace("failures", ""), "status --check reports no failures", o)
rc, o = lb(root, "demo")
ok(rc == 0 and "ALL CHECKS PASSED" in o, "the built-in demo passes", o[-300:])
for old in (("query", "refund"), ("explain", "shop/revenue.py"), ("doctor",), ("queue",), ("stats",)):
    ok(lb(alice, *old)[0] in (0, 4), f"old name `{old[0]}` still runs")

# --- 0.0.4: notes as key: value lines, plain notes, who wrote it, the allow rules --------------------------------------------------
rc, o = lb(bob, "note", "--fields", "--check", inp="title: t\nsummary: see `shop/gone.py` and `total()`\npaths: shop/revenue.py\n")
ok("! not found: shop/gone.py" in o and "checked only" in o, "note --fields --check reports the grounding and saves nothing", o)
before = len(list((bob / ".git/logbook/private").glob("*.json")))
rc, o = lb(bob, "note", "A plain note in plain words", "shop/revenue.py", env={"LOGBOOK_WRITER": "user"})
ok(rc == 0 and "recorded" in o, "a person writes a note in plain words", o)
newest = max((bob / ".git/logbook/private").glob("*.json"), key=lambda p: p.stat().st_mtime)
d = json.loads(newest.read_text(encoding="utf-8"))
ok(d["provenance"] == "user-written" and d["v"] == 2 and d["anchor"]["paths"] == ["shop/revenue.py"], "it is labelled user-written", d["provenance"])
rc, o = lb(bob, "note", "--fields", inp="kind: finding\ntitle: agent note\nsummary: `total()` in `shop/revenue.py` sums rows\nwhy: no filter\nevidence: read shop/revenue.py\npaths: shop/revenue.py\n",
           env={"LOGBOOK_WRITER": "agent"})
newest = max((bob / ".git/logbook/private").glob("*.json"), key=lambda p: p.stat().st_mtime)
d = json.loads(newest.read_text(encoding="utf-8"))
ok(rc == 0 and d["provenance"] == "agent-written" and d["topic"] == "agent note" and d["checks"]["evidence"], "an agent's note is labelled agent-written, title: is the topic, and it is grounded", d)
rc, o = lb(bob, "setup", "--yes", "--agent", "claude-code")
allow = json.loads((bob / ".claude/settings.local.json").read_text())["permissions"]["allow"]
ok("Bash(logbook note:*)" in allow and not any(w in a for a in allow for w in ("publish", "sync", "purge", "gc", "trust", "config")), "setup allows the safe commands only", allow)
rc, o = lb(bob, "uninstall", "--yes", "--agent", "claude-code")
ok("permissions" not in json.loads((bob / ".claude/settings.local.json").read_text()) if (bob / ".claude/settings.local.json").exists() else True, "uninstall removes the allow rules", o)

print(f"\n{len(fails)} failed" if fails else "\nALL PASSED")
print("workdir:", root)
sys.exit(1 if fails else 0)
