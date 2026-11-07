"""Savepoints: `logbook log` turns what the observer collected on a branch since the last savepoint into one stored log.

A stored log is an ordinary private entry of kind `log`. It always carries the branch; it carries a commit only when one was made since the last savepoint.
The summary comes from the same cheap model as the observations, or, with no model to ask, is put together from the observations by code. Its fields use the
entry body fields older versions already know: request -> context, completed -> what, learned -> why, investigated -> evidence, next steps -> open.
Every observation the log covers also becomes a note of its own (an ordinary `finding` entry with an `obs` record, the same id as the observation, `sources` =
the log), so it can be cited, tidied and published one by one. The observations and the tool uses behind them move to `running/<branch>/archive/`;
observations inherited from the parent branch stay where they are.
"""
from __future__ import annotations

import json
import re
import sys
import time

from . import capture, convo, ground, observer, running, worker
from . import git as g
from .entry import HEX_RE, ID_RE, MAX_LIST, Entry, new_id
from .safety import inside as safety_inside
from .safety import localize, redact, repo_relative

WAIT = 150  # seconds a savepoint waits for an observer pass already running (it holds the lock across its model calls) before it gives up
AUTO_MIN = 5  # auto mode saves after a commit once this many new observations have piled up
PROMPT_OBS = 60  # observations shown to the model
SYSTEM = """You write the savepoint for a coding session on the git branch `{branch}`. You cannot use tools. Below are the observations recorded since the last savepoint, oldest first. Summarize them for a teammate, or a later session, who has not seen the work.

Use only the observations: do not guess a cause and do not add anything they do not say. Keep a claim attributed to where it came from: if an observation says a document claims something, write "the roadmap says ..." and do not turn it into a fact about the project; leave out a document's version or status claim unless an observation shows it is still true. Do not copy secrets, tokens, email addresses or pasted data rows. Leave a field empty rather than invent it. Answer with exactly:

<savepoint>
  <title>a short title, under 80 characters</title>
  <request>what the person asked for, only if an observation says so</request>
  <investigated>what was looked at</investigated>
  <learned>what was found out or decided, and why</learned>
  <completed>what was built, fixed or changed</completed>
  <next_steps>what is left to do</next_steps>
</savepoint>
"""
FIELDS = (("request", "context"), ("investigated", "evidence"), ("learned", "why"), ("completed", "what"), ("next_steps", "open"))


def _state_path(run):
    return run.dir / "savepoint.json"


def last(run):
    try:
        return json.loads(_state_path(run).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


own = running.own


def commit_made(run, obs, head):
    """True when HEAD moved since the last savepoint, or, for the first one, since the first of these observations was made."""
    ref = last(run).get("head") or (obs[0].get("head") if obs else "")
    return bool(head and ref and head != ref)


def due(repo, branch, head):
    """Auto mode: save once a commit follows enough new observations."""
    run = running.Running(repo, branch)
    obs = own(run)
    return len(obs) >= AUTO_MIN and commit_made(run, obs, head)


# ---- the summary ------------------------------------------------------------------------------------------------
def build_prompt(branch, obs):
    lines = []
    for i, o in enumerate(obs[-PROMPT_OBS:], 1):
        facts = "; ".join(o.get("facts", [])[:4])
        lines.append(f"{i}. [{o['type']}] {o['title']}: {o['narrative'][:400]}" + (f" Facts: {facts[:300]}" if facts else "") +
                     (f" Changed: {', '.join(o['files_modified'][:6])}" if o.get("files_modified") else ""))
    return SYSTEM.format(branch=branch) + "\nOBSERVATIONS:\n" + "\n".join(lines) + "\n"


def parse(text):
    """The savepoint fields in a model answer, or {} when it did not follow the shape."""
    if "<savepoint>" not in text:
        return {}
    got = {k: observer._tag(text, k) for k in ("title", *(f for f, _ in FIELDS))}
    return got if got["title"] and (got["completed"] or got["learned"]) else {}


def fallback(obs):
    """What code can say with no model: titles of what changed, titles and facts of what was learned. Never invents; may be plain."""
    done = [o["title"] for o in obs if o["type"] in ("feature", "bugfix", "refactor", "change")]
    learned = [o["title"] + (": " + o["facts"][0] if o.get("facts") else "") for o in obs if o["type"] in ("discovery", "decision")]
    looked = sorted({f for o in obs for f in o.get("files_read", [])})
    title = (done or learned or [obs[0]["title"]])[0]
    return {"title": title[:80], "request": "", "investigated": ("read " + ", ".join(looked[:8])) if looked else "",
            "learned": "; ".join(learned)[:1500], "completed": "; ".join(done)[:1500], "next_steps": ""}


def summarize(repo, branch, obs, call=worker.call_model, now=time.time):
    """(fields, how): by the model when it is on, available and within its budget, else by code."""
    cfg = repo.cfg()
    if not (worker.enabled(repo) and (call is not worker.call_model or worker.available())):
        return fallback(obs), "code"
    led = worker.ledger(repo)
    if now() < led["cooldown_until"] or led["calls"] >= int(cfg.get("worker_calls", worker.MAX_CALLS)):
        return fallback(obs), "code"
    sent, _ = redact(build_prompt(branch, obs), cfg.get("deny", []))
    text, cost, error = call(sent)
    worker.settle(repo, led, cost, error, now)
    fields = parse(text) if not error else {}
    return (fields, "model") if fields else (fallback(obs), "code")


# ---- the savepoint ---------------------------------------------------------------------------------------------
def save(repo, branch, call=worker.call_model, now=time.time, use_model=True, observe=True, commit=None):
    """Make one savepoint. Returns {"saved": entry id, ...} or {"skipped": reason}; never raises for a model problem.
    `commit` is the commit that started it (the git post-commit hook passes it): the savepoint is about that commit, not about whatever HEAD is by the time the
    background process runs, and observations whose tool uses ran after the commit are left for the next savepoint."""
    if branch == "HEAD":
        return {"skipped": "HEAD is detached: check out a branch first"}
    if observe and worker.enabled(repo):
        observer.drain(repo, branch, flush=True, call=call, now=now, wait=WAIT)  # tool uses still in the queue belong in this savepoint
    run = running.Running(repo, branch)
    with capture._lock(worker._wdir(repo) / ".lock", timeout=WAIT, stale=worker.LOCK_STALE) as got:
        if not got:
            return {"skipped": "the observer is busy; try again in a moment"}
        commit = commit if commit and HEX_RE.match(commit) and g.commit_exists(repo.root, commit) else ""
        every = own(run)
        obs = [o for o in every if not (commit and _after(repo, commit, o))]
        if not obs:
            return {"skipped": "nothing new since the last savepoint"}
        head = commit or running.branch_now(repo)[1]
        sha = head if (commit or commit_made(run, obs, head)) else ""
        fields, how = summarize(repo, branch, obs, call, now) if use_model else (fallback(obs), "code")
        e = _entry(repo, branch, sha, obs, fields)
        prev = last(run).get("head") or (obs[0].get("head") if obs else "")
        for n in notes_from(repo, branch, head, prev, obs, e.id, run.queue_text(last(run).get("qoff", 0), run.offset())):
            if not repo.get_private(n.id):  # the same observation is never saved as a note twice
                repo.add_private(n)
        repo.add_private(e)
        qstart, qend = last(run).get("qoff", 0), run.offset()
        run.archive_queue(e.id, qstart, qend)
        talk, toff = convo.since(run, last(run).get("toff", 0))
        convo.save(repo, e.id, talk)
        covered = {o["id"] for o in obs}
        keep = [o for o in run.observations() if o["id"] not in covered]  # a pass may have appended since: only the covered ones leave
        if run.obs.exists():
            run.archive(e.id, [o for o in run.observations() if o["id"] in covered])
            run.rewrite(keep)
        later = len(every) > len(obs)  # observations left for the next savepoint: their tool uses must stay in its evidence text
        running.atomic_write(_state_path(run), json.dumps({"id": e.id, "head": head, "t": int(now()), "qoff": qstart if later else qend, "toff": toff}))
    # a new log is a moment to tidy, in every mode: judge changed notes, archive junk, keep the publish queue, in the background
    capture.spawn_detached([repo.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", "tidy", "--work", "--quiet", "--no-judge"], repo.root)
    return {"saved": e.id, "branch": branch, "commit": sha, "observations": len(covered), "notes": len(covered), "messages": len(talk), "title": e.topic, "by": how}


def _entry(repo, branch, sha, obs, fields):
    from . import tree
    paths = sorted({f for o in obs for f in o.get("files_modified", [])})
    body = {dest: fields.get(src, "") for src, dest in FIELDS}
    first = re.split(r"(?<=[.!?])\s", (fields.get("completed") or fields.get("learned") or "").strip(), maxsplit=1)[0]
    body["summary"] = (first or fields["title"])[:300]  # the first sentence: the full text is in what / why
    e = Entry(id=new_id(), kind="log", topic=fields["title"][:200], body={k: v[:2000] for k, v in body.items() if v}, provenance="worker-written",
              captured_via="savepoint", created=capture.now(), v=2, level="commit" if sha else "branch",
              sources=[o["id"] for o in obs if ID_RE.match(o["id"])][-MAX_LIST:],
              display=repo.cfg().get("display", "") if repo.attribution() == "named" else "")
    a = tree.anchor_for(repo, sha=sha or None, paths=paths, dirty=False, with_base=True)
    if not sha:  # no commit yet: the log belongs to the branch, not to whatever HEAD is
        a.update(sha="", tree="", parent="", patch_id="", subject="", date="", range_pid="")
    a["branch"] = branch
    e.anchor = a
    return e


# ---- the notes ---------------------------------------------------------------------------------------------------
def _after(repo, commit, o):
    """True when the observation's tool uses all ran after `commit` (HEAD was the commit or a descendant when the first of them ran)."""
    first = next((h for h in o.get("heads", []) if HEX_RE.match(h)), "")
    return bool(first) and (first == commit or g.try_run(["merge-base", "--is-ancestor", commit, first], repo.root)[0] == 0)


def _commit_for(repo, o, end, prev, mod, cache):
    """The commit that holds an observation's own work: the first commit after HEAD was where its first tool use saw it, up to `end`, that changed a file it modified.
    '' when there is none (the edits are not committed yet, or it changed nothing). A savepoint can span several commits; this is what tells them apart."""
    if not end or not mod:
        return ""
    start = next((h for h in o.get("heads", []) if HEX_RE.match(h)), "") or prev
    if not start or not HEX_RE.match(start):
        return ""
    if start == end:
        return ""
    rc, out, _ = g.try_run(["rev-list", "--reverse", "--first-parent", "-n", "50", f"{start}..{end}"], repo.root)
    if rc != 0:  # HEAD moved to unrelated history (a rebase, a reset): fall back to the savepoint's own commit
        return end if mod and set(g.changed_paths(repo.root, end)) & mod else ""
    for c in out.split():
        if c not in cache:
            cache[c] = set(g.changed_paths(repo.root, c))
        if cache[c] & mod:
            return c
    return ""


_inside = safety_inside  # the files git could know about: a path outside the repository (a scratch script, a file under the home folder) or a web address cannot be looked up there


_rel = repo_relative  # a file as the repo spells it, whatever form the model gave it in


def notes_from(repo, branch, end, prev, obs, log_id, tool_text=None):
    """One note per observation. A note is about the commit that holds its own work (see _commit_for; several commits can lie between two savepoints), else about the
    branch. `end` is the commit the savepoint stops at, `prev` the one the last savepoint stopped at. Its checks are worked out by code (see ground.py), so a draft that names a file or value that is not there is not shown to agents. With `tool_text` (what the
    tool uses behind the savepoint showed) the identifier-like words in its facts must also appear there, or in what the other observations of the savepoint say."""
    from . import tree
    root = repo.root.resolve().as_posix().rstrip("/") + "/"
    cache, anchors = {}, {}
    branch_a = tree.anchor_for(repo, paths=[], dirty=False, with_base=True)
    branch_a.update(sha="", tree="", parent="", patch_id="", subject="", date="", range_pid="")
    branch_a["branch"] = branch
    out = []
    for o in obs:
        mod = safety_inside([_rel(root, f) for f in o.get("files_modified", [])])  # a path outside the repository is never kept: a note is about this repo
        read = safety_inside([_rel(root, f) for f in o.get("files_read", [])])
        sha = _commit_for(repo, o, end, prev, set(mod), cache)
        about = bool(sha)
        if about and sha not in anchors:
            anchors[sha] = tree.anchor_for(repo, sha=sha, paths=[], dirty=False, with_base=True)
        a = dict(anchors[sha] if about else branch_a)
        a["paths"], a["names"] = mod, tree.names_of(mod)
        sub = o.get("subtitle") or re.split(r"(?<=[.!?])\s", o["narrative"].strip(), maxsplit=1)[0]
        facts = [f for f in o.get("facts", []) if f]
        proof = facts + ([f"changed: {', '.join(mod[:6])}"] if mod else []) + ([f"read: {', '.join(read[:6])}"] if read else [])
        body = {"summary": localize(sub[:300], root), "why": localize(o["narrative"][:2000], root)}
        if facts or mod:  # files read alone prove nothing: the note has evidence only when something was found or changed
            body["evidence"] = localize("\n".join(proof)[:2000], root)
        checks = ground.check(repo, body, o["title"], _inside(mod + read), sha or None)
        if tool_text is not None:
            others = " ".join(f"{x['title']} {x['narrative']}" for x in obs if x is not o)
            checks["unsupported"] = ground.unsupported([localize(f, root) for f in facts], tool_text + "\n" + others)  # the facts as stored: a path outside the repo cannot be looked up and must not be named here
        out.append(Entry(id=o["id"] if ID_RE.match(str(o.get("id", ""))) else new_id(), kind="finding", topic=localize(o["title"][:200], root), body=body, anchor=a,
                         provenance="worker-written", captured_via="savepoint", v=2, level="commit" if about else "branch", sources=[log_id],
                         checks=checks,
                         created=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(o.get("t") or time.time())),
                         obs={"type": o.get("type", ""), "concepts": o.get("concepts", []), "files_read": read, "files_modified": mod,
                              "session": o.get("session", ""), "t": o.get("t", 0)},
                         display=repo.cfg().get("display", "") if repo.attribution() == "named" else ""))
    return out
