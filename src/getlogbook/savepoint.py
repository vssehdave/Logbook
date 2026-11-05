"""Savepoints: `logbook log` turns what the observer collected on a branch since the last savepoint into one stored log.

A stored log is an ordinary private entry of kind `log`. It always carries the branch; it carries a commit only when one was made since the last savepoint.
The summary comes from the same cheap model as the observations, or, with no model to ask, is put together from the observations by code. Its fields use the
entry body fields older versions already know: request -> context, completed -> what, learned -> why, investigated -> evidence, next steps -> open.
The observations it covers move to `running/<branch>/archive/`; observations inherited from the parent branch stay where they are.
"""
from __future__ import annotations

import json
import re
import sys
import time

from . import capture, observer, running, worker
from .entry import ID_RE, MAX_LIST, Entry, new_id
from .safety import redact

WAIT = 150  # seconds a savepoint waits for an observer pass already running (it holds the lock across its model calls) before it gives up
AUTO_MIN = 5  # auto mode saves after a commit once this many new observations have piled up
PROMPT_OBS = 60  # observations shown to the model
SYSTEM = """You write the savepoint for a coding session on the git branch `{branch}`. You cannot use tools. Below are the observations recorded since the last savepoint, oldest first. Summarize them for a teammate, or a later session, who has not seen the work.

Use only the observations: do not guess a cause and do not add anything they do not say. Do not copy secrets, tokens, email addresses or pasted data rows. Leave a field empty rather than invent it. Answer with exactly:

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


def ask_block(repo, payload):
    """Ask mode: when a commit follows enough new observations, tell the agent once (per commit) to ask the person whether to save a log. `stop_hook_active`
    is true on the stop that follows our own block, so this cannot loop."""
    if repo.publish_mode() != "ask" or payload.get("stop_hook_active"):
        return ""
    branch, head = running.branch_now(repo)
    run = running.Running(repo, branch)
    if branch == "HEAD" or not due(repo, branch, head):
        return ""
    marker = run.dir / "asked"
    try:
        if marker.read_text(encoding="utf-8").strip() == head:
            return ""
    except OSError:
        pass
    running.atomic_write(marker, head)
    n = len(own(run))
    return json.dumps({"decision": "block", "reason": f"You committed after {n} recorded observations on branch {branch}. In one short sentence, ask the user whether to save a log of this work "
                       "(`logbook log`; it stays private until they publish it). If they say yes, run `logbook log` and tell them the result in a line. If they say no, say nothing more."})


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
def save(repo, branch, call=worker.call_model, now=time.time, use_model=True, observe=True):
    """Make one savepoint. Returns {"saved": entry id, ...} or {"skipped": reason}; never raises for a model problem."""
    if branch == "HEAD":
        return {"skipped": "HEAD is detached: check out a branch first"}
    if observe and worker.enabled(repo):
        observer.drain(repo, branch, flush=True, call=call, now=now, wait=WAIT)  # tool uses still in the queue belong in this savepoint
    run = running.Running(repo, branch)
    with capture._lock(worker._wdir(repo) / ".lock", timeout=WAIT, stale=worker.LOCK_STALE) as got:
        if not got:
            return {"skipped": "the observer is busy; try again in a moment"}
        obs = own(run)
        if not obs:
            return {"skipped": "nothing new since the last savepoint"}
        head = running.branch_now(repo)[1]
        sha = head if commit_made(run, obs, head) else ""
        fields, how = summarize(repo, branch, obs, call, now) if use_model else (fallback(obs), "code")
        e = _entry(repo, branch, sha, obs, fields)
        repo.add_private(e)
        covered = {o["id"] for o in obs}
        keep = [o for o in run.observations() if o["id"] not in covered]  # a pass may have appended since: only the covered ones leave
        if run.obs.exists():
            run.archive(e.id, [o for o in run.observations() if o["id"] in covered])
            run.rewrite(keep)
        running.atomic_write(_state_path(run), json.dumps({"id": e.id, "head": head, "t": int(now())}))
    if repo.cfg().get("tidy") == "auto":  # a new log is a moment to tidy: judge changed notes and fold old logs, in the background
        capture.spawn_detached([repo.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", "tidy", "--work", "--quiet"], repo.root)
    return {"saved": e.id, "branch": branch, "commit": sha, "observations": len(covered), "title": e.topic, "by": how}


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
