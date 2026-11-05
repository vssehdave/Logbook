"""The observer: turns the tool uses of a session into observations in the running log of the branch they happened on.

A hook queues every tool use (no model, no git process). A detached process reads the queue in batches, shows a cheap model the batch together with the last few
observations already written (so it does not write the same thing twice), and stores what it answers. Each call is stateless: the window of earlier observations
stands in for a long conversation, which measured cheaper (a flat 0.0009 USD a call, against a price that rose with every call as a conversation grew).

An observation is a short record of something learned, found, decided, built, fixed or changed: a type, a title, a one-line subtitle, self-contained facts, a
narrative, concepts and the files read and modified. Nothing here is shared; `logbook log` turns the running log into a stored log.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import sys
import time

from . import capture, running, worker
from .entry import new_id
from .safety import redact

OBS_TYPES = ("bugfix", "feature", "refactor", "change", "discovery", "decision")
CONCEPTS = ("how-it-works", "why-it-exists", "what-changed", "problem-solution", "gotcha", "pattern", "trade-off")
BATCH_EVENTS = 12  # tool uses per model call
BATCH_CHARS = 24000  # characters of tool input and output per call
MIN_BATCH = 4  # a pass that is not a flush waits until this many tool uses are queued
MAX_PASS_CALLS = 3  # calls in one background pass; the rest waits for the next
TRIGGER_BYTES = 9000  # queued bytes after which a tool use starts a pass
WINDOW = 8  # earlier observations shown to the model

SYSTEM = """You are the quiet note-taker for a coding session on the git branch `{branch}`. You are not doing the work and you cannot use tools. You read what the session did and write down what is worth remembering for later sessions on this repo.

Each batch below holds tool uses from the session: the tool, its input and its output. Turn them into observations about what was learned, found, decided, built, fixed or changed. Say what the code or the system now does, or what is now known, not what you are doing: "total() now skips refunded orders", not "looked at the revenue code".

Skip routine work: listing files, searches that find nothing, reads that lead nowhere, installs without errors, and anything already in the ALREADY RECORDED list (never write the same thing again, even in other words). If a batch holds nothing worth keeping, answer with exactly: <skip reason="short reason" />

Use only what the tool uses show. Do not guess a cause. Do not copy secrets, tokens, email addresses or pasted data rows. A batch gives zero to four observations. Each one is:

<observation>
  <type>one of: {types}</type>
  <title>a short title</title>
  <subtitle>one sentence</subtitle>
  <facts><fact>one self-contained fact, no pronouns, with the file or function name</fact></facts>
  <narrative>what happened or was learned, and why it matters</narrative>
  <concepts><concept>zero or more of: {concepts}</concept></concepts>
  <files_read><file>path from the project root</file></files_read>
  <files_modified><file>path from the project root</file></files_modified>
</observation>
"""


# ---- the hook side -------------------------------------------------------------------------------------------
def on_tool_use(repo, payload):
    """A PostToolUse hook: queue the tool use on the branch it happened on, and start a pass once enough has piled up. No model call, no git process."""
    cfg = repo.cfg()
    if not worker.is_on(cfg) or not worker.available():
        return
    branch, head = running.branch_now(repo)
    ev = running.event_from_payload(payload, branch, head)
    if ev is None:
        return
    run = running.Running(repo, branch)
    if run.push(ev) and run.pending_bytes() >= TRIGGER_BYTES:
        spawn_pass(repo, branch)


def spawn_pass(repo, branch, flush=False):
    cfg = repo.cfg()
    capture.spawn_detached([cfg.get("interpreter") or sys.executable, "-m", "getlogbook", "worker", "--drain", "--branch", branch] + (["--flush"] if flush else []), repo.root)


# ---- the model side ------------------------------------------------------------------------------------------
def build_prompt(branch, window, events):
    lines = ["ALREADY RECORDED (oldest first):"] + ([f"- [{o['type']}] {o['title']}: {o['narrative'][:160]}" for o in window] or ["(nothing yet)"]) + ["", "TOOL USES:"]
    for i, ev in enumerate(events, 1):
        lines.append(f'<tool_use n="{i}" tool="{ev["tool"]}"{" failed" if ev.get("failed") else ""}>\ninput: {ev["input"]}\noutput: {ev["output"]}\n</tool_use>')
    return SYSTEM.format(branch=branch, types=", ".join(OBS_TYPES), concepts=", ".join(CONCEPTS)) + "\n" + "\n".join(lines) + "\n"


def _tag(block, name):
    m = re.search(rf"<{name}>(.*?)</{name}>", block, re.S)
    return html.unescape(m.group(1)).strip() if m else ""


def _items(block, outer, inner):
    return [html.unescape(x).strip() for x in re.findall(rf"<{inner}>(.*?)</{inner}>", _tag_raw(block, outer), re.S) if x.strip()]


def _tag_raw(block, name):
    m = re.search(rf"<{name}>(.*?)</{name}>", block, re.S)
    return m.group(1) if m else ""


def parse(text):
    """The observations in a model answer (dicts without ids); [] for a skip. Tolerant of missing fields, strict about what it keeps."""
    out = []
    for block in re.findall(r"<observation>(.*?)</observation>", text, re.S):
        title, narrative = _tag(block, "title")[:200], _tag(block, "narrative")[:1200]
        if not title or not narrative:
            continue
        typ = _tag(block, "type").lower()
        out.append({"type": typ if typ in OBS_TYPES else "change", "title": title, "subtitle": _tag(block, "subtitle")[:300],
                    "facts": [f[:300] for f in _items(block, "facts", "fact")][:8], "narrative": narrative,
                    "concepts": [c for c in _items(block, "concepts", "concept") if c in CONCEPTS],
                    "files_read": [f[:200] for f in _items(block, "files_read", "file")][:10], "files_modified": [f[:200] for f in _items(block, "files_modified", "file")][:10]})
    return out


def digest(o):
    """What makes two observations the same: their type, title and narrative, ignoring case and spacing."""
    return hashlib.sha1(" ".join((o["type"] + " " + o["title"] + " " + o["narrative"]).lower().split()).encode("utf-8")).hexdigest()[:16]


def drain(repo, branch, flush=False, call=worker.call_model, now=time.time):
    """Observe what is queued on a branch, a few batches at most. Returns what happened and logs it; never raises for a model or network problem."""
    res = _drain(repo, branch, flush, call, now)
    worker.log_pass(repo, branch, {"branch": branch[:60], **res}, now)
    return res


def _drain(repo, branch, flush, call, now):
    if not worker.enabled(repo):
        return {"skipped": "the observer is off"}
    cfg = repo.cfg()
    with capture._lock(worker._wdir(repo) / ".lock", timeout=0.2) as got:
        if not got:
            return {"skipped": "another pass is running"}
        led = worker.ledger(repo)
        if now() < led["cooldown_until"]:
            return {"skipped": "paused: " + (led.get("pause_reason") or "waiting after the usage allowance ran out")}
        run = running.Running(repo, branch)
        from . import tree
        run.fork_from(tree.default_branch(repo))
        batch = int(cfg.get("worker_batch", BATCH_EVENTS))
        kept, dropped, calls, spent, why = [], 0, 0, 0.0, ""
        while calls < MAX_PASS_CALLS:
            if led["calls"] >= int(cfg.get("worker_calls", worker.MAX_CALLS)):
                why = "today's call cap is reached"
                break
            events, new_off = run.take(batch, BATCH_CHARS)
            if not events or (len(events) < MIN_BATCH and not flush):
                break
            window = [o for o in run.observations()][-WINDOW:]
            sent, _ = redact(build_prompt(branch, window, events), cfg.get("deny", []))
            text, cost, error = call(sent)
            calls += 1
            spent += cost
            worker.settle(repo, led, cost, error, now)
            if error:
                return {"error": error[:200], "calls": calls}  # the cursor stays, so the next pass reads these tool uses again
            seen = {o.get("hash") for o in run.observations()}
            fresh = []
            for o in parse(text):
                h = digest(o)
                if h in seen:
                    dropped += 1
                    continue
                seen.add(h)
                last = events[-1]
                fresh.append({"id": new_id(), "branch": branch, "head": last.get("head", ""), "session": last.get("session", ""), "prompt": last.get("prompt", ""),
                              "t": last["t"], "hash": h, **o})
            run.add(fresh)
            run.advance(new_off)
            kept += [o["id"] for o in fresh]
            if now() < led["cooldown_until"]:
                break  # that call showed a usage window at its limit: the rest waits for the reset
        led["notes"] += len(kept)
        worker.save(repo, led)
    if not calls:
        return {"skipped": why or ("not enough queued yet" if run.pending_bytes() else "nothing queued")}
    return {"observations": kept, "repeats": dropped, "calls": calls, "cost": round(spent, 6)}
