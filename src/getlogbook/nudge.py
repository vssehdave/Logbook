"""The investigation nudge: a context-only reminder to record a note.

A Stop hook cannot add context for the next turn, so the Stop checkpoint measures the turn (turn_stats) and the next
prompt-time hook says something (nudge_text). It never blocks the agent, so it cannot loop; it fires at most once per
turn and NUDGE_MAX times per session, and `nudge: false` in the config turns it off.
"""
from __future__ import annotations

import contextlib
import json
import re
import time

from .store import atomic_write

INVESTIGATE = {"Read", "Grep", "Glob", "WebFetch", "WebSearch"}
EDITS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
_SEARCHY = re.compile(r"\b(grep|rg|find|cat|ls|git\s+(log|show|diff|blame|grep))\b")
_NOTING = re.compile(r"\b(?:get)?logbook\s+note\b")  # the note subcommand itself: a query that merely says "note" does not count
NUDGE_AFTER, NUDGE_MAX, BLOCK_AFTER = 6, 3, 3
BLOCK_TEXT = ("Before you finish: this turn read or searched {n} times and no logbook note was recorded. If you found a cause, ruled "
              "something out, or a decision was made, record it now with `logbook note --fields` (see the logbook skill: 3 to 9 lines, with an `evidence:` line), then give "
              "your final answer again. If nothing is worth keeping, say so in one line and finish.")
NUDGE_TEXT = ("Logbook: your last turn read or searched {n} times and recorded no note. If you learned something a teammate's "
              "agent would otherwise have to rediscover (a cause, a wrong assumption, a dead end, a decision), record it now "
              "with `logbook note --fields` (see the logbook skill: 3 to 9 lines, with an `evidence:` line). If nothing is worth keeping, ignore this.")
# With the logbook-scribe agent installed the note is written in its own context: the main agent only hands over the facts.
HANDOFF = ("hand the facts to the logbook-scribe subagent (what was asked; what you found and why; what you ran or read, with the result; the files; "
           "what was decided or left open) and use its two-line answer. Do not write the note yourself")
BLOCK_SCRIBE = BLOCK_TEXT.replace("record it now with `logbook note --fields` (see the logbook skill: 3 to 9 lines, with an `evidence:` line), then give "
                                  "your final answer again.", HANDOFF + ", then give your final answer again.")
NUDGE_SCRIBE = NUDGE_TEXT.replace("record it now with `logbook note --fields` (see the logbook skill: 3 to 9 lines, with an `evidence:` line).", HANDOFF + ".")


def scribe_installed(repo):
    try:
        return "managed-by: logbook" in (repo.root / ".claude" / "agents" / "logbook-scribe.md").read_text(encoding="utf-8")
    except OSError:
        return False


def turn_stats(data):
    """What the agent did in the transcript bytes added since the last checkpoint: how much it looked, and whether it noted."""
    reads = edits = 0
    noted = False
    for line in data.decode("utf-8", "replace").splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        m = o.get("message") if isinstance(o, dict) else None
        if not isinstance(m, dict) or o.get("type") != "assistant" or not isinstance(m.get("content"), list):
            continue
        for b in m["content"]:
            if not isinstance(b, dict) or b.get("type") != "tool_use":
                continue
            name = b.get("name", "")
            cmd = str((b.get("input") or {}).get("command", "")) if name == "Bash" else ""
            if _NOTING.search(cmd) or (name in ("Agent", "Task") and (b.get("input") or {}).get("subagent_type") == "logbook-scribe"):
                noted = True  # the scribe writes its note in its own context, so the main transcript only shows the hand-off
            elif name in INVESTIGATE or (name == "Bash" and _SEARCHY.search(cmd)):
                reads += 1
            elif name in EDITS:
                edits += 1
    return {"reads": reads, "edits": edits, "noted": noted, "nudged": False}


def add_stats(old, new):
    """A turn spans several checkpoints (PreCompact, a second Stop after a block): its counts add up, and `nudged` is kept."""
    old = old or {}
    return {"reads": old.get("reads", 0) + new["reads"], "edits": old.get("edits", 0) + new["edits"],
            "noted": bool(old.get("noted")) or new["noted"], "nudged": bool(old.get("nudged"))}


def new_turn(repo, session):
    """A prompt arrived: the turn that was counting is over, the next one starts from zero."""
    from . import capture
    d = repo.cdir / "sessions" / capture._sid(session)
    if not session or not (d / "state.json").exists():
        return
    with capture._lock(d / ".lock") as ok:
        if ok:
            st = capture._load(d)
            st["turn"] = {}
            atomic_write(d / "state.json", json.dumps(st))


def _claim(repo, session, threshold):
    """Reads in the last turn if it earns a reminder (investigated, no note, not yet reminded, under the cap); marks it said."""
    from . import capture
    if not session:
        return 0
    d = repo.cdir / "sessions" / capture._sid(session)
    if not (d / "state.json").exists():
        return 0
    with capture._lock(d / ".lock") as ok:
        if not ok:
            return 0
        st = capture._load(d)
        turn = st.get("turn") or {}
        if turn.get("nudged") or turn.get("noted") or turn.get("reads", 0) < threshold or st.get("nudges", 0) >= NUDGE_MAX:
            return 0
        turn["nudged"] = True
        st["turn"], st["nudges"] = turn, st.get("nudges", 0) + 1
        atomic_write(d / "state.json", json.dumps(st))
    with contextlib.suppress(OSError):
        with open(repo.cdir / "nudges.log", "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": int(time.time()), "session": capture._sid(session), "reads": turn.get("reads", 0)}) + "\n")
    return turn.get("reads", 0)


def mode(repo):
    """'block' (default), 'context' or 'off'. Measured on a small task: with block the agent wrote a note in 4 of 4 runs,
    with a reminder only in 1 of 4, and with neither in 0 of 4."""
    v = repo.cfg().get("nudge", "block")
    return "off" if v is False else "context" if v in (True, "context") else "block"


def nudge_text(repo, session):
    """The reminder for this prompt, or ''. Said once per turn."""
    if mode(repo) == "off":
        return ""
    n = _claim(repo, session, int(repo.cfg().get("nudge_after", NUDGE_AFTER)))
    return (NUDGE_SCRIBE if scribe_installed(repo) else NUDGE_TEXT).format(n=n) if n else ""


def stop_block(repo, payload):
    """Block mode only: ask the agent to record a note before it finishes, once. `stop_hook_active` is true on the stop that
    follows our own block, so this cannot loop."""
    if mode(repo) != "block" or payload.get("stop_hook_active"):
        return ""
    n = _claim(repo, str(payload.get("session_id", "")), int(repo.cfg().get("block_after", BLOCK_AFTER)))
    return json.dumps({"decision": "block", "reason": (BLOCK_SCRIBE if scribe_installed(repo) else BLOCK_TEXT).format(n=n)}) if n else ""


def join(*parts):
    return "\n".join(p for p in parts if p)
