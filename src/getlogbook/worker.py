"""The background worker: one model pass per finished turn that turns the transcript into private notes.

Opt-in (`logbook config worker on`). After a turn ends, a detached process reads the transcript bytes added since its last pass, asks a cheap model
(through the person's own `claude -p`, so no key is stored) for the few things worth keeping, and writes them as PRIVATE notes labelled
`worker-written`, anchored to the branch and commit like any note. It never publishes. A note is kept only when Python can check it: it has evidence that
appears in the transcript, it names nothing that is not in the repo, it is the right size, and it does not repeat a note that already exists.

Cost is bounded three ways: a turn with little activity is skipped without a call, the transcript sent is capped, and there is a daily call cap. When the
model says the usage allowance is gone the worker backs off for an hour, so it does not compete with the person's own session. Its own `claude -p` runs
with the guard variable set, from an empty directory, with settings, MCP servers and slash commands off, so Logbook's hooks ignore it.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from . import capture, ground, nudge
from .entry import BODY_FIELDS
from .safety import redact
from .store import atomic_write

GUARD = "LOGBOOK_WORKER"  # set on the worker's own claude run: every Logbook hook returns at once when it is present
MODEL = "haiku"
MAX_CHARS = 60000  # transcript characters sent per pass (the newest are kept)
MAX_CALLS = 40  # model calls per day
MAX_NOTES = 3  # notes taken from one pass
MIN_ACTIVITY = 2  # reads plus edits in the turn below which no call is made
COOLDOWN = 3600  # seconds to stay quiet after the usage allowance runs out
TIMEOUT = 240
_QUOTA = re.compile(r"usage (allowance|limit)|rate.?limit|quota|exhausted|overloaded|too many requests", re.I)
_NOISE = re.compile(r"<(system-reminder|logbook-notes|claude-mem[\w-]*|local-command-[\w-]+)>.*?</\1>", re.S)
FLAGS = ["--output-format", "json", "--no-session-persistence", "--tools", "", "--strict-mcp-config", "--disable-slash-commands", "--setting-sources", ""]

PROMPT = """You keep the private notebook for a person's coding sessions. Below is what happened in one turn of a session: their messages, Claude's replies and the tools it used.

Write 0 to 3 notes worth keeping for a future session on this repo: a root cause found, an approach ruled out and why, a decision made and the reason, a non-obvious fact about the code.
Not a recap of the turn, not chores, not what the diff already says. Most turns have nothing: then answer exactly NONE.

Each note is `key: value` lines, notes separated by a line of ---:
kind: finding
topic: short title
summary: 2 to 4 sentences: what was found and why it matters
why: the cause or the reason
evidence: a command and its result, or file:line, that you SAW in the transcript below; quote it
decided: the choice made and what was rejected, only if there was one
open: what is still unknown, only if something is
paths: files this is about that exist in the repo, comma separated

Rules: only what the transcript shows; never guess a cause; 3 to 9 lines per note; no secrets, tokens, emails or pasted data rows; if you cannot quote evidence, leave the note out.

TRANSCRIPT
"""


# ---- reading the transcript ----------------------------------------------------------------------------------
def _text_of(content):
    if isinstance(content, str):
        return content
    return " ".join(b.get("text", "") for b in content or [] if isinstance(b, dict) and b.get("type") == "text")


def condense(data, limit=MAX_CHARS):
    """The transcript bytes as short lines a model can read: what was said, the tool calls and the start of each result. The newest `limit` characters."""
    out = []
    for raw in data.decode("utf-8", "replace").splitlines():
        try:
            o = json.loads(raw)
        except ValueError:
            continue
        m = o.get("message") if isinstance(o, dict) else None
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        blocks = [{"type": "text", "text": c}] if isinstance(c, str) else [b for b in c if isinstance(b, dict)] if isinstance(c, list) else []
        for b in blocks:
            kind = b.get("type")
            if kind == "text":
                txt = _NOISE.sub("", b.get("text", "")).strip()
                if txt:
                    out.append(("USER: " if m.get("role") == "user" else "CLAUDE: ") + txt[:1500])
            elif kind == "tool_use":
                i = b.get("input") or {}
                brief = i.get("command") or i.get("file_path") or i.get("pattern") or i.get("path") or ""
                if b.get("name") in nudge.EDITS and i.get("new_string"):
                    brief = f"{brief}: {str(i['new_string'])[:200]}"
                out.append(f"TOOL {b.get('name', '')}: {str(brief)[:300]}")
            elif kind == "tool_result":
                out.append("RESULT: " + _text_of(b.get("content")).strip()[:400].replace("\n", " | "))
    text = "\n".join(out)
    return text if len(text) <= limit else "[earlier part cut]\n" + text[-limit:]


# ---- the model -----------------------------------------------------------------------------------------------
def call_model(prompt, model=MODEL):
    """(text, cost in USD, error). Runs the person's own `claude -p`: from an empty directory, with the guard set, without settings, MCP servers or tools."""
    env = dict(os.environ, **{GUARD: "1"})
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    with tempfile.TemporaryDirectory(prefix="logbook-worker-") as d:
        try:
            p = subprocess.run(["claude", "-p", "--model", os.environ.get("LOGBOOK_WORKER_MODEL", model), *FLAGS], input=prompt, cwd=d, env=env,
                               capture_output=True, text=True, encoding="utf-8", timeout=TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as ex:
            return "", 0.0, f"could not run claude: {ex}"
    try:
        j = json.loads(p.stdout)
    except ValueError:
        return "", 0.0, (p.stdout + p.stderr).strip()[:300] or f"claude exited {p.returncode}"
    if p.returncode or j.get("is_error"):
        return "", float(j.get("total_cost_usd") or 0), str(j.get("result") or p.stderr)[:300]
    return str(j.get("result") or ""), float(j.get("total_cost_usd") or 0), ""


# ---- what the model said --------------------------------------------------------------------------------------
def parse_notes(text):
    """The note blocks in the model's answer as dicts (kind, topic, paths and the body fields), [] for NONE."""
    from . import cli  # the same key: value reading as `logbook note --fields`
    if not text.strip() or text.strip().upper().startswith("NONE"):
        return []
    blocks, cur = [], []
    for line in text.splitlines() + ["---"]:
        if line.strip() == "---":
            if cur:
                blocks.append("\n".join(cur))
            cur = []
        else:
            cur.append(line)
    return [cli._parse_fields(b) for b in blocks if b.strip()][:MAX_NOTES * 2]


def check(repo, note, transcript, views):
    """(entry fields, '') for a note worth keeping, or (None, why not). Everything Python can verify is verified here."""
    body = {k: str(note[k])[:1000] for k in BODY_FIELDS if note.get(k)}
    topic = str(note.get("topic") or body.get("summary", ""))[:200]
    if not body.get("summary") or not body.get("evidence"):
        return None, "no summary or no evidence"
    if not any(tok in transcript for tok in re.findall(r"[\w./\\-]{6,}", body["evidence"])):
        return None, "its evidence is not in the transcript"
    kind = note.get("kind") if note.get("kind") in ("finding", "change") else "finding"
    if ground.size_problems(kind, body):
        return None, "wrong size"
    paths = [p for p in (note.get("paths") or []) if p]
    cks = ground.check(repo, body, topic, paths)
    if cks["missing"]:
        return None, "it names something that is not in the repo: " + ", ".join(cks["missing"][:3])
    by_id = {v["id"]: v for v in views}
    supersedes = []
    for o in ground.overlaps(views, topic, body["summary"], cks["files"]):
        if o["mine"] and by_id[o["id"]]["provenance"] == "worker-written":
            supersedes.append(o["id"])  # the worker is updating its own earlier observation
        else:
            return None, "a note about this already exists"
    return {"kind": kind, "topic": topic, "body": body, "paths": cks["files"] or None, "checks": cks, "supersedes": supersedes}, ""


# ---- the ledger: what it has spent, and when to stay quiet -------------------------------------------------------
def _wdir(repo):
    return repo.cdir / "worker"


def ledger(repo):
    try:
        led = json.loads((_wdir(repo) / "ledger.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        led = {}
    day = time.strftime("%Y-%m-%d")
    if led.get("day") != day:
        led.update(day=day, calls=0, cost=0.0)
    for k, v in (("notes", 0), ("cooldown_until", 0), ("last_error", ""), ("last_run", 0), ("skipped", "")):
        led.setdefault(k, v)
    return led


def _save(repo, led):
    _wdir(repo).mkdir(parents=True, exist_ok=True)
    atomic_write(_wdir(repo) / "ledger.json", json.dumps(led))


def enabled(repo):
    return repo.cfg().get("worker") == "on" and not os.environ.get(GUARD)


# ---- one pass -------------------------------------------------------------------------------------------------
LOG_LINES = 200


def run(repo, session, call=call_model, now=time.time):
    """One pass, and a line in worker/log.jsonl saying what happened (a skipped pass leaves no other trace)."""
    res = _run(repo, session, call, now)
    try:
        p = _wdir(repo) / "log.jsonl"
        _wdir(repo).mkdir(parents=True, exist_ok=True)
        old = p.read_text(encoding="utf-8").splitlines()[-(LOG_LINES - 1):] if p.exists() else []
        atomic_write(p, "\n".join(old + [json.dumps({"t": int(now()), "session": capture._sid(session)[:12], **{k: v for k, v in res.items() if k != "dropped"}, **({"dropped": res["dropped"]} if res.get("dropped") else {})})]) + "\n")
    except OSError:
        pass
    return res


def last_pass(repo):
    try:
        return json.loads((_wdir(repo) / "log.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    except (OSError, ValueError, IndexError):
        return {}


def _run(repo, session, call, now):
    """One pass over the new part of a session's transcript. Returns what happened as a dict; never raises for a model or network problem."""
    if not enabled(repo):
        return {"skipped": "worker is off"}
    d = repo.cdir / "sessions" / capture._sid(session)
    cfg = repo.cfg()
    with capture._lock(_wdir(repo) / ".lock", timeout=0.2) as got:
        if not got:
            return {"skipped": "another pass is running"}
        led = ledger(repo)
        if now() < led["cooldown_until"]:
            return {"skipped": "waiting after the usage allowance ran out"}
        if led["calls"] >= int(cfg.get("worker_calls", MAX_CALLS)):
            return {"skipped": "today's call cap is reached"}
        st = capture._load(d)
        start = int(st.get("worked", 0))
        data = b"".join(sl.read_bytes() for sl in sorted(d.glob("slice-*.jsonl")) if int(sl.stem.split("-")[1]) >= start)
        if not data:
            return {"skipped": "nothing new"}
        stats = nudge.turn_stats(data)
        if stats["reads"] + stats["edits"] < MIN_ACTIVITY:
            st["worked"] = st["offset"]
            atomic_write(d / "state.json", json.dumps(st))
            return {"skipped": "a quiet turn"}
        transcript = condense(data, int(cfg.get("worker_chars", MAX_CHARS)))
        sent, _ = redact(transcript, cfg.get("deny", []))
        text, cost, error = call(PROMPT + sent)
        led.update(calls=led["calls"] + 1, cost=round(led["cost"] + cost, 6), last_run=int(now()), last_error=error[:300])
        if error:
            if _QUOTA.search(error):
                led["cooldown_until"] = now() + COOLDOWN
            _save(repo, led)
            return {"error": error[:200]}  # the offset stays, so the next pass tries these bytes again
        from . import tree
        views = [v for v in tree.all_views(repo)[0] if not v.get("is_status")]
        kept, dropped = [], []
        for note in parse_notes(text):
            if len(kept) >= MAX_NOTES:
                break
            fields, why = check(repo, note, transcript, views)
            if not fields:
                dropped.append(why)
                continue
            e = capture.make_entry(repo, fields["kind"], fields["topic"], fields["body"], paths=fields["paths"], provenance="worker-written", via="worker",
                                   supersedes=fields["supersedes"], checks=fields["checks"])
            kept.append(e.id)
            views.append({"id": e.id, "topic": e.topic, "mine": True, "provenance": "worker-written", "kind": e.kind, "paths": e.anchor.get("paths", []),
                          "body": e.body})  # so a second note in this pass is compared with the first
        st["worked"] = st["offset"]
        atomic_write(d / "state.json", json.dumps(st))
        led["notes"] += len(kept)
        _save(repo, led)
        done = {"notes": kept, "dropped": dropped, "cost": cost}
    if repo.cfg().get("tidy") == "auto":
        from . import tidy
        done["archived"] = tidy.auto(repo)
    return done


def status(repo):
    led = ledger(repo)
    return {"worker": "on" if repo.cfg().get("worker") == "on" else "off", "tidy": repo.cfg().get("tidy", "manual"), "calls_today": led["calls"],
            "cost_today": led["cost"], "notes_written": led["notes"], "cooling_down": time.time() < led["cooldown_until"], "last_error": led["last_error"],
            "last_pass": last_pass(repo)}
