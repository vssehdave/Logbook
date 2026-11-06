"""The conversation behind a log: what the person typed and what the agent answered, and nothing else.

Two hooks feed it, with no model and no git process: the prompt hook (the person's own words) and the stop hook (the agent's final visible reply of the turn,
`last_assistant_message`). Thinking, tool calls and tool output never reach this file because neither payload carries them, and text a tool or the harness injected
(a task notice, a system reminder) is skipped. Everything is redacted before it is written, so a secret pasted into a prompt is not stored at all.

    .git/logbook/running/<branch>/talk.jsonl   one line per message, only ever appended
    .git/logbook/convo/<log id>.jsonl          the messages one savepoint covers, trimmed to fit (private)
    convo/<log id>.jsonl                       the same in the shared tree, written by `logbook publish` next to the log, redacted again

A conversation too long for the cap keeps its beginning and its end and says how many messages were left out. Git compresses what it stores, so the size that
matters is the text: a cap per conversation and a cap on all of one person's conversations bound what the repository grows by.
"""
from __future__ import annotations

import json
import os
import time

from . import running
from .safety import looks_tabular, redact
from .store import MAX_CONVO, atomic_write

MAX_MSG = 6000  # characters of one message kept (the start and the end of it)
SKIP = ("<task-notification", "<system-reminder", "<command-", "<local-command")  # what the harness or a tool injects as a "prompt"
ROLES = {"UserPromptSubmit": "user", "Stop": "assistant"}


def _trim(text, cap=MAX_MSG):
    if len(text) <= cap:
        return text
    keep = cap * 2 // 3
    return text[:keep] + f"\n[... {len(text) - cap} characters left out ...]\n" + text[-(cap - keep):]


def _path(run):
    return run.dir / "talk.jsonl"


def record(repo, event, payload):
    """Append what the person typed (UserPromptSubmit) or the agent's final reply (Stop) to the branch's talk file. Never raises for a bad payload."""
    from . import worker
    role = ROLES.get(event)
    cfg = repo.cfg()
    if not role or not worker.is_on(cfg):  # the same switch as the observer: `logbook config worker off` stops the collecting
        return
    text = payload.get("prompt") if role == "user" else payload.get("last_assistant_message")
    if not isinstance(text, str) or not text.strip():
        return
    if role == "user" and text.lstrip().startswith(SKIP):
        return
    branch, _ = running.branch_now(repo)
    if branch == "HEAD":
        return
    text, _ = redact(_trim(text.strip()), cfg.get("deny", []))
    run = running.Running(repo, branch)
    run.dir.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"t": int(time.time()), "session": str(payload.get("session_id", ""))[:80], "prompt": str(payload.get("prompt_id", ""))[:40],
                       "role": role, "text": text}, ensure_ascii=False) + "\n"
    fd = os.open(_path(run), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)  # one write on an append-only file: two sessions cannot interleave a line
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def since(run, offset=0):
    """(messages, offset after them): the whole lines of the talk file past `offset`."""
    try:
        with open(_path(run), "rb") as f:
            f.seek(offset)
            raw = f.read()
    except OSError:
        return [], offset
    end = raw.rfind(b"\n") + 1  # a line still being written waits
    out = []
    for line in raw[:end].splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if isinstance(m, dict) and m.get("role") in ("user", "assistant") and isinstance(m.get("text"), str):
            out.append(m)
    return out, offset + end


def fit(messages, cap=MAX_CONVO):
    """The messages as lines of JSON, within `cap` bytes: the first and the last messages that fit, with one line saying how many were left out between them."""
    lines = [json.dumps(m, ensure_ascii=False) for m in messages]
    if sum(len(x.encode("utf-8")) + 1 for x in lines) <= cap:
        return lines
    half = (cap - 200) // 2  # room for the line that says what was left out
    head, tail, used = [], [], 0
    for x in lines:
        used += len(x.encode("utf-8")) + 1
        if used > half:
            break
        head.append(x)
    used = 0
    for x in reversed(lines[len(head):]):
        used += len(x.encode("utf-8")) + 1
        if used > half:
            break
        tail.append(x)
    left = len(lines) - len(head) - len(tail)
    gap = json.dumps({"role": "gap", "text": f"[{left} message{'s' if left != 1 else ''} left out to keep this log small]"})
    return head + [gap] + tail[::-1]


def private_path(repo, log_id):
    return repo.cdir / "convo" / f"{log_id}.jsonl"


def save(repo, log_id, messages):
    """Keep the conversation a savepoint covers, privately. Returns the number of messages stored (0 when there were none)."""
    if not messages:
        return 0
    lines = fit(messages)
    atomic_write(private_path(repo, log_id), "\n".join(lines) + "\n")
    return len(lines)


def parse(data):
    out = []
    for line in (data.decode("utf-8", "replace") if isinstance(data, bytes) else data).splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if isinstance(m, dict) and isinstance(m.get("text"), str):
            out.append(m)
    return out


def load(repo, log_id):
    """The messages of a log's conversation: the private copy, else the shared one (yours, or a teammate's after a sync). [] when there is none."""
    try:
        return parse(private_path(repo, log_id).read_text(encoding="utf-8"))
    except OSError:
        return parse(repo.shared_convo(log_id) or b"")


def shareable(repo, log_id, allow_table=False):
    """(bytes to publish, findings, message count) for a log's private conversation, redacted again with today's deny list, or None when it has none.
    Pasted table rows are replaced, not published (unless allowed)."""
    msgs = load_private(repo, log_id)
    if not msgs:
        return None
    deny, found, out = repo.cfg().get("deny", []), [], []
    for m in msgs:
        text, f = redact(m["text"], deny)
        found += f
        if not allow_table and looks_tabular(text):
            text, found = "[pasted rows left out]", found + ["table-rows"]
        out.append({**{k: m[k] for k in ("t", "session", "prompt", "role") if k in m}, "text": text})
    lines = fit(out)
    return ("\n".join(lines) + "\n").encode("utf-8"), found, len(lines)


def load_private(repo, log_id):
    try:
        return parse(private_path(repo, log_id).read_text(encoding="utf-8"))
    except OSError:
        return []
