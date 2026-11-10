"""Citations: the numbered sources behind an answer.

When notes are put in front of an agent they get a number that stays the same for the rest of that chat (¹, ², ³ ...), kept in
the library (tables `chat` and `cite`: a chat is open while it goes and archived when its session ends). The agent cites a note by writing its number after the claim. This module turns a number back
into what a reader needs: the header, a link to the commit or pull request, who wrote it and when.

A link and an author are shown only for notes a teammate shared. Your own notes and private notes need no source line. A shared note
with no commit says "Note added by <name> on <date>".
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import git as g
from .safety import sanitize

_SAFE = re.compile(r"[^A-Za-z0-9_-]")
_REMOTE = re.compile(r"^(?:ssh://)?(?:git@|https?://)(?:[^@/]+@)?([^/:]+)[:/](.+?)(?:\.git)?/?$")
_PR = re.compile(r"\(#(\d+)\)|^Merge pull request #(\d+)")
SUP = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")


def sup(n):
    return str(n).translate(SUP)


def _chat(session):
    return _SAFE.sub("", session or "") or "none"


def peek(repo, session, note_id):
    """The number a note has in this chat, or the one it would get, without recording anything."""
    return repo.db.cite_peek(_chat(session), note_id)


def number(repo, session, note_id, branch=""):
    """The number of a note in this chat, giving it the next one the first time it is shown (and opening the chat, with the branch it is on)."""
    return repo.db.cite_number(_chat(session), note_id, branch)


def archive(repo, session):
    """The session ended: its citations page is kept, marked archived (it opens again if the chat is resumed and cites something)."""
    if session:
        repo.db.end_chat(_chat(session))


def status(repo, session):
    """'open', 'archived', or '' for a chat with no citations."""
    return repo.db.chat_status(_chat(session))


def latest_session(repo):
    return repo.db.latest_chat()


_RUNS = re.compile("[⁰¹²³⁴⁵⁶⁷⁸⁹]+")


def transcript_path(session):
    """Claude Code's transcript of a chat: <config dir>/projects/<project>/<session>.jsonl, the config dir being CLAUDE_CONFIG_DIR or ~/.claude."""
    safe = _SAFE.sub("", session or "")
    if not safe:
        return None
    base = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "projects"
    return next(base.glob(f"*/{safe}.jsonl"), None)


def _clean(s):
    return re.sub(r"\s+", " ", s)  # runs of whitespace become one space; the edges keep theirs, so "²" and the next word stay apart


def hits(session, n):
    """The answers in this chat that cite number n, oldest first, from the transcript, so it does not matter what is on screen:
    [{uuid, before, after}], the uuid being the row's id (what a client scrolls to) and before/after the words around the citation.
    A run of superscript digits counts only when it is exactly n: the citation 2 is not part of 22 or 12."""
    path = transcript_path(session)
    if path is None:
        return []
    mark, out = sup(n), []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    for line in lines:
        if '"type":"assistant"' not in line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("type") != "assistant" or d.get("isSidechain") or not isinstance(d.get("uuid"), str):
            continue
        content = (d.get("message") or {}).get("content")
        text = content if isinstance(content, str) else " ".join(b.get("text", "") for b in content or [] if isinstance(b, dict) and b.get("type") == "text")
        run = next((m for m in _RUNS.finditer(text) if m.group(0) == mark), None)
        if run:
            out.append({"uuid": d["uuid"], "before": _clean(text[max(0, run.start() - 70):run.start()]),
                        "after": _clean(text[run.end():run.end() + 40])})
    return out


def web_url(repo, kind, ident):
    """Link to a commit or a pull request on GitHub, GitLab or Bitbucket; '' elsewhere. For another host, or a local remote, set
    `commit_url` (with {sha}) and `pr_url` (with {n}) in the config."""
    url = g.try_run(["remote", "get-url", "origin"], repo.root)[1].strip()
    tmpl = repo.cfg().get("commit_url" if kind == "commit" else "pr_url")
    if tmpl:
        return tmpl.replace("{sha}" if kind == "commit" else "{n}", ident)
    m = _REMOTE.match(url)
    if not m:
        return ""
    host, path = m.group(1), m.group(2)
    base = f"https://{host}/{path}"
    if host == "github.com":
        return f"{base}/commit/{ident}" if kind == "commit" else f"{base}/pull/{ident}"
    if "gitlab" in host:
        return f"{base}/-/commit/{ident}" if kind == "commit" else f"{base}/-/merge_requests/{ident}"
    if host == "bitbucket.org":
        return f"{base}/commits/{ident}" if kind == "commit" else f"{base}/pull-requests/{ident}"
    return ""


def record(repo, v, n):
    """Everything known about one citation. `expandable` is true for a note a teammate shared: those get a link and a name."""
    sha = v["placed"] or v["sha"]
    info = (g.commit_info(repo.root, sha) or {}) if sha else {}
    commit_header = info.get("subject") or v["subject"]
    pr = _PR.search(commit_header or "")
    if not v["mine"]:  # words from a teammate: shown to people and agents, so they go through the same filter as injected notes
        commit_header, v = sanitize(commit_header, 200), {**v, "author": sanitize(v["author"], 60), "topic": sanitize(v["topic"], 200)}
    url = ""
    if sha:  # the pull request when the header names one and the host has an address for it, else the commit
        url = (web_url(repo, "pr", pr.group(1) or pr.group(2)) if pr else "") or web_url(repo, "commit", sha)
    date = (v["created"] or "")[:10]
    expandable = v["scope"] == "shared" and not v["mine"]
    if sha:
        detail = f"{v['topic']} | {commit_header}  by {v['author']}, {date}" + (f"  {url}" if url else f"  commit {sha[:8]}")
    else:
        detail = f"Note added by {v['author']} on {date}"
    return {"n": n, "mark": sup(n), "id": v["id"], "header": v["topic"], "commit_header": commit_header if sha else "", "url": url, "author": v["author"],
            "date": date, "scope": v["scope"], "mine": v["mine"], "has_commit": bool(sha), "expandable": expandable, "log": v.get("log", ""),
            "detail": detail if expandable else ""}


def records(repo, session, views):
    """Citation records for every note shown in this chat, in number order."""
    items = repo.db.cite_items(_chat(session))
    by_id = {v["id"]: v for v in views}
    return [record(repo, by_id[i], n) for i, n in sorted(items.items(), key=lambda kv: kv[1]) if i in by_id]


def source_line(repo, v):
    """What goes next to an injected note so the agent can cite it: header and link for a teammate's shared note, else little."""
    if v["scope"] != "shared" or v["mine"]:
        return ""
    return sanitize(record(repo, v, 0)["detail"], 260)


def text(recs, expanded=True):
    """The bibliography as plain text: one line per source; shared teammates' notes also carry the link, author and date."""
    rows = []
    for r in recs:
        head = f"{r['mark']} {r['header']}"
        rows.append(f"{r['mark']} {r['detail']}" if expanded and r["expandable"] else head)
    return "\n".join(rows)
