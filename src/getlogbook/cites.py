"""Citations: the numbered sources behind an answer.

When notes are put in front of an agent they get a number that stays the same for the rest of that chat (¹, ², ³ ...), kept in
`.git/logbook/cites/<session>.json`. The agent cites a note by writing its number after the claim. This module turns a number back
into what a reader needs: the header, a link to the commit or pull request, who wrote it and when.

A link and an author are shown only for notes a teammate shared. Your own notes and private notes need no source line. A shared note
with no commit says "Note added by <name> on <date>".
"""
from __future__ import annotations

import json
import re

from . import git as g
from .safety import sanitize
from .store import atomic_write

_SAFE = re.compile(r"[^A-Za-z0-9_-]")
_REMOTE = re.compile(r"^(?:ssh://)?(?:git@|https?://)(?:[^@/]+@)?([^/:]+)[:/](.+?)(?:\.git)?/?$")
_PR = re.compile(r"\(#(\d+)\)|^Merge pull request #(\d+)")
SUP = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")


def sup(n):
    return str(n).translate(SUP)


def _file(repo, session):
    return repo.cdir / "cites" / f"{_SAFE.sub('', session) or 'none'}.json"


def _load(repo, session):
    try:
        d = json.loads(_file(repo, session).read_text(encoding="utf-8"))
        return d if isinstance(d.get("items"), dict) else {"items": {}}
    except (OSError, ValueError):
        return {"items": {}}


def peek(repo, session, note_id):
    """The number a note has in this chat, or the one it would get, without recording anything."""
    items = _load(repo, session)["items"]
    return items.get(note_id) or max(items.values(), default=0) + 1


def number(repo, session, note_id):
    """The number of a note in this chat, giving it the next one the first time it is shown."""
    d = _load(repo, session)
    if note_id not in d["items"]:
        d["items"][note_id] = max(d["items"].values(), default=0) + 1
        try:
            atomic_write(_file(repo, session), json.dumps(d))
        except OSError:
            pass
    return d["items"][note_id]


def latest_session(repo):
    files = sorted((repo.cdir / "cites").glob("*.json"), key=lambda p: p.stat().st_mtime) if (repo.cdir / "cites").exists() else []
    return files[-1].stem if files else ""


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
    return {"n": n, "mark": f"[{sup(n)}]", "id": v["id"], "header": v["topic"], "commit_header": commit_header if sha else "", "url": url, "author": v["author"],
            "date": date, "scope": v["scope"], "mine": v["mine"], "has_commit": bool(sha), "expandable": expandable,
            "detail": detail if expandable else ""}


def records(repo, session, views):
    """Citation records for every note shown in this chat, in number order."""
    items = _load(repo, session)["items"]
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
