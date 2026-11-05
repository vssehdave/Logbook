"""Keeping notes true: candidates for tidying, and the validated way to change a note's status.

Python finds candidates and says why, from git and from the notes alone, and checks every proposal before anything is stored. It does not judge
whether a later commit really outdates a note or whether two notes mean the same thing: that is an agent's call, and the person approves the whole
list once (`logbook tidy --apply` is a command Claude Code asks about). A status is a small record written by the note's own author; the note itself
is never edited, so nothing already shared changes under a teammate.
"""
from __future__ import annotations

import re
import shutil

from . import capture, ground
from . import git as g
from .entry import HEX_RE, ID_RE, STATES
from .safety import sanitize

OLD_DRAFT_DAYS = 30  # an auto-copied draft this old and never turned into a real note is junk until shown otherwise
MAX_CHECKED = 200  # notes asked about their files, newest first: one `git log` each. shortcut: no index, upgrade if a repo has far more live notes
MAX_COMMITS = 20  # commits looked up per note: enough to cite from, and the shown list is the first few
SHOWN_COMMITS = 5
MAX_FILES = 20
MAX_APPLY = 50
_KEYS = ("status_of", "status", "commits", "reason")


def tracked(repo, v):
    """The files a note is about. A change note is about its commit, so those files. A finding is about the files it names (and a finding is anchored
    to whatever HEAD was when it was written, which says nothing about its subject); one that names none falls back to its commit's files."""
    sha = v["placed"] or v["sha"]
    named = list(dict.fromkeys(((v["checks"] or {}).get("files") or []) + (v["paths"] or [])))
    if v["kind"] == "change" and sha:
        return g.changed_paths(repo.root, sha) or named
    return named or (g.changed_paths(repo.root, sha) if sha else [])


def later_commits(repo, v):
    """[(full sha, subject)] of commits after the note's own commit (or after HEAD when it was written) that touched its files, newest first."""
    base = v["placed"] or v["sha"] or (v["checks"] or {}).get("at") or ""
    files = [f for f in tracked(repo, v) if f and not f.startswith("-")][:MAX_FILES]
    if not files or not g.commit_exists(repo.root, base):  # the id came from a note, possibly a teammate's: only a real commit goes near git's arguments
        return []
    rc, out, _ = g.try_run(["log", f"-n{MAX_COMMITS}", "--format=%H %s", f"{base}..HEAD", "--"] + files, repo.root)
    return [tuple(line.split(" ", 1)) for line in out.splitlines() if line.strip()] if rc == 0 else []


def candidates(repo, views):
    """[{id, topic, mine, reason, detail, commits}] in this order: repeated notes, notes whose files changed since, old drafts. A note that is
    already resolved, and a status record, are not candidates."""
    live = [v for v in views if v["kind"] != "summary" and not v.get("is_status") and v.get("status") != "resolved"]
    notes = [v for v in live if v["provenance"] != "auto-copied"]
    out, seen = [], set()
    for v in notes:
        for o in ground.overlaps([w for w in notes if w["id"] != v["id"]], v["topic"], v["body"].get("summary", ""), v["paths"]):
            pair = tuple(sorted((v["id"], o["id"])))
            if pair not in seen:
                seen.add(pair)
                out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": "may say the same as another note",
                            "detail": [f"{o['id']} ({'yours' if o['mine'] else 'a teammate'}): {o['topic'][:70]}"], "commits": []})
    for v in sorted(notes, key=lambda x: x["created"] or "", reverse=True)[:MAX_CHECKED]:
        later = later_commits(repo, v)
        if later and not (v.get("status") == "in-progress" and v["status_commits"] and later[0][0] in v["status_commits"]):  # already looked at up to the newest of these
            out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": "files it is about changed in later commits",
                        "detail": [f"{sha[:8]} {subject[:70]}" for sha, subject in later[:SHOWN_COMMITS]], "commits": [sha for sha, _ in later]})
    for v in live:
        if v["provenance"] == "auto-copied" and (v["age_days"] or 0) >= OLD_DRAFT_DAYS:
            out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": f"auto-copied draft, {v['age_days']} days old", "detail": [], "commits": []})
    return out


def parse(text):
    """Proposals as blocks of `key: value` lines (status_of, status, commits, reason) separated by a line of `---`. A value may run over several lines."""
    blocks, cur, key = [], {}, None
    for line in text.splitlines() + ["---"]:
        if line.strip() == "---":
            if cur:
                blocks.append({k: v.strip() for k, v in cur.items()})
            cur, key = {}, None
            continue
        m = re.match(r"^([a-z_]+):[ \t]?(.*)$", line)
        if m and m.group(1) in _KEYS:
            key = m.group(1)
            cur[key] = m.group(2)
        elif key:
            cur[key] += "\n" + line
    return blocks


def check(repo, views, blk):
    """(error, target view, full commit ids) for one proposal. A proposal is accepted only when the note is the proposer's own, and a resolved or
    in-progress one cites commits that exist and touched the note's files after it was written, with a reason."""
    nid, state = blk.get("status_of", ""), blk.get("status", "")
    if not ID_RE.match(nid):
        return f"{nid!r} is not a note id", None, []
    t = next((v for v in views if v["id"] == nid), None)
    if not t or t.get("is_status"):
        return f"{nid}: no such note", None, []
    if not t["mine"]:
        return f"{nid}: not your note; only the author can change its status", None, []
    if state not in STATES:
        return f"{nid}: status must be one of {', '.join(STATES)}", None, []
    if not blk.get("reason"):
        return f"{nid}: a reason is required", None, []
    shas = []
    if state != "open":
        asked = [c for c in re.split(r"[,\s]+", blk.get("commits", "")) if c]
        if not asked:
            return f"{nid}: {state} needs the commit or commits that justify it", None, []
        touching = [sha for sha, _ in later_commits(repo, t)]
        for c in asked:
            full = [s for s in touching if HEX_RE.match(c) and s.startswith(c.lower())]
            if len(full) != 1:
                return f"{nid}: commit {c} did not touch this note's files after it was written", None, []
            shas.append(full[0])
    return "", t, shas


def apply(repo, views, text):
    """([(note id, status, the new record)], [errors]). Nothing is stored unless every proposal is valid, so what the person approved is what happens."""
    blocks = parse(text)
    if not blocks:
        return [], ["no proposals on stdin (blocks of status_of / status / commits / reason lines, separated by ---)"]
    if len(blocks) > MAX_APPLY:
        return [], [f"{len(blocks)} proposals; at most {MAX_APPLY} at a time"]
    checked = [(b, *check(repo, views, b)) for b in blocks]
    errors = [e for _, e, _, _ in checked if e]
    if errors:
        return [], errors
    done = []
    for b, _, t, shas in checked:
        state = b["status"]
        cited = [f"{s[:8]} {subj[:60]}" for s, subj in later_commits(repo, t) if s in shas]
        body = {"summary": b["reason"][:1000], "evidence": ("later commits: " + "; ".join(cited)) if cited else "reopened by its author"}
        e = capture.make_entry(repo, "finding", f"{state}: {t['topic']}"[:200], body, paths=t["paths"], via="tidy", status={"of": t["id"], "state": state, "commits": shas})
        done.append((t["id"], state, e))
    return done, []


def brief(repo, views, limit=20):
    """What an agent needs to judge the candidates: each note's text and the later commits to read with `git show`. Makes no model call."""
    by_id = {v["id"]: v for v in views}
    lines = ["Candidates for tidying. For each, decide: still true (leave it), partly changed (in-progress), fixed or gone (resolved), or the same as another note.",
             "Read the commits with `git show <sha> -- <file>` before deciding. Give the person the whole list in chat and wait for a yes; then run",
             "`logbook tidy --apply` once, with blocks of lines  status_of: <id>  status: in-progress|resolved|open  commits: <sha>, <sha>  reason: why, citing the commit",
             "separated by a line of ---. A reason and, for resolved or in-progress, a commit that touched the note's files are required. Only your own notes can be changed.", ""]
    for c in candidates(repo, views)[:limit]:
        v = by_id[c["id"]]
        lines += [f"{c['id']}  {'yours' if c['mine'] else 'a teammate'}  {sanitize(v['topic'], 100)}", f"  why listed: {c['reason']}"]
        for k in ("summary", "why", "fix", "decided", "open"):  # a teammate's words reach the agent, so they are cleaned like any injected note
            if v["body"].get(k):
                lines.append(f"  {k}: {sanitize(v['body'][k], 300)}")
        lines += [f"  files: {sanitize(', '.join(tracked(repo, v)[:6]), 200)}"] + [f"  - {sanitize(d, 120)}" for d in c["detail"]] + [""]
    return "\n".join(lines)


RETENTION_DAYS = 30


def garbage(repo, views, days=None):
    """Your own private worker drafts that are no longer worth keeping, each with the reason: marked resolved, about files that are all gone, or older than the
    retention. Only machine-made, private, yours: a note a person or an agent wrote, or one already shared, is never listed here."""
    days = int(days or repo.cfg().get("worker_days", RETENTION_DAYS))
    out = []
    for v in views:
        if v.get("is_status") or not v["mine"] or v["provenance"] != "worker-written" or v["scope"] != "private":
            continue
        files = tracked(repo, v)[:MAX_FILES]
        if v.get("status") == "resolved":
            reason = "resolved"
        elif files and all(g.try_run(["cat-file", "-e", f"HEAD:{f}"], repo.root)[0] != 0 for f in files):
            reason = "every file it is about is gone"
        elif (v["age_days"] or 0) >= days:
            reason = f"{v['age_days']} days old (kept {days})"
        else:
            continue
        out.append({"id": v["id"], "topic": v["topic"], "reason": reason})
    return out


def archive(repo, ids):
    """Move private notes out of the log into .git/logbook/archive/, where they stay readable; nothing is deleted. Returns how many moved."""
    d = repo.cdir / "archive"
    d.mkdir(parents=True, exist_ok=True)
    moved = 0
    for i in ids:
        src = repo.pdir / f"{i}.json"
        if src.exists():
            shutil.copy2(src, d / src.name)
            moved += repo.drop_private(i)
    return moved


def auto(repo):
    """The automatic mode (`logbook config tidy auto`): archive the worker drafts that `garbage` lists, after a worker pass."""
    from . import tree
    return archive(repo, [c["id"] for c in garbage(repo, tree.all_views(repo)[0])])
