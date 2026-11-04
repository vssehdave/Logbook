"""Candidates for tidying: notes that may be out of date, repeated or junk.

Python finds them and says why, from git and from the notes alone. It does not judge whether a later commit really outdates a note or whether two
notes mean the same thing (that is an agent's call, then the person's approval), and it changes nothing.
"""
from __future__ import annotations

from . import git as g
from . import ground

OLD_DRAFT_DAYS = 30  # an auto-copied draft this old and never turned into a real note is junk until shown otherwise
MAX_CHECKED = 200  # notes asked about their files, newest first: one `git log` each. shortcut: no index, upgrade if a repo has far more live notes
MAX_COMMITS = 5
MAX_FILES = 20


def tracked(repo, v):
    """The files a note is about: the commit's files when it has a commit, else the files it named that exist, else the paths it is anchored to."""
    sha = v["placed"] or v["sha"]
    files = g.changed_paths(repo.root, sha) if sha else []
    return files or list(dict.fromkeys(((v["checks"] or {}).get("files") or []) + (v["paths"] or [])))


def later_commits(repo, v):
    """[(short sha, subject)] of commits after the note's own commit (or after HEAD when it was written) that touched its files, newest first."""
    base = v["placed"] or v["sha"] or (v["checks"] or {}).get("at") or ""
    files = [f for f in tracked(repo, v) if f and not f.startswith("-")][:MAX_FILES]
    if not files or not g.commit_exists(repo.root, base):  # the id came from a note, possibly a teammate's: only a real commit goes near git's arguments
        return []
    rc, out, _ = g.try_run(["log", f"-n{MAX_COMMITS}", "--format=%h %s", f"{base}..HEAD", "--"] + files, repo.root)
    return [tuple(line.split(" ", 1)) for line in out.splitlines() if line.strip()] if rc == 0 else []


def candidates(repo, views):
    """[{id, topic, mine, reason, detail}] in this order: repeated notes, notes whose files changed since, old drafts."""
    live = [v for v in views if v["kind"] != "summary"]
    notes = [v for v in live if v["provenance"] != "auto-copied"]
    out, seen = [], set()
    for v in notes:
        for o in ground.overlaps([w for w in notes if w["id"] != v["id"]], v["topic"], v["body"].get("summary", ""), v["paths"]):
            pair = tuple(sorted((v["id"], o["id"])))
            if pair not in seen:
                seen.add(pair)
                out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": "may say the same as another note",
                            "detail": [f"{o['id']} ({'yours' if o['mine'] else 'a teammate'}): {o['topic'][:70]}"]})
    for v in sorted(notes, key=lambda x: x["created"] or "", reverse=True)[:MAX_CHECKED]:
        later = later_commits(repo, v)
        if later:
            out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": "files it is about changed in later commits",
                        "detail": [f"{sha} {subject[:70]}" for sha, subject in later]})
    for v in live:
        if v["provenance"] == "auto-copied" and (v["age_days"] or 0) >= OLD_DRAFT_DAYS:
            out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": f"auto-copied draft, {v['age_days']} days old", "detail": []})
    return out
