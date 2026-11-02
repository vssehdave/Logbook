"""Anchoring and the branch -> commit -> entry tree.

Re-anchor ladder (first hit wins, the rung is recorded and shown, never presented as fact):
  exact sha -> patch-id -> PR number -> tree hash -> unresolved (kept under its branch node).
Entries are never rewritten; everything here is derived at read time.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import PurePosixPath

from . import git as g
from .store import atomic_write, user_id

SPINE_LIMIT = 500
MERGE_SHOWN = 40  # children listed per merge card; the rest are counted
_PR = re.compile(r"\(#(\d+)\)")


def names_of(paths):
    """File names (stems) of changed paths: what a prompt or a note is likely to call a thing. Dunder and tiny stems are noise."""
    seen, out = set(), []
    for p in paths:
        stem = PurePosixPath(p.replace("\\", "/")).stem
        if len(stem) >= 3 and not stem.startswith("__") and stem not in seen:
            seen.add(stem)
            out.append(stem)
    return out


def spine(repo, limit=SPINE_LIMIT):
    rc, out, _ = g.try_run(["log", "--first-parent", f"-n{limit}", "--format=%H%x1f%T%x1f%P%x1f%an%x1f%aI%x1f%s%x1f%ae"], repo.root)
    rows = []
    for line in out.splitlines() if rc == 0 else []:
        h, t, p, an, ad, s, ae = (line.split("\x1f") + [""] * 7)[:7]
        rows.append({"sha": h, "tree": t, "parent": p.split()[0] if p else "", "parents": p.split(), "author": an, "date": ad,
                     "subject": s, "email": ae})
    return rows


SIDE_SCAN = 3000  # newest commits scanned for merge side branches; older merges just show no children
_MERGED = re.compile(r"Merge (?:branch|remote-tracking branch) '([^']+)'|Merge pull request #\d+ from (?:[^/\s]+/)?(\S+)")


def merged_branch(subject):
    m = _MERGED.match(subject)
    return (m.group(1) or m.group(2)) if m else ""


def merge_sides(repo, sp):
    """{merge sha: [commits it brought in, newest first]} for merges on the spine, from one git log (no per-merge subprocess)."""
    merges = [c for c in sp if len(c["parents"]) > 1]
    if not merges:
        return {}
    rc, out, _ = g.try_run(["log", f"-n{SIDE_SCAN}", "--format=%H%x1f%P%x1f%an%x1f%aI%x1f%s"], repo.root)
    rows = {}
    for line in out.splitlines() if rc == 0 else []:
        h, p, an, ad, s = (line.split("\x1f") + [""] * 5)[:5]
        rows[h] = {"sha": h, "parents": p.split(), "author": an, "date": ad, "subject": s}
    spine_shas, claimed, sides = {c["sha"] for c in sp}, set(), {}
    for m in merges:  # newest merge first, so a commit belongs to the merge that brought it in
        stack, got = list(m["parents"][1:]), []
        while stack:
            sha = stack.pop()
            if sha in spine_shas or sha in claimed or sha not in rows:
                continue
            claimed.add(sha)
            got.append(rows[sha])
            stack.extend(rows[sha]["parents"])
        sides[m["sha"]] = sorted(got, key=lambda r: r["date"], reverse=True)
    return sides


def get_derived(repo, head=None):
    """Per-HEAD cache of expensive git lookups (patch-ids, renames, tracked model names), kept in memory and on disk."""
    d = getattr(repo, "_derived", None)
    if d is not None and (head is None or d.get("head") == head):
        return d
    head = head if head is not None else (g.head_sha(repo.root) or "")
    try:
        d = json.loads((repo.cdir / "derived.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    if d.get("head") != head:
        d = {"head": head}
    repo._derived = d
    return d


def save_derived(repo):
    try:
        atomic_write(repo.cdir / "derived.json", json.dumps(repo._derived))
    except OSError:
        pass


def patch_ids(repo, limit=SPINE_LIMIT):
    """patch-id -> sha for the spine (one subprocess pair, only called when an entry needs it)."""
    rc, patch, _ = g.try_run(["log", "--first-parent", f"-n{limit}", "-p", "--format=%H"], repo.root)
    if rc or not patch.strip():
        return {}
    rc, out, _ = g.try_run(["patch-id", "--stable"], repo.root, input=patch)
    return {line.split()[0]: line.split()[1] for line in out.splitlines() if len(line.split()) == 2} if rc == 0 else {}


class Anchorer:
    def __init__(self, repo):
        self.repo = repo
        self.sp = spine(repo)
        self.by_sha = {c["sha"]: i for i, c in enumerate(self.sp)}
        repo._committers = {user_id(c["email"]) for c in self.sp if c["email"]}  # reuse this log: no extra subprocess
        self.by_tree = {}
        self.by_pr = {}
        for c in self.sp:
            self.by_tree.setdefault(c["tree"], c["sha"])
            m = _PR.search(c["subject"])
            if m:
                self.by_pr.setdefault(m.group(1), c["sha"])
        self._pids = None
        self.derived = get_derived(repo, self.sp[0]["sha"] if self.sp else "")
        self.shallow = (repo.common / "shallow").exists()  # no subprocess needed
        self.exists = None

    def prime(self, shas):
        """One batched existence check for every anchor sha we are about to place."""
        self.exists = g.existing_commits(self.repo.root, shas)

    def _has(self, sha):
        return sha in self.exists if self.exists is not None else g.commit_exists(self.repo.root, sha)

    def place(self, a):
        """-> (sha_on_spine | None, state, rung). state: exact | rewritten | orphaned | unknown | unanchored."""
        sha = a.get("sha", "")
        if not sha:
            return None, "unanchored", ""
        if sha in self.by_sha:
            return sha, "exact", "sha"
        if self._has(sha):
            return sha, "exact", "sha (off first-parent line)"
        if a.get("patch_id"):
            if self._pids is None:
                if "patch_ids" not in self.derived:
                    self.derived["patch_ids"] = patch_ids(self.repo)
                    save_derived(self.repo)
                self._pids = self.derived["patch_ids"]
            if a["patch_id"] in self._pids:
                return self._pids[a["patch_id"]], "rewritten", "patch-id"
        if a.get("pr") and a["pr"] in self.by_pr:
            return self.by_pr[a["pr"]], "rewritten", "PR number"
        if a.get("tree") and a["tree"] in self.by_tree:
            return self.by_tree[a["tree"]], "rewritten", "tree hash"
        return None, ("unknown" if self.shallow else "orphaned"), ""

    def behind(self, sha):
        """Commits between the matched commit and HEAD (distance from the nearest *matched* commit)."""
        if sha in self.by_sha:
            return self.by_sha[sha]
        rc, out, _ = g.try_run(["rev-list", "--count", f"{sha}..HEAD"], self.repo.root)
        return int(out.strip()) if rc == 0 and out.strip().isdigit() else None


def anchor_for(repo, sha=None, paths=None, dirty=None, pr=""):
    """Snapshot of an anchor. Denormalised on purpose: it must still render when the commit is gone."""
    head, br, _, is_dirty = g.state(repo.root)
    sha = sha or head
    a = {"sha": sha or "", "branch": br, "pr": pr, "dirty": is_dirty if dirty is None else dirty}
    if sha:
        info = g.commit_info(repo.root, sha) or {}
        a.update(tree=info.get("tree", ""), parent=info.get("parent", ""), subject=info.get("subject", ""),
                 date=info.get("date", ""), patch_id=g.patch_id(repo.root, sha) or "")
        if paths is None:
            paths = g.changed_paths(repo.root, sha)
    a["paths"] = list(paths or [])
    a["names"] = names_of(a["paths"])
    return a


def renames(repo, limit=SPINE_LIMIT):
    """old name -> newest name, from rename detection over the first-parent line. Derived cache, heuristic."""
    d = get_derived(repo)
    if "renames" in d:
        return d["renames"]
    rc, out, _ = g.try_run(["log", "--first-parent", f"-n{limit}", "-M", "--name-status", "--diff-filter=R", "--format="], repo.root)
    pairs = []  # newest first
    for line in out.splitlines() if rc == 0 else []:
        parts = line.split("\t")
        if len(parts) == 3 and parts[0].startswith("R"):
            pairs.append((parts[1], parts[2]))
    alias = {}
    for old, new in reversed(pairs):  # oldest first, so chains resolve to the latest name
        for k, v in list(alias.items()):
            if v == old:
                alias[k] = new
        alias[old] = new
    d["renames"] = alias
    save_derived(repo)
    return alias


def aliases_for(repo, name):
    """All historical names for a file (stems), for query expansion."""
    al = renames(repo)
    stems = {PurePosixPath(k).stem: PurePosixPath(v).stem for k, v in al.items()}
    names = {name}
    for old, new in stems.items():
        if name in (old, new):
            names |= {old, new}
    return names


def age_days(created):
    try:
        return max(0, int((time.time() - time.mktime(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))) // 86400))
    except (ValueError, OverflowError):
        return None


def view(repo, loaded, anch):
    """Flat, JSON-safe dict for one entry (UI and CLI share this)."""
    e, a = loaded.entry, loaded.entry.anchor
    sha, state, rung = anch.place(a)
    behind = anch.behind(sha) if sha else None
    return {"id": e.id, "kind": e.kind, "topic": e.topic, "body": e.body, "provenance": e.provenance,
            "scope": loaded.scope, "author": repo.label(loaded), "mine": loaded.user == repo.user,
            "trusted": loaded.user in repo.trusted(), "state": state, "rung": rung, "behind": behind,
            "age_days": age_days(e.created), "created": e.created, "captured_via": e.captured_via,
            "branch": a.get("branch", ""), "subject": a.get("subject", ""), "sha": a.get("sha", ""), "placed": sha or "",
            "paths": a.get("paths", []), "names": a.get("names", []), "dirty": a.get("dirty", False),
            "supersedes": e.supersedes, "redacted": e.redacted}


def all_views(repo):
    """(views of every visible entry, the Anchorer used). Primed so placing N entries costs O(1) subprocesses."""
    anch = Anchorer(repo)
    loaded = repo.all_entries()
    anch.prime([l.entry.anchor.get("sha", "") for l in loaded])
    return [view(repo, l, anch) for l in loaded], anch


def build(repo):
    views, anch = all_views(repo)
    sides = merge_sides(repo, anch.sp)
    on_side = {s["sha"] for cs in sides.values() for s in cs}
    by_commit, loose = {}, {}
    for v in views:
        if v["placed"] in anch.by_sha or v["placed"] in on_side:
            by_commit.setdefault(v["placed"], []).append(v)
        else:
            loose.setdefault(v["branch"] or "(no branch)", []).append(v)

    def card(c):
        ents = sorted(by_commit.get(c["sha"], []), key=lambda v: v["id"])
        return {**c, "short": c["sha"][:8], "entries": ents}

    commits = []
    for c in anch.sp:
        ents = by_commit.get(c["sha"])
        if ents or c["sha"] in sides or len(commits) < 30:
            row = card(c)
            if c["sha"] in sides:
                kids = sides[c["sha"]]
                row["merge"] = {"branch": merged_branch(c["subject"]), "commits": [card(s) for s in kids[:MERGE_SHOWN]],
                                "more": max(0, len(kids) - MERGE_SHOWN)}
            commits.append(row)
    loose_list = [{"branch": b, "entries": sorted(es, key=lambda v: v["id"])} for b, es in sorted(loose.items())]
    return {"repo": repo.root.name, "head": g.head_sha(repo.root) or "", "branch": g.branch(repo.root), "shallow": anch.shallow,
            "me": repo.user, "commits": commits, "unplaced": loose_list, "entry_count": len(views)}
