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


TRIVIAL_TYPES = ("chore", "style", "docs")
_CC = re.compile(r"^(\w+)(\([^)]*\))?!?:")


def trivial_subject(subject):
    m = _CC.match(subject)
    return bool(m) and m.group(1).lower() in TRIVIAL_TYPES


def trivial_shas(repo, commits):
    """Commits that need no note: merges, chore/style/docs, and changes that vanish once whitespace is ignored or only rename
    files. Deterministic and cheap (one git call); an agent or a person can still write a note for any of them."""
    out, need = set(), []
    for c in commits:
        if len(c["parents"]) > 1 or trivial_subject(c["subject"]):
            out.add(c["sha"])
        else:
            need.append(c["sha"])
    if need:
        rc, txt, _ = g.try_run(["log", "--no-walk=unsorted", "--root", "-w", "-M", "--numstat", "--format=%x1e%H", *need], repo.root)
        for block in txt.split(chr(30))[1:] if rc == 0 else []:
            lines = [ln for ln in block.splitlines() if ln.strip()]
            if lines and all(ln.split(chr(9))[:2] == ["0", "0"] for ln in lines[1:]):
                out.add(lines[0].strip())
    return out


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
        self._sides = self._side_shas = None
        self.derived = get_derived(repo, self.sp[0]["sha"] if self.sp else "")
        self.shallow = (repo.common / "shallow").exists()  # no subprocess needed
        self.exists = None

    def prime(self, shas):
        """One batched existence check for every anchor sha we are about to place."""
        self.exists = g.existing_commits(self.repo.root, shas)

    def _has(self, sha):
        return sha in self.exists if self.exists is not None else g.commit_exists(self.repo.root, sha)

    def sides(self):
        if self._sides is None:
            self._sides = merge_sides(self.repo, self.sp)
        return self._sides

    def side_shas(self):
        if self._side_shas is None:
            self._side_shas = {c["sha"] for cs in self.sides().values() for c in cs}
        return self._side_shas

    def pids(self):
        if self._pids is None:
            if "patch_ids" not in self.derived:
                self.derived["patch_ids"] = patch_ids(self.repo)
                save_derived(self.repo)
            self._pids = self.derived["patch_ids"]
        return self._pids

    def merged_into(self, branch, merge_base):
        """The oldest merge on the main line, after the branch started, that is named for this branch; else None."""
        stop = self.by_sha.get(merge_base, len(self.sp))
        for c in reversed(self.sp[:stop]):
            if len(c["parents"]) > 1 and merged_branch(c["subject"]) == branch:
                return c["sha"]
        return None

    def follow(self, a):
        """Where a rewritten commit went: by patch-id, by the diff of its whole branch (a squash), by PR number, by tree."""
        if a.get("patch_id") and a["patch_id"] in self.pids():
            return self.pids()[a["patch_id"]], "rewritten", "patch-id"
        if a.get("range_pid") and a["range_pid"] in self.pids():
            return self.pids()[a["range_pid"]], "rewritten", "squashed branch"
        if a.get("pr") and a["pr"] in self.by_pr:
            return self.by_pr[a["pr"]], "rewritten", "PR number"
        if a.get("tree") and a["tree"] in self.by_tree:
            return self.by_tree[a["tree"]], "rewritten", "tree hash"
        return None

    def place(self, a):
        """-> (sha_on_spine | None, state, rung).
        state: exact | rewritten | branch | orphaned | unknown | unanchored. 'branch' is a note about a branch's work, written
        before the branch had a commit of its own: it stays with the branch until a merge named for it shows up."""
        sha = a.get("sha", "")
        if not sha:
            return None, "unanchored", ""
        if a.get("merge_base") and a.get("branch") and sha == a["merge_base"] and a["branch"] != a.get("base"):
            hit = self.merged_into(a["branch"], a["merge_base"])
            return (hit, "rewritten", "merged branch") if hit else (None, "branch", "")
        if sha in self.by_sha:
            return sha, "exact", "sha"
        if self._has(sha):
            if sha in self.side_shas():
                return sha, "exact", "sha (off first-parent line)"  # a merge brought it in
            hit = self.follow(a)  # reachable only by an old ref or the object store: rebased, squashed or abandoned
            return hit or (sha, "exact", "sha (off first-parent line)")
        return self.follow(a) or (None, ("unknown" if self.shallow else "orphaned"), "")

    def behind(self, sha):
        """Commits between the matched commit and HEAD (distance from the nearest *matched* commit)."""
        if sha in self.by_sha:
            return self.by_sha[sha]
        rc, out, _ = g.try_run(["rev-list", "--count", f"{sha}..HEAD"], self.repo.root)
        return int(out.strip()) if rc == 0 and out.strip().isdigit() else None


def default_branch(repo):
    """Local name of the repo's main line: origin's HEAD if known, else main, else master, else ''."""
    rc, out, _ = g.try_run(["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"], repo.root)
    if rc == 0 and out.strip().startswith("origin/"):
        return out.strip()[len("origin/"):]
    for name in ("main", "master"):
        if g.try_run(["rev-parse", "--verify", "--quiet", f"refs/heads/{name}"], repo.root)[0] == 0:
            return name
    return ""


def branch_point(repo, sha, branch):
    """(merge-base with the main line, main line name) for a note written off the main line, else ('', '').
    Only the note path calls this: it costs two git calls, which hooks and the commit sweep must not pay."""
    base = default_branch(repo)
    if not base or not branch or branch == base or not sha:
        return "", ""
    rc, out, _ = g.try_run(["merge-base", sha, f"refs/heads/{base}"], repo.root)
    return (out.strip(), base) if rc == 0 and out.strip() else ("", "")


def anchor_for(repo, sha=None, paths=None, dirty=None, pr="", with_base=False):
    """Snapshot of an anchor. Denormalised on purpose: it must still render when the commit is gone."""
    head, br, _, is_dirty = g.state(repo.root)
    sha = sha or head
    if sha and sha != head and g.try_run(["merge-base", "--is-ancestor", sha, head or "HEAD"], repo.root)[0] != 0:
        br = ""  # an old commit that is not behind HEAD: do not claim it belongs to the branch we are standing on
    a = {"sha": sha or "", "branch": br, "pr": pr, "dirty": is_dirty if dirty is None else dirty}
    if sha:
        info = g.commit_info(repo.root, sha) or {}
        a.update(tree=info.get("tree", ""), parent=info.get("parent", ""), subject=info.get("subject", ""),
                 date=info.get("date", ""), patch_id=g.patch_id(repo.root, sha) or "")
        if paths is None:
            paths = g.changed_paths(repo.root, sha)
    a["paths"] = list(paths or [])
    a["names"] = names_of(a["paths"])
    if with_base:
        a["merge_base"], a["base"] = branch_point(repo, sha, br)
        if a["merge_base"] and a["merge_base"] != sha:
            rc, diff, _ = g.try_run(["diff", a["merge_base"], sha], repo.root)
            if rc == 0 and diff.strip():
                rc, pid, _ = g.try_run(["patch-id", "--stable"], repo.root, input=diff)
                a["range_pid"] = pid.split()[0] if rc == 0 and pid.split() else ""
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
            "supersedes": e.supersedes, "redacted": e.redacted, "level": e.level, "sources": e.sources,
            "merge_base": a.get("merge_base", ""), "base": a.get("base", "")}


def all_views(repo):
    """(views of every visible entry, the Anchorer used). Primed so placing N entries costs O(1) subprocesses."""
    anch = Anchorer(repo)
    loaded = repo.all_entries()
    anch.prime([l.entry.anchor.get("sha", "") for l in loaded])
    return [view(repo, l, anch) for l in loaded], anch


def build(repo):
    views, anch = all_views(repo)
    sides = anch.sides()
    on_side = anch.side_shas()
    by_commit, loose = {}, {}
    for v in views:
        if v["placed"] in anch.by_sha or v["placed"] in on_side:
            by_commit.setdefault(v["placed"], []).append(v)
        else:
            loose.setdefault(v["branch"] or "(no branch)", []).append(v)

    shown = [c for i, c in enumerate(anch.sp) if by_commit.get(c["sha"]) or c["sha"] in sides or i < 30]
    kid_rows = [k for c in shown if c["sha"] in sides for k in sides[c["sha"]][:MERGE_SHOWN]]
    triv = trivial_shas(repo, shown + kid_rows)

    def card(c):
        ents = sorted(by_commit.get(c["sha"], []), key=lambda v: v["id"])
        return {**c, "short": c["sha"][:8], "entries": ents, "trivial": c["sha"] in triv}

    commits, cards = [], []
    for c in shown:
        row = card(c)
        cards.append(row)
        if c["sha"] in sides:
            kids = sides[c["sha"]]
            row["merge"] = {"branch": merged_branch(c["subject"]), "commits": [card(s) for s in kids[:MERGE_SHOWN]],
                            "more": max(0, len(kids) - MERGE_SHOWN)}
            cards += row["merge"]["commits"]
        commits.append(row)
    reasoned = lambda cd: any(v["body"].get("why") or v["body"].get("wrong") for v in cd["entries"])
    cover = {"commits": len(cards), "trivial": sum(1 for cd in cards if cd["trivial"] and not cd["entries"]),
             "with_reason": sum(1 for cd in cards if reasoned(cd))}
    cover["without_reason"] = len(cards) - cover["trivial"] - cover["with_reason"]
    loose_list = [{"branch": b, "entries": sorted(es, key=lambda v: v["id"])} for b, es in sorted(loose.items())]
    return {"repo": repo.root.name, "head": g.head_sha(repo.root) or "", "branch": g.branch(repo.root), "shallow": anch.shallow,
            "me": repo.user, "commits": commits, "unplaced": loose_list, "entry_count": len(views), "coverage": cover}
