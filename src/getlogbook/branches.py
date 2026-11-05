"""Which branches have been merged into the main line, so their private logs and notes can be offered for publishing.

Two signals, both from git alone:
  * a commit one of the branch's own entries is anchored to is now part of the main line's history (the entry's commit is not just the point the branch left
    the main line, which a branch with no commits of its own also "contains");
  * a merge commit on the main line names the branch ("Merge pull request #7 from user/feat-x", "Merge branch 'feat-x'").
A squash merge leaves neither: someone with access to the host (the agent, using the GitHub tools) says so, and `logbook publish --branch <name>` does the rest.
"""
from __future__ import annotations

from . import git as g
from . import tree

SCAN = 300  # newest first-parent commits on the main line looked through for merge subjects


def pending(repo):
    """{branch: [unpublished private entries]} for every branch other than the main line."""
    base = tree.default_branch(repo)
    by = {}
    for e in repo.unpublished():
        b = e.anchor.get("branch") or ""
        if b and b != base:
            by.setdefault(b, []).append(e)
    return by


def landed(repo, views):
    """Names of the branches whose work is in the main line, judged from the given log views: a merge commit on the main line names the branch, or a log's own
    commit is in the main line's history (not just the commit the branch left it at). Works for logs from teammates too; a squash merge is not seen."""
    base = tree.default_branch(repo)
    if not base:
        return set()
    tip = f"refs/heads/{base}"
    names = set()
    rc, out, _ = g.try_run(["log", "--first-parent", f"-n{SCAN}", "--format=%s", tip], repo.root)
    for subject in out.splitlines() if rc == 0 else []:
        if tree.merged_branch(subject):
            names.add(tree.merged_branch(subject))
    for v in views:
        sha, left = v.get("sha") or "", v.get("merge_base") or ""
        if v["branch"] and v["branch"] not in names and sha and sha != left and g.try_run(["merge-base", "--is-ancestor", sha, tip], repo.root)[0] == 0:
            names.add(v["branch"])
    return names - {base}


def merged(repo):
    """[(branch, entries, how)] for branches with unpublished entries that look merged into the main line, oldest branch name first."""
    base = tree.default_branch(repo)
    if not base:
        return []
    tip = f"refs/heads/{base}"
    named = set()
    rc, out, _ = g.try_run(["log", "--first-parent", f"-n{SCAN}", "--format=%s", tip], repo.root)
    for subject in out.splitlines() if rc == 0 else []:
        if tree.merged_branch(subject):
            named.add(tree.merged_branch(subject))
    res = []
    for branch, entries in sorted(pending(repo).items()):
        if branch in named:
            res.append((branch, entries, "a merge commit names it"))
            continue
        for e in entries:
            sha, left = e.anchor.get("sha") or "", e.anchor.get("merge_base") or ""
            if sha and sha != left and g.try_run(["merge-base", "--is-ancestor", sha, tip], repo.root)[0] == 0:
                res.append((branch, entries, "its commits are in " + base))
                break
    return res


def reminder(repo, mode):
    """The line for an agent at session start: merged branches whose logs and notes are still private. '' in manual mode or when there is none."""
    if mode not in ("ask", "auto"):
        return ""
    found = merged(repo)
    if not found:
        return ""
    names = ", ".join(f"{b} ({len(es)})" for b, es, _ in found[:5])
    how = ("Run `logbook publish --branch <name> --yes` for each (a redacted preview is printed; anything the checks refuse stays private)." if mode == "auto"
           else "Ask the user whether to publish them; on a yes run `logbook publish --branch <name>` and show the preview.")
    return f"[logbook] These branches look merged and still have private logs or notes: {names}. {how}"
