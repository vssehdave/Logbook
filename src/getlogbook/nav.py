"""The repo as a tree you can walk: repo -> branch -> commit -> note.

The shape comes from git and from where each note is anchored, so building it costs no model call and gives the same tree for the
same history. The summaries at the repo and branch level are written by the agent (see `logbook summarize`) and go stale when the
notes under them change. Nothing is copied out of git: every commit node points back at `git show <sha>`, every note keeps its text.

Addresses: `repo`, `branch:<name>`, `commit:<sha prefix>`, `note:<id prefix>`.
"""
from __future__ import annotations

from . import tree

KINDS = ("branch", "commit", "note")


def _node(addr, kind, title, parent, children=(), summary=None, view=None, sha=""):
    return {"addr": addr, "kind": kind, "title": title, "parent": parent, "children": list(children), "summary": summary,
            "view": view, "sha": sha}


def build(repo):
    """{address: node}. A node's `children` are addresses; `summary` is the stored summary dict (with `fresh`) or None."""
    t = tree.build(repo)
    by_branch = {(s["level"], s["branch"]): s for s in t["summaries"]}
    nodes = {}
    here = t["branch"] or "(detached)"

    def commit_node(c, parent):
        addr = f"commit:{c['short']}"
        kids = []
        for v in c["entries"]:
            nid = f"note:{v['id']}"
            nodes[nid] = _node(nid, "note", v["topic"], addr, view=v)
            kids.append(nid)
        for k in (c.get("merge") or {}).get("commits", []):
            kids.append(commit_node(k, addr))
        nodes[addr] = _node(addr, "commit", c["subject"], parent, kids, sha=c["sha"])
        return addr

    cur = [commit_node(c, f"branch:{here}") for c in t["commits"] if c["entries"] or not c["trivial"]]
    branches = {here: cur}
    for u in t["unplaced"]:  # notes about a branch's work that no commit carries yet: they hang off the branch node
        kids = []
        for v in u["entries"]:
            nid = f"note:{v['id']}"
            nodes[nid] = _node(nid, "note", v["topic"], f"branch:{u['branch']}", view=v)
            kids.append(nid)
        branches[u["branch"]] = kids + branches.get(u["branch"], [])
    for (level, b), _s in by_branch.items():
        if level == "branch":
            branches.setdefault(b, [])
    for b, kids in branches.items():
        addr = f"branch:{b}"
        nodes[addr] = _node(addr, "branch", b, "repo", kids, summary=by_branch.get(("branch", b)))
        for k in kids:
            if nodes[k]["parent"] != addr:
                nodes[k]["parent"] = addr
    nodes["repo"] = _node("repo", "repo", repo.root.name, "", [f"branch:{b}" for b in branches], summary=by_branch.get(("repo", "")))
    return nodes


def resolve(nodes, address):
    """The node for an address, accepting a prefix of a sha or note id. (node, "") or (None, why)."""
    address = address.strip()
    if address in nodes:
        return nodes[address], ""
    kind, _, rest = address.partition(":")
    if kind not in KINDS or not rest:
        return None, f"not an address: {address!r} (repo, branch:<name>, commit:<sha>, note:<id>)"
    hits = [n for a, n in nodes.items() if a.startswith(kind + ":") and a[len(kind) + 1:].startswith(rest)]
    if len(hits) == 1:
        return hits[0], ""
    return None, ("no such node" if not hits else "ambiguous: " + ", ".join(n["addr"] for n in hits[:6]))


def path(nodes, node):
    """Addresses from the root down to the node."""
    out = []
    while node:
        out.append(node["addr"])
        node = nodes.get(node["parent"])
    return list(reversed(out))


def looks_like_address(word):
    return word == "repo" or word.partition(":")[0] in KINDS and ":" in word
