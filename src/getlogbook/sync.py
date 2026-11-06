"""Fetch/push of logbook refs. Others' refs land in refs/logbook-remote/<remote>/ so a fetch can never
clobber your own unpushed ref. We never write remote.<r>.push (that would hijack a plain `git push`)."""
from __future__ import annotations

import re
from pathlib import Path

from . import git as g
from .store import BRANCH_PREFIX, PREFIX, REMOTE_NS, SHELF, Repo, _apply_tombstones


_REFUSED = re.compile(r"denied|declined|refusing|not permitted|protected|forbidden|403|pre-receive|hook|unable to create", re.I)
_DIVERGED = re.compile(r"non-fast-forward|fetch first|stale info|rejected.*already exists", re.I)


def fetch_specs(remote):
    return [f"+{PREFIX}/*:{REMOTE_NS}/{remote}/log/*", f"+{BRANCH_PREFIX}/*:{REMOTE_NS}/{remote}/branchlog/*"]


def remotes(repo):
    return g.run(["remote"], repo.root).split()


def ensure_fetch_config(repo, remote="origin"):
    have = g.try_run(["config", "--get-all", f"remote.{remote}.fetch"], repo.root)[1].splitlines()
    added = 0
    for spec in fetch_specs(remote):
        if spec not in have:
            g.run(["config", "--add", f"remote.{remote}.fetch", spec], repo.root)
            added += 1
    return added


def fetch(repo, remote="origin", depth=None):
    args = ["fetch", "--no-tags", "--quiet"] + ([f"--depth={depth}"] if depth else []) + [remote, *fetch_specs(remote)]
    rc, _, err = g.try_run(args, repo.root)
    return {"ok": rc == 0, "error": err.strip() if rc else ""}


def _remote_ref(repo, remote):
    kind = "branchlog" if repo.cfg().get("transport") == "branches" else "log"
    return f"{REMOTE_NS}/{remote}/{kind}/{repo.user}/{SHELF}"


def _sha(repo, ref):
    return g.try_run(["rev-parse", "--verify", "-q", ref], repo.root)[1].strip()


def merge_remote(repo, remote="origin"):
    """Bring your shelf and the fetched remote copy of it together (the same person on two machines).
    Returns (state, needs_force). Entries are never edited, so the merge is the union of both trees; a purge's
    tombstone wins, and then the result is a fresh parentless commit that must be force-pushed (a merge commit
    would keep the purged text reachable through its parent)."""
    ref, rref = repo.own_ref(), _remote_ref(repo, remote)
    rtip, ltip = _sha(repo, rref), _sha(repo, ref)
    if not rtip or rtip == ltip:
        return "same", False
    if not ltip:
        g.run(["update-ref", ref, rtip], repo.root)
        return "adopted", False
    if g.try_run(["merge-base", "--is-ancestor", rtip, ltip], repo.root)[0] == 0:
        return "ahead", False
    if g.try_run(["merge-base", "--is-ancestor", ltip, rtip], repo.root)[0] == 0:
        g.run(["update-ref", ref, rtip], repo.root)
        return "fast-forward", False
    merged = {**repo._tree_files(rref), **repo._tree_files(ref)}
    kept = _apply_tombstones(merged)
    purged = len(kept) != len(merged)
    repo._write_ref(ref, kept, "logbook: merge two machines", None if purged else [ltip, rtip])
    return ("rewritten" if purged else "merged"), purged


def _drop_legacy_remote(repo, remote):
    """Delete the old per-device names of your own refs on the remote, once the shelf is pushed."""
    names = repo.cfg().get("legacy_remote", [])
    left = []
    for n in names:
        rc, _, err = g.try_run(["push", "--quiet", remote, f":{n}"], repo.root)
        if rc and "exist" not in err:
            left.append(n)
    if left != names:
        c = repo.cfg()
        c["legacy_remote"] = left
        repo.save_cfg(c)


def unpushed(repo, remote="origin"):
    """True when your shelf has commits the remote copy lacks, or the remote has no copy yet."""
    tip = _sha(repo, repo.own_ref())
    return bool(tip) and tip != _sha(repo, _remote_ref(repo, remote))


def _mark_pushed(repo, remote):
    """What was just pushed is now the remote copy, so `unpushed` is false until the next change (a fetch would say the same)."""
    g.try_run(["update-ref", _remote_ref(repo, remote), _sha(repo, repo.own_ref())], repo.root)


def push(repo, remote="origin", force=False):
    repo.adopt_legacy()
    ref = repo.own_ref()
    if g.try_run(["rev-parse", "--verify", "-q", ref], repo.root)[0]:
        return {"ok": True, "via": "nothing to push", "ref": ref}
    err = ""
    for attempt in range(3):
        flag = []
        if force:  # one person per ref, so force is safe; the lease still protects against a surprise remote tip
            tip = g.try_run(["ls-remote", remote, ref], repo.root)[1].split()
            flag = [f"--force-with-lease={ref}:{tip[0]}"] if tip else ["--force"]
        rc, _, err = g.try_run(["push", "--quiet", *flag, remote, f"{ref}:{ref}"], repo.root)
        if rc == 0:
            _mark_pushed(repo, remote)
            _drop_legacy_remote(repo, remote)
            return {"ok": True, "via": repo.cfg().get("transport", "refs"), "ref": ref}
        if not _DIVERGED.search(err) or attempt == 2:
            break
        # the same person pushed from another machine first: fetch their copy, merge, try again
        if not fetch(repo, remote)["ok"]:
            break
        force = merge_remote(repo, remote)[1] or force
    if _DIVERGED.search(err):
        return {"ok": False, "error": "remote copy of your shelf kept changing while merging; run `logbook sync` again: " + err.strip(), "ref": ref}
    if repo.cfg().get("transport") != "branches" and _REFUSED.search(err):
        # host refused a custom ref namespace: fall back to orphan branches and remember the choice
        bref = f"{BRANCH_PREFIX}/{repo.user}/{SHELF}"
        tip = g.run(["rev-parse", ref], repo.root).strip()
        g.run(["update-ref", bref, tip], repo.root)
        rc2, _, err2 = g.try_run(["push", "--quiet", *flag, remote, f"{bref}:{bref}"], repo.root)
        if rc2 == 0:
            c = repo.cfg()
            c["transport"] = "branches"
            repo.save_cfg(c)
            _mark_pushed(repo, remote)
            return {"ok": True, "via": "branches (host rejected custom refs)", "ref": bref}
        err = err2 or err
    return {"ok": False, "error": err.strip(), "ref": ref}


def sync(repo, remote="origin", fetch_only=True, depth=None):
    """Fetch what teammates shared and merge your own shelf's two copies. It never pushes (`publish` does); `fetch_only` is kept for older callers.
    The result has "news": what is new from teammates since the last look (also kept for the next prompt, see news.py)."""
    from . import news
    repo.adopt_legacy()
    out = {"fetch": fetch(repo, remote, depth)}
    if out["fetch"]["ok"]:
        out["merge"] = merge_remote(repo, remote)[0]
    shared, _ = repo.load_shared()
    out["news"] = news.update(repo) if out["fetch"]["ok"] else []
    out["writers"] = len({l.user for l in shared})
    out["entries"] = len(shared)
    return out


def doctor(repo, remote="origin"):
    """List of (level, message). Levels: ok | warn | fail."""
    r = []
    ok = lambda m: r.append(("ok", m))
    warn = lambda m: r.append(("warn", m))
    c = repo.cfg()
    if not c.get("user"):
        r.append(("fail", "not initialised: run `logbook init`"))
        return r
    ok(g.run(["version"], repo.root).strip())
    ok(f"interpreter pinned: {c.get('interpreter')}")
    ok(f"transport: {c.get('transport', 'refs')}; attribution: {repo.attribution()}")
    if g.is_shallow(repo.root):
        warn("shallow clone: anchors to missing commits show as 'unverified' (git fetch --unshallow to fix)")
    if remote in remotes(repo):
        have = g.try_run(["config", "--get-all", f"remote.{remote}.fetch"], repo.root)[1]
        if fetch_specs(remote)[0] in have:
            ok("fetch refspec present")
        else:
            warn(f"fetch refspec missing: run `logbook join` (plain `git fetch` will skip logbook refs)")
    else:
        warn(f"no remote named {remote!r}: entries stay local until you add one")
    hp = g.try_run(["config", "--get", "core.hooksPath"], repo.root)[1].strip()
    hooks_dir = g.run(["rev-parse", "--path-format=absolute", "--git-path", "hooks"], repo.root).strip()
    hf = Path(hooks_dir) / "post-merge"
    if hf.exists() and "logbook" in hf.read_text(encoding="utf-8", errors="ignore"):
        ok(f"post-merge hook installed ({hooks_dir}): a pull fetches shared logs")
    else:
        warn("post-merge hook not installed: run `logbook setup` (a pull will not fetch shared logs by itself)")
    if hp:
        warn(f"core.hooksPath is set ({hp}); hooks are read from there")
    err = repo.cdir / "errors.log"
    if err.exists() and err.stat().st_size:
        warn(f"hook errors logged: {err}")
    return r
