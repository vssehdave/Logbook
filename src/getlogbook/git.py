"""Thin wrapper over the git CLI. Needs git >= 2.31 (--path-format=absolute)."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


def _env(extra=None):
    # GIT_OPTIONAL_LOCKS=0: `git status` otherwise refreshes the index, which takes index.lock, and a hook doing that while the person runs
    # `git commit` makes their commit fail with "Unable to create index.lock". Logbook only reads with status and writes refs through plumbing.
    e = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    if extra:
        e.update(extra)
    return e


def try_run(args, cwd, input=None, env=None, timeout=None):
    if isinstance(input, str):
        input = input.encode("utf-8")
    try:
        p = subprocess.run(["git", "-C", str(cwd), *args], input=input, capture_output=True, env=_env(env), timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "", f"git {args[0]} timed out after {timeout}s"
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def run(args, cwd, input=None, env=None):
    rc, out, err = try_run(args, cwd, input, env)
    if rc:
        raise GitError(f"git {' '.join(args)}: {err.strip()}")
    return out


def repo_paths(cwd):
    """(toplevel, common git dir) in one subprocess."""
    out = run(["rev-parse", "--path-format=absolute", "--show-toplevel", "--git-common-dir"], cwd).splitlines()
    return Path(out[0].strip()), Path(out[1].strip())


def state(cwd):
    """(head sha or None, branch, changed paths, dirty) in one subprocess."""
    rc, out, _ = try_run(["status", "--porcelain=v2", "--branch", "-z"], cwd)
    head, br, paths = None, "HEAD", []
    for rec in out.split("\0") if rc == 0 else []:
        if rec.startswith("# branch.oid "):
            head = None if rec.endswith("(initial)") else rec.split()[2]
        elif rec.startswith("# branch.head "):
            br = rec.split(" ", 2)[2]
        elif rec[:2] in ("1 ", "u "):
            paths.append(rec.split(" ", 8 if rec[0] == "1" else 10)[-1])
        elif rec[:2] == "2 ":
            paths.append(rec.split(" ", 9)[-1])
        elif rec[:2] == "? ":
            paths.append(rec[2:])
    return head, br, paths, bool(paths)


def existing_commits(cwd, shas):
    """Which of these shas are commits present locally (one subprocess)."""
    shas = [s for s in dict.fromkeys(shas) if s]
    if not shas:
        return set()
    p = subprocess.run(["git", "-C", str(cwd), "cat-file", "--batch-check"], input=("\n".join(shas) + "\n").encode(),
                       capture_output=True, env=_env())
    return {l.split()[0] for l in p.stdout.decode("utf-8", "replace").splitlines() if len(l.split()) >= 2 and l.split()[1] == "commit"}


def toplevel(cwd):
    return Path(run(["rev-parse", "--show-toplevel"], cwd).strip())


def common_dir(cwd):
    return Path(run(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd).strip())


def head_sha(cwd):
    rc, out, _ = try_run(["rev-parse", "--verify", "-q", "HEAD"], cwd)
    return out.strip() if rc == 0 else None


def branch(cwd):
    rc, out, _ = try_run(["symbolic-ref", "--short", "-q", "HEAD"], cwd)
    return out.strip() if rc == 0 else "HEAD"


def is_shallow(cwd):
    return run(["rev-parse", "--is-shallow-repository"], cwd).strip() == "true"


def is_dirty(cwd):
    return bool(run(["status", "--porcelain"], cwd).strip())


def config_get(cwd, key):
    rc, out, _ = try_run(["config", "--get", key], cwd)
    return out.strip() if rc == 0 else ""


def _is_rev(sha):
    """A commit id and nothing else. Whatever starts with a dash would reach git as an option (`show --output=<file>` writes a file),
    so the helpers below refuse anything that is not hex, however it got here."""
    return bool(sha) and bool(re.match(r"^[0-9a-fA-F]{4,64}$", sha))


def commit_exists(cwd, sha):
    return _is_rev(sha) and try_run(["cat-file", "-e", f"{sha}^{{commit}}"], cwd)[0] == 0


def commit_info(cwd, sha):
    """Return dict(sha, tree, parent, author, date, subject) or None."""
    if not _is_rev(sha):
        return None
    rc, out, _ = try_run(["show", "-s", "--format=%H%x1f%T%x1f%P%x1f%an%x1f%aI%x1f%s", sha], cwd)
    if rc:
        return None
    h, t, p, an, ad, s = (out.rstrip("\n").split("\x1f") + [""] * 6)[:6]
    return {"sha": h, "tree": t, "parent": p.split()[0] if p else "", "author": an, "date": ad, "subject": s}


def commit_body(cwd, sha):
    """The commit message below its subject ('' when there is none or the id is not a commit). Read from git each time, never copied into a note."""
    if not _is_rev(sha):
        return ""
    return try_run(["show", "-s", "--format=%b", sha], cwd)[1].strip()


def patch_id(cwd, sha):
    """Stable patch-id of a single-parent commit, else None."""
    if not _is_rev(sha):
        return None
    rc, patch, _ = try_run(["diff-tree", "-p", "--root", sha], cwd)
    if rc or not patch.strip():
        return None
    rc, out, _ = try_run(["patch-id", "--stable"], cwd, input=patch)
    return out.split()[0] if rc == 0 and out.split() else None


def changed_paths(cwd, sha):
    if not _is_rev(sha):
        return []
    rc, out, _ = try_run(["diff-tree", "--no-commit-id", "--name-only", "-r", "--root", sha], cwd)
    return [l for l in out.splitlines() if l] if rc == 0 else []


def cat_blobs(cwd, oids):
    """oid -> bytes for many blobs in one process."""
    if not oids:
        return {}
    p = subprocess.run(["git", "-C", str(cwd), "cat-file", "--batch"], input=("\n".join(oids) + "\n").encode(),
                       capture_output=True, env=_env())
    data, pos, res = p.stdout, 0, {}
    for oid in oids:
        nl = data.find(b"\n", pos)
        if nl < 0:
            break
        header = data[pos:nl].split()
        if len(header) == 3 and header[1] == b"blob":
            size = int(header[2])
            res[oid] = data[nl + 1:nl + 1 + size]
            pos = nl + 1 + size + 1
        else:
            pos = nl + 1
    return res
