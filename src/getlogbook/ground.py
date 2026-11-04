"""Grounding: what can be checked about a note before it is saved, and what cannot.

A note says things about a repo: which files it concerns, which functions and values, which commits. Those claims can be looked up. Whether the
note is TRUE cannot be. So these checks catch what is checkable (a file that does not exist, a name that is nowhere in the code, a commit that is
not in the history, a finding that points at nothing) and say so, and what is left is marked unverified instead of being passed off as fact.
Everything here is deterministic and costs no model call.
"""
from __future__ import annotations

import re

from . import git as g

_TICKS = re.compile(r"`([^`\n]{2,80})`")
_FILE = re.compile(r"^[\w./\\-]+\.[A-Za-z0-9]{1,6}$")
_IDENT = re.compile(r"^[A-Za-z_][\w.:]*(?:\(\))?$")
_SHA = re.compile(r"\b[0-9a-f]{7,40}\b")
_EXTS = frozenset("py js ts tsx jsx sql md json yml yaml toml txt sh go rs java rb c h cpp css html ini cfg lock".split())
_PLAIN = frozenset("true false none null self cls args kwargs str int bool dict list set tuple".split())
MAX_IDENT = 12  # names looked up per note: each is one `git grep`
MAX_FILES = 20
TEXT_FIELDS = ("summary", "context", "what", "why", "wrong", "fix", "decided", "open", "scale", "evidence")


def _refs(texts):
    """The files, names and commit ids a note names: backticked names, and bare 7 to 40 character hex ids."""
    files, idents, shas = [], [], []
    for t in texts:
        for m in _TICKS.findall(t):
            m = m.strip()
            if _FILE.match(m) and ("/" in m or "\\" in m or m.rsplit(".", 1)[-1].lower() in _EXTS):
                files.append(m.replace("\\", "/"))
            elif _IDENT.match(m) and len(m.rstrip("()")) >= 3 and m.rstrip("()").lower() not in _PLAIN:
                idents.append(m.rstrip("()"))
        shas += [s for s in _SHA.findall(t) if re.search("[a-f]", s) and re.search("[0-9]", s)]  # a hex-looking word or a number is not a commit
    uniq = lambda xs: list(dict.fromkeys(xs))
    return uniq(files), uniq(idents), uniq(shas)


def check(repo, body, topic, paths, sha=None):
    """Look up what the note names, in the commit it is about (or HEAD). Returns the record that is saved with the note:
    {paths: [found, total], names: [found, total], commits: [found, total], files: [the files that exist], missing: [what was not found],
     evidence: bool (a real file, a real commit or an evidence field), at: HEAD when checked}."""
    ref = sha or "HEAD"
    named_files, idents, shas = _refs([topic] + [body.get(k, "") for k in TEXT_FIELDS])
    files = list(dict.fromkeys([p.replace("\\", "/") for p in (paths or []) if p] + named_files))
    found_f = [f for f in files if g.try_run(["cat-file", "-e", f"{ref}:{f}"], repo.root)[0] == 0]
    miss_f = [f for f in files if f not in found_f]
    found_n, miss_n, looked = 0, [], 0
    for name in idents[:MAX_IDENT]:
        rc = g.try_run(["grep", "-q", "-F", "-e", name, ref, "--"], repo.root)[0]  # 0 found, 1 not found, else git could not say
        if rc in (0, 1):
            looked += 1
            found_n += rc == 0
            if rc == 1:
                miss_n.append(name)
    found_c = [s for s in shas if g.commit_exists(repo.root, s)]
    miss_c = [s for s in shas if s not in found_c]
    return {"paths": [len(found_f), len(files)], "names": [found_n, looked], "commits": [len(found_c), len(shas)],
            "files": found_f[:MAX_FILES], "missing": (miss_f + miss_n + miss_c)[:8],
            "evidence": bool(body.get("evidence") or found_f or found_c), "at": g.head_sha(repo.root) or ""}


def problems(cks):
    """What is wrong with a checked note, in words: empty when everything it names exists and it points at something."""
    if not cks:
        return []
    out = [f"not found: {m}" for m in cks.get("missing", [])]
    if not cks.get("evidence"):
        out.append("it points at nothing: no file that exists, no commit, no evidence")
    return out


def line(cks):
    p, n, c = cks["paths"], cks["names"], cks["commits"]
    return f"files {p[0]}/{p[1]}, names {n[0]}/{n[1]}, commits {c[0]}/{c[1]}, evidence {'yes' if cks['evidence'] else 'NO'}"


def _words(text):
    return set(re.findall(r"[a-z0-9_]{3,}", text.lower()))


def overlaps(views, topic, summary, files, limit=3):
    """Notes already on the same files that say much the same thing: the ones to supersede, or to say why both stand.
    A guess from shared files and shared words, so it only ever suggests."""
    mine, want = _words(topic + " " + summary), set(files)
    scored = []
    for v in views:
        if v["kind"] == "summary" or v["provenance"] == "auto-copied" or not (want & set(v["paths"])):
            continue
        theirs = _words(v["topic"] + " " + v["body"].get("summary", ""))
        sim = len(mine & theirs) / len(mine | theirs) if mine and theirs else 0
        if sim >= 0.25:
            scored.append((sim, v))
    scored.sort(key=lambda x: -x[0])
    return [{"id": v["id"], "topic": v["topic"], "mine": v["mine"]} for _, v in scored[:limit]]
