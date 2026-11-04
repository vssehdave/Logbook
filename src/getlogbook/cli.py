"""logbook CLI. Exit codes for scripts: 0 found, 3 ambiguous (candidates listed), 4 nothing matched."""
from __future__ import annotations

import argparse
import json
import re
import sys

from . import capture, cites, ground, nav, recall, sync, tree
from . import git as g
from .entry import BODY_FIELDS, ID_RE, MAX_SUMMARY
from .safety import digest_hash, looks_tabular, redact
from .safety import sanitize as safety_sanitize
from .store import PUBLISH_MODES, Repo

SHARE_FIELDS = ("summary", "context", "what", "why", "wrong", "fix", "decided", "open", "scale")  # allowlist: evidence is opt-in


def out(s=""):
    print(s)


def txt(v, s, cap=600):
    """Text written by another writer is untrusted: an agent reading this output would be reading their words."""
    return s if v["mine"] else safety_sanitize(s, cap)


def line(v):
    where = {"exact": "anchor ok", "rewritten": f"re-anchored by {v['rung']}", "orphaned": "anchor commit gone",
             "unknown": "anchor unverified (shallow)", "unanchored": "no commit",
             "branch": f"on branch {v['branch']}, not merged here"}[v["state"]]
    behind = f", {v['behind']} behind HEAD" if v["behind"] is not None else ""
    return (f"{v['id']}  {v['kind']:<7} {v['scope']:<7} by {v['author']:<10} {v['provenance']:<13} "
            f"{where}{behind}\n    {txt(v, v['topic'], 200)}")


def detail(v):
    rows = [line(v), f"    branch {txt(v, v['branch'], 100)}  commit {v['sha'][:8]} {txt(v, v['subject'], 150)}",
            f"    names {txt(v, ', '.join(v['names']), 200) or '-'}  captured via {txt(v, v['captured_via'], 40)}"]
    for k in BODY_FIELDS:
        if v["body"].get(k):
            rows.append(f"    {k}: {txt(v, v['body'][k])}")
    if not v["mine"]:
        rows.append("    (text from another writer is shown sanitised: links, code and instruction-like lines are removed)")
    return "\n".join(rows)


def need_repo():
    try:
        r = Repo(".")
    except Exception:
        raise SystemExit("logbook: not inside a git repository")
    if not r.cfg().get("user"):
        raise SystemExit("logbook: run `logbook setup` first")
    return r


def views(repo):
    return tree.all_views(repo)


# ---- commands --------------------------------------------------------------------------------------------------
def cmd_init(a):
    r = Repo(".")
    c = r.init()
    if a.attribution:
        c["attribution"] = a.attribution
        r.save_cfg(c)
    out(f"initialised. you are {c['user']}; attribution: {r.attribution()}")
    out("next: `logbook setup`")


def cmd_join(a):
    r = Repo(".")
    r.init()
    added = sync.ensure_fetch_config(r, a.remote) if a.remote in sync.remotes(r) else 0
    res = sync.fetch(r, a.remote) if a.remote in sync.remotes(r) else {"ok": False, "error": "no such remote"}
    shared, _ = r.load_shared()
    writers = {l.user for l in shared}
    out(f"joined. fetch refspecs added: {added}; fetch {'ok' if res['ok'] else 'failed: ' + res['error']}")
    out(f"found {len(writers)} writers, {len(shared)} entries")
    for u in sorted(writers):
        out(f"  writer {u}{'  (you)' if u == r.user else '  [not trusted: searchable, never auto-injected; `logbook trust ' + u + '`]' if u not in r.trusted() else '  [trusted]'}")


_FIELD_KEYS = frozenset(("kind", "topic", "title", "commit", "before_commit", "level", "paths", "sources", "supersedes", *BODY_FIELDS))  # title: what an agent calls the topic
_LIST_KEYS = ("paths", "sources", "supersedes")


def _parse_fields(text):
    """`key: value` lines, a value running on over the lines after it until the next key. No braces and no quotes, so a command that carries
    it does not trip Claude Code's check for obfuscated shell (which refuses `{"` and needs a person to approve it), and nothing needs escaping."""
    out, key = {}, None
    for line in text.splitlines():
        m = re.match(r"^([a-z_]+):[ \t]?(.*)$", line)
        if m and m.group(1) in _FIELD_KEYS:
            key = m.group(1)
            out[key] = m.group(2)
        elif key is not None:
            out[key] += "\n" + line
    obj = {k: v.strip() for k, v in out.items()}
    if "title" in obj:
        obj.setdefault("topic", obj.pop("title"))
    for k in _LIST_KEYS:
        if k in obj:
            obj[k] = [x for x in re.split(r"[,\s]+", obj[k]) if x]
    if "before_commit" in obj:
        obj["before_commit"] = obj["before_commit"].lower() in ("yes", "true", "1")
    return obj


def _note_input(a):
    """The note as (kind, topic, body, paths, commit, before_commit, level, sources, supersedes), from flags, from `key: value` lines on stdin
    (--fields) or from JSON on stdin (--json)."""
    fields = getattr(a, "fields", False)
    if not (a.json or fields):
        body = {k: getattr(a, k) for k in BODY_FIELDS if getattr(a, k, None)}
        if a.from_stdin:
            body["summary"] = sys.stdin.read().strip()[:MAX_SUMMARY]
        words = getattr(a, "text", None) or []  # logbook note "what you found" [files...]: the plain way a person writes one
        if words and not body.get("summary"):
            body["summary"], files = words[0][:MAX_SUMMARY], words[1:]
        else:
            files = words
        return (a.kind, a.topic, body, (a.paths.split(",") if a.paths else (files or None)), a.commit, a.before_commit, "",
                a.sources.split(",") if a.sources else [], a.supersedes.split(",") if a.supersedes else [])
    if fields:
        obj = _parse_fields(sys.stdin.read())
    else:
        try:
            obj = json.loads(sys.stdin.read())
        except ValueError as ex:
            raise SystemExit(f"logbook: --json needs a JSON object on stdin ({ex})")
    if not isinstance(obj, dict):
        raise SystemExit("logbook: --json needs a JSON object on stdin")
    body = {k: str(obj[k]) for k in BODY_FIELDS if obj.get(k)}
    paths = obj.get("paths")
    paths = [str(p) for p in paths] if isinstance(paths, list) else (str(paths).split(",") if paths else None)
    ids = lambda k: [str(x) for x in obj.get(k) or []] if isinstance(obj.get(k), list) else []
    return (obj.get("kind") if obj.get("kind") in ("finding", "change", "summary") else "finding", str(obj.get("topic") or ""), body, paths,
            str(obj.get("commit") or "") or None, bool(obj.get("before_commit")), str(obj.get("level") or ""), ids("sources"), ids("supersedes"))


def cmd_note(a):
    r = need_repo()
    kind, topic, body, paths, commit, before_commit, level, sources, supersedes = _note_input(a)
    sources = [x.strip() for x in sources if x.strip()]
    supersedes = [x.strip() for x in supersedes if x.strip()]
    bad = [x for x in sources + supersedes if not ID_RE.match(x)]
    if bad:
        raise SystemExit(f"logbook: {bad[0]!r} is not a note id (see `logbook context` or `logbook ask`)")
    mine = {l.entry.id for l in r.all_entries() if l.user == r.user}
    foreign = [x for x in supersedes if x not in mine]
    if foreign:
        raise SystemExit(f"logbook: {foreign[0]} is not one of your notes; only the author can supersede a note")
    if not body.get("summary"):
        raise SystemExit("logbook: a summary is required (what happened, in a few sentences)")
    if kind == "finding" and not (body.get("why") or body.get("wrong")) and capture.writer() == "agent-written":
        out("note: no why/wrong given; this entry will be searchable but never injected into agent context")
    sha = None
    if commit:
        if before_commit:
            raise SystemExit("logbook: --commit and --before-commit cannot be used together")
        rc, full, _ = g.try_run(["rev-parse", "--verify", "--quiet", commit + "^{commit}"], r.root)
        if rc != 0 or not full.strip():
            raise SystemExit(f"logbook: no commit {commit!r} in this repo")
        sha = full.strip()
    topic = topic or body["summary"][:80]
    pending = before_commit and kind == "change"
    # Grounding: look up what the note names. Whether it is true cannot be checked; whether it points at something real can.
    cks = ground.check(r, body, topic, paths if paths is not None else (g.changed_paths(r.root, sha) if sha else []), sha)
    near = [o for o in (ground.overlaps(views(r)[0], topic, body["summary"], cks["files"]) if kind != "summary" else [])
            if o["id"] not in supersedes]
    out("grounding: " + ground.line(cks))
    agent = capture.writer() == "agent-written"
    size = ground.size_problems(kind, body) if agent else []
    for p in ground.problems(cks, agent) + size:
        out("  ! " + p)
    for o in near:
        out(f"  ~ may overlap {o['id']} ({'yours' if o['mine'] else 'a teammate'}): {o['topic'][:70]}")
    if near:
        out('    if this replaces it, add the line supersedes: <id> (your own notes only); otherwise say in the note why both stand')
    if a.check:
        out("(checked only: nothing was saved)")
        return 0
    if size:
        raise SystemExit("logbook: not saving the note, it has " + size[0])
    if kind != "summary" and agent and not cks["evidence"] and not a.allow_ungrounded:
        raise SystemExit("logbook: not saving a note with no evidence. Add an evidence: line with what you ran or read (a command and its result, "
                         "or file:line); naming a file is not enough. --allow-ungrounded saves it anyway, marked unverified.")
    e = capture.make_entry(r, kind, topic, body, paths=paths, via="cli", sha=sha, level=level, sources=sources, supersedes=supersedes,
                           pending=pending, checks=cks)
    shared = not pending and auto_publish(r, e)
    out(f"recorded {e.id} ({'pending: attaches to your next commit' if pending else 'published (auto mode)' if shared else 'private'})")


def auto_publish(r, e):
    """Publish mode auto: share a note as soon as it is written, redacted exactly as `logbook publish` would. A note the checks refuse
    (pasted table rows, too big, a teammate already shared the same words) stays private. Pushing is still `logbook sync`."""
    if r.publish_mode() != "auto" or e.provenance == "auto-copied":
        return False
    bad = ground.problems(e.checks, e.provenance != "user-written")
    if bad:  # a note that names something that is not there, or an agent's that points at nothing, is not shared on its own
        print("logbook: not shared automatically (" + "; ".join(bad)[:120] + "); it stays private", file=sys.stderr)
        return False
    try:
        c, _ = share_copy(r, e, False, False)
        if r.duplicate_of(c):
            return False
        r.publish([c])
    except (SystemExit, ValueError) as ex:
        print(f"logbook: not shared automatically ({ex}); it stays private", file=sys.stderr)
        return False
    r.drop_private(e.id)
    return True


def share_copy(r, e, include_evidence, allow_table):
    """Build the exact object that would be published: allowlisted, redacted, size-capped. Returns (entry, findings)."""
    deny = r.cfg().get("deny", [])
    found = []
    fields = SHARE_FIELDS + (("evidence",) if include_evidence else ())
    body = {}
    for k in fields:
        if e.body.get(k):
            body[k], f = redact(e.body[k], deny)
            found += f
    if not allow_table and any(looks_tabular(v) for v in body.values()):
        raise SystemExit("logbook: a field looks like pasted table rows; refusing. Remove it, or pass --allow-table after checking it.")
    c = e.copy(body=body, redacted=True, display=r.cfg().get("display", "") if r.attribution() == "named" else "")
    c.topic, f = redact(e.topic, deny)
    found += f
    a = dict(e.anchor)
    for k in ("subject", "branch"):
        a[k], f = redact(a.get(k, ""), deny)
        found += f
    c.anchor = a
    return c, found


def cmd_publish(a):
    r = need_repo()
    if r.publish_mode() == "never":
        raise SystemExit("logbook: publishing is off: the publish mode is never, or this repo's policy turns it off (.logbook/policy.json)")
    ready = []
    if getattr(a, "all", False):
        ids = r.unpublished()
    elif a.ids:
        ids = a.ids
    else:
        ids = _pick_unpublished(r)
    ids = [e.id if hasattr(e, "id") else e for e in ids]
    if not ids:
        out("nothing to publish.")
        return 0
    for eid in ids:
        e = r.get_private(eid)
        if not e:
            raise SystemExit(f"logbook: no private entry {eid}")
        c, found = share_copy(r, e, a.include_evidence, a.allow_table)
        dup = r.duplicate_of(c)
        if dup and dup[0] == "same-id":
            out(f"skipped {eid}: already shared.")
            continue
        if dup and not getattr(a, "force", False):
            out(f"skipped {eid}: {r.label(dup[1])} already shared the same text ({dup[1].entry.id}). --force publishes it anyway.")
            continue
        text = c.to_json()
        out(f"--- would publish {eid} (redaction: {len(found)} item(s) masked{': ' + ', '.join(sorted(set(found))) if found else ''})")
        out(text)
        ready.append((c, digest_hash(text)))
    if not ready:
        out("nothing new to publish.")
        return 0
    out("Published entries cannot be fully recalled: forks and mirrors may keep copies. Rotate any secret that appears above.")
    if not a.yes and _ask("Publish exactly the text above? [y/N] ").strip().lower() != "y":
        raise SystemExit("aborted; nothing published")
    for c, h in ready:
        if digest_hash(c.to_json()) != h:
            raise SystemExit("logbook: entry changed after preview; aborting")
    ref = r.publish([c for c, _ in ready])
    keep = getattr(a, "keep", False)
    if not keep:  # a move, not a copy: the shared (redacted) text replaces the private original
        for c, _ in ready:
            r.drop_private(c.id)
    out(f"published {len(ready)} entr{'y' if len(ready) == 1 else 'ies'} to {ref} (local"
        f"{'' if keep else '; the private copy was removed, --keep leaves it'}). `logbook sync` pushes it.")
    if a.push:
        out(json.dumps(sync.push(r)))


def _ask(prompt):
    try:
        return input(prompt)
    except EOFError:
        return ""


def _pick_unpublished(r):
    """Numbered list of private notes not shared yet; asks which ones when a person is at the keyboard."""
    q = sorted(r.unpublished(), key=lambda e: e.id, reverse=True)
    for i, e in enumerate(q, 1):
        out(f"  {i}. {e.id}  {e.kind:<8} {e.topic[:70]}")
    if not q:
        return []
    if not sys.stdin.isatty():
        out("pass ids to publish, or --all")
        return []
    try:
        ans = input("which ones? (numbers like 1,3 / all / empty to cancel) ").strip().lower()
    except EOFError:
        return []
    if ans == "all":
        return q
    want = {int(x) for x in ans.replace(" ", "").split(",") if x.isdigit()}
    return [e for i, e in enumerate(q, 1) if i in want]


def cmd_sync(a):
    r = need_repo()
    res = sync.sync(r, a.remote, a.fetch_only, a.depth)
    out(json.dumps(res, indent=2))
    return 0 if res["fetch"]["ok"] and res.get("push", {"ok": True})["ok"] else 1


def cmd_query(a):
    r = need_repo()
    vs, an = views(r)
    ranked = recall.rank(r, query=a.q, views=vs, anch=an)[: a.limit]
    if not ranked:
        out("no match")
        return 4
    for s, v in ranked:
        out(line(v))
    return 0


def cmd_explain(a):
    r = need_repo()
    vs, an = views(r)
    by_prefix = [v for v in vs if v["id"].startswith(a.target)]
    if ID_RE.match(a.target) or len(by_prefix) >= 1 and len(a.target) >= 6:
        if len(by_prefix) > 1:
            out("ambiguous:")
            [out("  " + v["id"]) for v in by_prefix]
            return 3
        if by_prefix:
            out(detail(by_prefix[0]))
            return 0
    names = {a.target.lower()}
    cands = {m.lower() for v in vs for m in v["names"] if a.target.lower() in m.lower()}
    exact = {m for m in cands if m == a.target.lower()}
    if not exact and len(cands) > 1:
        out("ambiguous: " + ", ".join(sorted(cands)))
        return 3
    if not exact and cands:
        names = cands
    ranked = recall.rank(r, names=names, files=[a.target], views=vs, anch=an)
    if not ranked:
        if not getattr(a, "quiet", False):
            out(f"nothing recorded for {a.target}")
        return 4
    known = sorted({n for m in names for n in tree.aliases_for(r, m)})
    if len(known) > 1:
        out("known under names: " + ", ".join(known) + "  (rename detection is heuristic)")
    for _, v in ranked:
        out(detail(v))
        out("")
    return 0


def cmd_path(a):
    r = need_repo()
    rc, o, _ = g.try_run(["rev-list", "--first-parent", "--reverse", f"{a.a}..{a.b}"], r.root)
    if rc:
        out("no match: could not resolve both revisions")
        return 4
    vs, an = views(r)
    by = {}
    for v in vs:
        by.setdefault(v["placed"], []).append(v)
    shas = o.split()
    if not shas:
        out("no commits between those revisions")
        return 4
    for s in shas:
        info = g.commit_info(r.root, s) or {}
        out(f"{s[:8]}  {info.get('subject', '')}")
        for v in by.get(s, []):
            out("    - " + v["topic"] + f"  [{v['kind']}, {v['author']}]")
    return 0


def _entry_line(v, verbose):
    who = v["author"] + (", private" if v["scope"] == "private" else "")
    head = f"{txt(v, v['topic'], 120)}  ({who}, {v['created'][:10]})"
    rows = [head]
    for k in (("summary", "why", "wrong", "fix", "decided", "open") if verbose else ()):
        if v["body"].get(k):
            rows.append(f"        {k}: {txt(v, v['body'][k])}")
    return "\n".join(rows)


def _log_commit(c, verbose, indent=""):
    merge = c.get("merge") or {}
    out(f"{indent}{c['short']}  {c['subject']}{'  (merge)' if merge else ''}")
    for v in c["entries"]:
        out(f"{indent}    - {_entry_line(v, verbose)}")
    for k in merge.get("commits", []):
        _log_commit(k, verbose, indent + "    ")
    if merge.get("more"):
        out(f"{indent}    ... {merge['more']} more commits in that branch")


def cmd_log(a):
    """The notes next to your commits, newest first, in the terminal."""
    r = need_repo()
    t = tree.build(r)
    for s in t["summaries"]:
        where = "repo" if s["level"] == "repo" else f"branch {s['branch']}"
        out(f"[{where} summary{'' if s['fresh'] else ', out of date'}] {s['topic']}")
        out("    " + (s["summary"] if s["mine"] else safety_sanitize(s["summary"], 600)))
    rows = [c for c in t["commits"] if a.verbose or c["entries"] or not c["trivial"]][: a.n]
    for c in rows:
        _log_commit(c, a.verbose)
    for u in t["unplaced"]:
        out(f"notes on branch {u['branch']} (not on this history yet)")
        for v in u["entries"]:
            out(f"    - {_entry_line(v, a.verbose)}")
    cov = t["coverage"]
    need = cov["commits"] - cov["trivial"]
    out(f"{cov['with_reason']} of {need} recent commits say why.")
    return 0


def _is_rev(r, w):
    return g.try_run(["rev-parse", "--verify", "-q", w + "^{commit}"], r.root)[0] == 0


def _show_node(r, address):
    """One node of the tree: where it sits, its summary, and what is below it. The way down to the original is `git show`."""
    nodes = nav.build(r)
    n, why = nav.resolve(nodes, address)
    if not n:
        out(why)
        return 3 if why.startswith("ambiguous") else 4
    out("path: " + " > ".join(nav.path(nodes, n)))
    if n["kind"] == "note":
        out(detail(n["view"]))
        return 0
    out(f"{n['addr']}  {n['title']}")
    s = n["summary"]
    if s:
        out(f"summary ({'current' if s['fresh'] else 'out of date'}, from {s['count']} notes, by {s['author']}): "
            + (s["summary"] if s["mine"] else safety_sanitize(s["summary"], 600)))
    elif n["kind"] in ("repo", "branch"):
        out("summary: none yet (an agent can write one: `logbook summarize`)")
    if n["kind"] == "commit":
        body = g.commit_body(r.root, n["sha"])
        if body:  # the whole message comes from git; a note holds only what git does not have
            out("message:\n" + "\n".join("  " + safety_sanitize(ln, 200) for ln in body.splitlines()[:40]))
        out(f"original: git show {n['sha'][:8]}")
    out(f"below ({len(n['children'])}):")
    for k in n["children"]:
        c = nodes[k]
        out(f"  {k}  " + (_entry_line(c["view"], False) if c["kind"] == "note" else c["title"]))
    return 0


def cmd_ask(a):
    """One way in: a revision range, an id, a file or name, or free text."""
    r = need_repo()
    words = a.what
    if len(words) == 1 and nav.looks_like_address(words[0]):
        return _show_node(r, words[0])
    if len(words) == 1 and ".." in words[0]:
        words = words[0].split("..", 1)
    if len(words) == 2 and all(_is_rev(r, w) for w in words):
        return cmd_path(argparse.Namespace(a=words[0], b=words[1]))
    if len(words) == 1:
        code = cmd_explain(argparse.Namespace(target=words[0], quiet=True))
        if code != 4:
            return code
    return cmd_query(argparse.Namespace(q=" ".join(words), limit=a.limit))


def cmd_setup(a):
    """init (or join, when there is a remote) and install, in one go."""
    r = Repo(".")
    if "origin" in sync.remotes(r):
        cmd_join(argparse.Namespace(remote="origin"))
    else:
        cmd_init(argparse.Namespace(attribution=None))
    return cmd_install(a)


def cmd_status(a):
    r = need_repo()
    vs, an = views(r)
    shared, _ = r.load_shared()
    spool = list((r.cdir / "spool").glob("*.json")) if (r.cdir / "spool").exists() else []
    sess = [p for p in (r.cdir / "sessions").iterdir()] if (r.cdir / "sessions").exists() else []
    out(f"you: {r.user}  attribution: {r.attribution()}  transport: {r.cfg().get('transport', 'refs')}")
    out(f"entries: {len(vs)} visible ({sum(1 for v in vs if v['scope'] == 'private')} private, "
        f"{sum(1 for v in vs if v['scope'] == 'shared')} shared) from {len({l.user for l in shared})} writers")
    out(f"capture: {len(spool)} spooled events waiting, {len([s for s in sess if s.is_dir()])} sessions seen")
    if an.shallow:
        out("note: shallow clone; some anchors are unverified")
    if not shared and (r.cdir / "private").exists():
        out("note: nothing shared yet: `logbook publish` then `logbook sync`; or `logbook setup` to fetch teammates' entries")
    stale = [s for s in tree.summaries(vs) if not s["fresh"]]
    if stale:
        out(f"{len(stale)} summary(ies) out of date: `logbook summarize` briefs an agent to refresh them")
    waiting = len(r.unpublished()) if r.publish_mode() != "never" else 0
    if waiting:
        out(f"{waiting} private note(s) not shared yet: `logbook publish`")
    if getattr(a, "check", False):
        out("")
        cmd_doctor(argparse.Namespace(remote="origin"))
    if getattr(a, "stats", False):
        out("")
        cmd_stats(a)


def cmd_doctor(a):
    r = need_repo()
    bad = False
    for level, msg in sync.doctor(r, a.remote):
        out(f"[{level:<4}] {msg}")
        bad |= level == "fail"
    from . import install as ins
    out("what is installed here (`logbook install` sets it up, `logbook uninstall` removes it):")
    out(f"  git hooks   : post-commit {'installed' if ins.git_hook_installed(r) else 'missing'}, "
        f"pre-push {'installed' if ins.git_hook_installed(r, 'pre-push') else 'missing'}")
    cov = tree.build(r)["coverage"]
    need = cov["commits"] - cov["trivial"]
    out(f"  coverage    : {cov['with_reason']} of {need} recent commits have a note that says why ({cov['trivial']} trivial: chores, merges, whitespace)")
    for sm in tree.summaries(views(r)[0]):
        node = "repo" if sm["level"] == "repo" else "branch " + sm["branch"]
        out(f"  summary     : {node}: {'up to date' if sm['fresh'] else str(sm['new_notes']) + ' newer note(s), stale (logbook summarize)'}")
    for t, st in ins.status(r).items():
        out(f"  {t:<12}: {st}")
    out("  Only Claude Code has hooks (it captures sessions and shows notes automatically). The other agents get the rules")
    out("  file only, so they rely on the agent following it; the git hook is the same for everyone.")
    return 1 if bad else 0


def cmd_reconcile(a):
    r = need_repo()
    res = capture.reconcile(r)
    if not a.quiet:
        out(json.dumps(res))


def cmd_capture(a):
    try:
        text = capture.handle_hook(a.event, a.agent, sys.stdin.read() if not sys.stdin.isatty() else "")
        if text:
            sys.stdout.write(text)
    except Exception:
        pass
    return 0  # a hook must never fail the agent


def cmd_post_commit(a):
    try:  # attach pending entries now (fast); the sweep for hook-less commits runs detached so the commit never waits
        r = Repo(".")
        capture.post_commit(r)
        capture.spawn_detached([r.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", "reconcile", "--quiet"], r.root)
    except Exception:
        pass
    return 0


def cmd_install_hook(a):
    r = need_repo()
    f = capture.uninstall_git_hook(r) if a.remove else capture.install_git_hook(r)
    out(f"{'removed from' if a.remove else 'installed in'} {f}")


def _targets(a, default):
    from . import install as ins
    picked = list(a.agent or [])
    if not picked or "auto" in picked:
        return default
    bad = [t for t in picked if t not in ins.TARGETS]
    if bad:
        raise SystemExit(f"logbook: unknown agent {bad[0]!r}; choose from {', '.join(ins.TARGETS)} or auto")
    return picked


def _confirm(a, lines):
    if a.dry_run:
        out("(dry run: nothing written)")
        return False
    if a.yes or a.write:
        return True
    if sys.stdin.isatty():
        try:
            return input("Apply these changes? [y/N] ").strip().lower() == "y"
        except EOFError:
            return False
    out("(not applied: run again with --yes to apply)")
    return False


def cmd_install(a):
    """One command: init if needed, the git hook, and for each agent its hooks, skill and always-on rules."""
    from . import install as ins
    r = Repo(".")
    targets = _targets(a, ins.detect(r.root))
    out("logbook will make these changes (existing files are backed up to .git/logbook/backups):")
    lines = ins.describe(r, targets, pretool=not a.no_pretool)
    for line in lines:
        out(line)
    if not _confirm(a, lines):
        return 0
    if not r.cfg().get("user"):
        r.init()
    ins.apply(r, targets, pretool=not a.no_pretool)
    out("done. `logbook doctor` shows what is installed; `logbook uninstall` reverses it.")
    if "claude-code" in targets:
        out("Claude Code will be asked once to record a note before it finishes a turn that read or searched 3 or more times and wrote")
        out("none. `logbook config nudge context` makes that a reminder on the next prompt, `logbook config nudge off` turns it off.")
    return 0


def cmd_uninstall(a):
    from . import install as ins
    r = Repo(".")
    targets = _targets(a, list(ins.TARGETS))
    out("logbook will remove its own changes (your notes are kept; files are backed up first):")
    for line in ins.describe(r, targets, remove=True):
        out(line)
    if not _confirm(a, None):
        return 0
    ins.apply(r, targets, remove=True)
    out("done.")
    return 0


CONFIG_KEYS = {"nudge": ("off", "context", "block"), "nudge_after": None, "block_after": None, "publish": PUBLISH_MODES}


def cmd_queue(a):
    """Private notes that are not shared yet. Sharing stays your decision: this only lists, and `publish` previews and asks."""
    r = need_repo()
    q = r.unpublished() if r.publish_mode() != "never" else []
    if a.hook:
        said = []
        if q:
            said.append(f"{len(q)} private note(s) are not shared with your team yet (`logbook publish` shows what would be shared and asks first).")
        if "origin" in sync.remotes(r) and sync.unpushed(r):
            said.append("your published notes are not pushed yet (`logbook sync` pushes them).")
        if said:
            print("logbook: " + " ".join(said), file=sys.stderr)
        return 0
    if not q:
        out("nothing waiting: every note of yours is shared, auto-copied, or publishing is off for this repo.")
        return 0
    out(f"{len(q)} private note(s) not shared yet (newest first):")
    for e in sorted(q, key=lambda x: x.id, reverse=True):
        out(f"  {e.id}  {e.kind:<8} {e.topic[:80]}")
    out("`logbook publish --all` previews them with redaction and asks once; `logbook publish <id>` does one.")
    return 0


def cmd_config(a):
    r = need_repo()
    c = r.cfg()
    if not a.key:
        for k in CONFIG_KEYS:
            out(f"{k} = {('off' if c.get(k) is False else c.get(k)) if k in c else '(default)'}")
        return 0
    if a.key not in CONFIG_KEYS:
        raise SystemExit(f"logbook: unknown setting {a.key!r}; choose from {', '.join(CONFIG_KEYS)}")
    if a.value is None:
        out(r.publish_mode() if a.key == "publish" else str(c.get(a.key, "(default)")))
        return 0
    allowed = CONFIG_KEYS[a.key]
    if allowed and a.value not in allowed:
        raise SystemExit(f"logbook: {a.key} must be one of {', '.join(allowed)}")
    if not allowed and not a.value.isdigit():
        raise SystemExit(f"logbook: {a.key} must be a number")
    c[a.key] = False if a.value == "off" else int(a.value) if a.value.isdigit() else a.value
    r.save_cfg(c)
    out(f"{a.key} = {a.value}")
    return 0


def cmd_context(a):
    """What an agent needs to write the note for a commit: whether it needs one, and which of your findings it grew out of."""
    r = need_repo()
    if a.commit:
        rc, full, _ = g.try_run(["rev-parse", "--verify", "--quiet", a.commit + "^{commit}"], r.root)
        if rc != 0:
            raise SystemExit(f"logbook: no commit {a.commit!r} in this repo")
        paths = g.changed_paths(r.root, full.strip())
        what = f"commit {full.strip()[:8]}"
        rc, num, _ = g.try_run(["show", "-w", "-M", "--numstat", "--format=", full.strip()], r.root)
    else:
        staged = [x for x in g.try_run(["diff", "--cached", "--name-only"], r.root)[1].split() if x]
        paths = staged or [x for x in g.try_run(["diff", "--name-only", "HEAD"], r.root)[1].split() if x]
        what = "the staged changes" if staged else "the working tree"
        rc, num, _ = g.try_run(["diff", "--cached", "-w", "-M", "--numstat"], r.root)
    rows = [ln.split(chr(9))[:2] for ln in num.splitlines() if ln.strip()] if rc == 0 else []
    trivial = bool(paths) and all(x == ["0", "0"] for x in rows)
    out(f"Context for {what}: {len(paths)} file(s) changed" + ("; whitespace or renames only, so a note is optional." if trivial else "."))
    vs, _ = views(r)
    cited = {x for v in vs for x in v["sources"]}
    mine = [v for v in vs if v["mine"] and v["kind"] == "finding" and v["provenance"] != "auto-copied" and v["id"] not in cited]
    want, want_names = set(paths), set(tree.names_of(paths))
    near = [v for v in mine if want & set(v["paths"]) or want_names & set(v["names"])]
    if near:
        out("Your findings that touch these files and are not yet part of a change note:")
        for v in sorted(near, key=lambda x: x["id"], reverse=True)[:8]:
            out(f"  {v['id']}  {txt(v, v['topic'], 90)}  -  {txt(v, v['body'].get('summary', ''), 140)}")
        out('Cite the ones this change grew out of: a sources: <id>, <id> line in the note (logbook note --fields).')
    else:
        out(f"No unlinked finding of yours touches these files ({len(mine)} other unlinked finding(s); `logbook query` finds them).")
    return 0


def cmd_summarize(a):
    """Brief an agent on the notes under a node (the repo, or a branch) so it can write the summary. No model call here."""
    r = need_repo()
    vs, _ = views(r)
    cur = g.branch(r.root)
    if a.branch:
        level, branch = "branch", a.branch
    elif a.repo or not cur or cur == tree.default_branch(r):
        level, branch = "repo", ""
    else:
        level, branch = "branch", cur
    pool = tree.under(vs, level, branch)
    where = "the repo" if level == "repo" else f"branch {branch}"
    if not pool:
        out(f"nothing to summarise: no note with a reason under {where}.")
        return 0
    prev = next((s for s in tree.summaries(vs) if s["level"] == level and s["branch"] == branch), None)
    if prev and prev["fresh"]:
        out(f"The summary of {where} is up to date (built from {prev['count']} notes). Nothing to do.")
        return 0
    out(f"Summarise {where} from these {len(pool)} notes (newest first). Keep what still stands, drop what newer notes overturned,")
    out("and add no claim the notes do not support. 4 to 8 sentences, at most 1000 characters: what is known, what was decided, what is open.")
    if prev:
        out(f"Previous summary ({prev['new_notes']} newer note(s) since): {prev['summary'][:700]}")
    for v in pool:
        out("")
        out(f"{v['id']}  {v['kind']}  {v['author']}  {txt(v, v['topic'], 90)}")
        for k in ("summary", "why", "wrong", "decided", "open"):
            if v["body"].get(k):
                out(f"    {k}: {txt(v, v['body'][k], 200)}")
    out("")
    out("Record it with `logbook note --fields`:")
    out(json.dumps({"kind": "summary", "level": level, "topic": f"Summary of {where}", "summary": "<your summary>",
                    "sources": [v["id"] for v in pool]}))
    return 0


def cmd_backfill(a):
    """Brief an agent on commits that have no note saying why, so it can write one from the diff. Makes no model call itself."""
    r = need_repo()
    vs, an = views(r)
    explained = {v["placed"] for v in vs if v["body"].get("why") or v["body"].get("wrong")}
    if a.shas:
        picked = []
        for x in a.shas:
            rc, full, _ = g.try_run(["rev-parse", "--verify", "--quiet", x + "^{commit}"], r.root)
            if rc != 0:
                raise SystemExit(f"logbook: no commit {x!r} in this repo")
            picked.append(full.strip())
    else:
        recent = an.sp[:a.scan]
        triv = tree.trivial_shas(r, recent)
        picked = [c["sha"] for c in recent if c["sha"] not in explained and c["sha"] not in triv][:a.limit]
    if not picked:
        out("nothing to backfill: every recent commit has a note saying why, or is trivial.")
        return 0
    out(f"{len(picked)} commit(s) have no note saying why. For each, write one only if the change needed real thought;")
    out('use `logbook note --fields` with the line commit: <sha>. Base it on the message and diff below, mark anything you inferred as')
    out("not verified, and do not invent motives. Skip chores.")
    for sha in picked:
        info = g.commit_info(r.root, sha) or {}
        body = g.try_run(["show", "-s", "--format=%b", sha], r.root)[1].strip()
        stat = g.try_run(["show", "--stat", "--format=", sha], r.root)[1].strip()
        diff = g.try_run(["show", "-w", "-M", "--format=", "--unified=2", sha], r.root)[1]
        out("")
        out("=" * 72)
        out(f"commit {sha}  {info.get('subject', '')}")
        if body:
            out(body[:1200])
        out(stat[:1200])
        out(diff[:a.max_diff])
        if len(diff) > a.max_diff:
            out(f"... diff cut at {a.max_diff} characters")
    return 0


def cmd_purge(a):
    r = need_repo()
    ref = r.purge(a.id)
    if not ref:
        out(f"no published entry {a.id} on your ref (private copy removed if present)")
        r.drop_private(a.id)
        return 4
    out(f"rewrote {ref} without {a.id} and left an id-only tombstone; private copy removed")
    out("Forks, mirrors and anyone who already fetched may keep a copy. ROTATE ANY SECRET that was in it.")
    if a.push:
        out(json.dumps(sync.push(r, force=True)))
    else:
        out("run `logbook sync` after `logbook purge --push`, or re-run with --push (it must be a forced push of your own ref)")


def cmd_gc(a):
    r = need_repo()
    if not a.yes:
        raise SystemExit("logbook gc squashes your own ref to one commit (loses its commit history). Re-run with --yes.")
    ref = r.squash_own_ref()
    out(f"squashed {ref}" if ref else "nothing to squash")
    if ref and a.push:
        out(json.dumps(sync.push(r, force=True)))


def cmd_trust(a):
    r = need_repo()
    c = r.cfg()
    t = set(c.get("trusted", []))
    (t.discard if a.remove else t.add)(a.user)
    c["trusted"] = sorted(t)
    r.save_cfg(c)
    pol = r.policy().get("inject_from")
    out(f"trusted: {', '.join(c['trusted']) or '(none: only your own entries are injected)'}" + (f"\nnote: repo policy inject_from={pol} limits this" if pol == "self" else ""))


def cmd_inject(a):
    r = need_repo()
    text = recall.digest(r, a.event, a.prompt or "", a.file or [], a.session or "")
    out(text if text else "(nothing to inject)")


def cmd_snippet(a):
    from . import install as ins
    out(ins.asset("rules.md").rstrip())


def cmd_stats(a):
    r = need_repo()
    p = r.cdir / "injections.log"
    rows = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []
    out(f"injections: {len(rows)}, entries shown: {sum(len(x['ids']) for x in rows)}, chars injected: {sum(x['chars'] for x in rows)}")
    nl = r.cdir / "nudges.log"
    nudges = len([x for x in nl.read_text(encoding="utf-8").splitlines() if x.strip()]) if nl.exists() else 0
    mine = [l.entry for l in r.all_entries() if l.user == r.user]
    out(f"nudges sent: {nudges}; your notes: {sum(1 for e in mine if e.provenance != 'auto-copied')} written, "
        f"{sum(1 for e in mine if e.provenance == 'auto-copied')} auto-copied")
    out("model calls: 0 (backend none)")


def cmd_cites(a):
    """The numbered sources behind an answer in this chat. Teammates' shared notes carry a link, a name and a date."""
    r = need_repo()
    session = a.session or cites.latest_session(r)
    if a.where:  # the answers in this chat that cite this number, from Claude Code's transcript of it
        out(json.dumps({"session": session, "hits": cites.hits(session, a.where)}, ensure_ascii=False))
        return 0
    vs, _ = views(r)
    recs = cites.records(r, session, vs)
    if a.json:
        out(json.dumps({"session": session, "mode": r.publish_mode(), "sources": recs}, ensure_ascii=False))
        return 0
    if not recs:
        out("no notes have been numbered in this chat yet")
        return 4
    out(cites.text(recs, expanded=not a.compact))
    return 0


def cmd_demo(a):
    from . import demo
    return demo.run(a.dir)


HIDDEN = {"init", "join", "query", "explain", "path", "doctor", "queue", "stats", "install", "install-hook", "capture", "post-commit",
          "reconcile", "inject", "context", "summarize", "backfill", "trust", "purge", "gc", "config", "uninstall", "snippet", "demo",
          "cites"}
HELP_MORE = """more (run `logbook <name> -h`):
  trust purge gc config uninstall snippet demo
agents and hooks call these; you rarely need to:
  context summarize backfill inject cites capture post-commit reconcile
older names that still work:
  init join query explain path doctor queue stats install install-hook"""


def build_parser():
    p = argparse.ArgumentParser(prog="logbook", formatter_class=argparse.RawDescriptionHelpFormatter,
                                description="Commit-anchored shared memory for AI-assisted repos.", epilog=HELP_MORE)
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(name, fn, help="", **_):
        # hidden ones still run; argparse lists a command only when `help` is passed at all, even as None
        sp = sub.add_parser(name, **({} if name in HIDDEN else {"help": help}))
        sp.set_defaults(fn=fn)
        return sp

    s = add("setup", cmd_setup, "set up this repo: your id, git hook, agent hooks, skill and rules (asks first)")
    s.add_argument("--agent", nargs="+", metavar="AGENT", help="claude-code agents-md copilot gemini cursor, or auto (default)")
    s.add_argument("--yes", action="store_true", help="apply without asking")
    s.add_argument("--write", action="store_true", help="same as --yes")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--no-pretool", action="store_true", help="do not add the before-read/edit note lookup")
    s = add("ask", cmd_ask, "search the notes; explain an id, a file or name, or a range (a..b); open a node (repo, branch:x, commit:y, note:z)")
    s.add_argument("what", nargs="+")
    s.add_argument("--limit", type=int, default=10)
    s = add("log", cmd_log, "the notes next to your commits, newest first")
    s.add_argument("-n", type=int, default=20, help="how many commits")
    s.add_argument("-v", "--verbose", action="store_true", help="show each note's text and trivial commits")
    s = add("init", cmd_init, "create your id and config")
    s.add_argument("--attribution", choices=["none", "pseudonym", "named"])
    s = add("join", cmd_join, "init + fetch teammates' entries (run this after cloning)")
    s.add_argument("--remote", default="origin")
    s = add("note", cmd_note, "record a finding or change in your private log")
    s.add_argument("text", nargs="*", help="the note, in plain words, then the files it is about: logbook note \"late export dips revenue\" shop/revenue.py")
    s.add_argument("--kind", choices=["finding", "change", "summary"], default="finding")
    s.add_argument("--topic")
    for k in BODY_FIELDS:
        s.add_argument(f"--{k}")
    s.add_argument("--paths", help="comma-separated; defaults to the commit's files / working tree")
    s.add_argument("--before-commit", action="store_true", help="change entry: attach to the next commit")
    s.add_argument("--commit", help="write the note about this earlier commit instead of HEAD")
    s.add_argument("--sources", help="comma-separated ids of the findings this note was written from")
    s.add_argument("--from-stdin", action="store_true", help="read the summary from stdin (for agents without hooks)")
    s.add_argument("--json", action="store_true", help="read the whole note as a JSON object on stdin")
    s.add_argument("--fields", action="store_true", help="read the whole note as `key: value` lines on stdin (no braces or quotes: what an agent should use)")
    s.add_argument("--supersedes", help="comma-separated ids of your own notes this one replaces")
    s.add_argument("--check", action="store_true", help="only look up what the note names and report; save nothing")
    s.add_argument("--allow-ungrounded", action="store_true", help="save a finding or change with no evidence line, marked unverified")
    s = add("publish", cmd_publish, "share private entries (preview + redaction, per entry)")
    s.add_argument("ids", nargs="*")
    s.add_argument("--all", action="store_true", help="every private note not shared yet (same preview and one confirmation)")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--push", action="store_true")
    s.add_argument("--include-evidence", action="store_true")
    s.add_argument("--allow-table", action="store_true")
    s.add_argument("--keep", action="store_true", help="leave the private copy in place after publishing")
    s.add_argument("--force", action="store_true", help="publish even if a teammate already shared the same text")
    s = add("sync", cmd_sync, "fetch teammates' entries and push yours")
    s.add_argument("--remote", default="origin")
    s.add_argument("--fetch-only", action="store_true")
    s.add_argument("--depth", type=int)
    s = add("query", cmd_query, "search entries")
    s.add_argument("q")
    s.add_argument("--limit", type=int, default=10)
    s = add("explain", cmd_explain, "everything known about an entry id, a model, or a path")
    s.add_argument("target")
    s = add("path", cmd_path, "commits (with their entries) between two revisions")
    s.add_argument("a")
    s.add_argument("b")
    s = add("status", cmd_status, "what is recorded, what is waiting to be shared (--check for problems)")
    s.add_argument("--check", action="store_true", help="also run the setup and coverage checks")
    s.add_argument("--stats", action="store_true", help="also show injection and cost counters")
    s = add("doctor", cmd_doctor, "check setup and capture coverage")
    s.add_argument("--remote", default="origin")
    s = add("reconcile", cmd_reconcile, "process spooled events, recover sessions, record uncovered commits")
    s.add_argument("--quiet", action="store_true")
    s = add("capture", cmd_capture, "hook entry point (reads JSON on stdin; never fails)")
    s.add_argument("--event", required=True)
    s.add_argument("--agent", default="")
    add("post-commit", cmd_post_commit, "git hook entry point")
    s = add("install-hook", cmd_install_hook, "chain a post-commit hook (never overwrites yours)")
    s.add_argument("--remove", action="store_true")
    s = add("install", cmd_install, "set everything up: git hook, agent hooks, skill and rules (asks first)")
    s.add_argument("--agent", nargs="+", metavar="AGENT", help="claude-code agents-md copilot gemini cursor, or auto (default)")
    s.add_argument("--yes", action="store_true", help="apply without asking")
    s.add_argument("--write", action="store_true", help="same as --yes")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--no-pretool", action="store_true", help="do not add the before-read/edit note lookup")
    s = add("uninstall", cmd_uninstall, "remove what install added (notes are kept)")
    s.add_argument("--agent", nargs="+", metavar="AGENT")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--write", action="store_true")
    s.add_argument("--dry-run", action="store_true")
    s = add("context", cmd_context, "what to cite and whether a note is needed before you commit")
    s.add_argument("--commit", help="for an existing commit instead of the staged changes")
    s = add("summarize", cmd_summarize, "brief an agent on the notes under the repo or a branch so it can write the summary")
    s.add_argument("--repo", action="store_true", help="the whole repo even when on a branch")
    s.add_argument("--branch", help="a named branch")
    s = add("backfill", cmd_backfill, "brief an agent on commits with no note saying why, so it can write them")
    s.add_argument("shas", nargs="*")
    s.add_argument("--limit", type=int, default=3)
    s.add_argument("--scan", type=int, default=50, help="how many recent commits to look through")
    s.add_argument("--max-diff", type=int, default=6000)
    s = add("queue", cmd_queue, "list private notes that are not shared yet")
    s.add_argument("--hook", action="store_true", help="the quiet one-line reminder the pre-push hook prints")
    s = add("config", cmd_config, "show or set: nudge (off|context|block), nudge_after, block_after")
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")
    s = add("purge", cmd_purge, "remove a published entry from your ref")
    s.add_argument("id")
    s.add_argument("--push", action="store_true")
    s = add("gc", cmd_gc, "squash your own ref")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--push", action="store_true")
    s = add("trust", cmd_trust, "allow a writer's entries to be injected into your agent")
    s.add_argument("user")
    s.add_argument("--remove", action="store_true")
    s = add("inject", cmd_inject, "show what would be injected")
    s.add_argument("--event", default="UserPromptSubmit")
    s.add_argument("--prompt")
    s.add_argument("--file", action="append")
    s.add_argument("--session")
    add("stats", cmd_stats, "injection and cost counters")
    s = add("cites", cmd_cites, "the numbered sources behind an answer in a chat")
    s.add_argument("--session", help="the chat's id (default: the most recent one)")
    s.add_argument("--json", action="store_true")
    s.add_argument("--compact", action="store_true", help="one short line per source, no links")
    s.add_argument("--where", type=int, help="the answers in this chat that cite this number, as JSON (the band uses it)")
    add("snippet", cmd_snippet, "text to paste into CLAUDE.md / AGENTS.md / copilot-instructions for agents without hooks")
    s = add("demo", cmd_demo, "build a scratch two-person team and walk through it")
    s.add_argument("--dir")
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    a = build_parser().parse_args(argv)
    try:
        rc = a.fn(a)
    except g.GitError as ex:
        print(f"logbook: {ex}", file=sys.stderr)
        return 1
    return rc or 0
