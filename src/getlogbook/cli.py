"""logbook CLI. Exit codes for scripts: 0 found, 3 ambiguous (candidates listed), 4 nothing matched."""
from __future__ import annotations

import argparse
import json
import re
import sys
import time

from . import capture, cites, convo, ground, nav, outbox, recall, sync, tidy, tree
from . import git as g
from .entry import BODY_FIELDS, ID_RE, MAX_SUMMARY
from .safety import digest_hash, looks_tabular, redact
from .safety import sanitize as safety_sanitize
from .store import LEGACY_MODES, PUBLISH_MODES, Repo

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
    if v.get("status", "open") != "open":  # set by its author's status record; the reason and the commits come from that record
        rows.append(f"    status: {v['status']} (record {v['status_id']}; commits {', '.join(c[:8] for c in v['status_commits']) or '-'}): {txt(v, v['status_reason'], 300)}")
    home = v.get("log", "")
    if home:  # a note of yours made at a savepoint: the log it came from is on this machine
        rows.append(f"    from your log {home}: `logbook ask note:{home}` for the log, `logbook convo {home}` for the conversation")
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
    obj.pop("before_commit", None)  # a note is no longer held back for the next commit: the key is accepted and ignored
    return obj


def _note_input(a):
    """The note as (kind, topic, body, paths, commit, level, sources, supersedes), from flags, from `key: value` lines on stdin
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
        return (a.kind, a.topic, body, (a.paths.split(",") if a.paths else (files or None)), a.commit, "",
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
            str(obj.get("commit") or "") or None, str(obj.get("level") or ""), ids("sources"), ids("supersedes"))


def cmd_note(a):
    r = need_repo()
    kind, topic, body, paths, commit, level, sources, supersedes = _note_input(a)
    sources = [x.strip() for x in sources if x.strip()]
    supersedes = [x.strip() for x in supersedes if x.strip()]
    bad = [x for x in sources + supersedes if not ID_RE.match(x)]
    if bad:
        raise SystemExit(f"logbook: {bad[0]!r} is not a note id (see `logbook ask`)")
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
        rc, full, _ = g.try_run(["rev-parse", "--verify", "--quiet", commit + "^{commit}"], r.root)
        if rc != 0 or not full.strip():
            raise SystemExit(f"logbook: no commit {commit!r} in this repo")
        sha = full.strip()
    topic = topic or body["summary"][:80]
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
                           checks=cks)
    out(f"recorded {e.id} (private)")
    if a.queue:
        outbox.add(r, [e.id], "user")
        out("queued: `logbook publish` will share it (`logbook queue --remove` takes it back out)")


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


def cmd_convo(a):
    """Print the conversation behind one of your own logs (it never leaves this machine)."""
    r = need_repo()
    msgs = convo.load(r, a.id)
    if not msgs:
        raise SystemExit(f"logbook: no conversation is stored for {a.id}")
    for m in msgs:
        out(f"[{m.get('role', '?')}] {safety_sanitize(m['text'], 1500)}")
    return 0


def cmd_publish(a):
    r = need_repo()
    if r.publish_mode() == "never":
        raise SystemExit("logbook: publishing is off for this repo: its policy turns it off (.logbook/policy.json)")
    if r.publish_mode() in ("ask", "auto") and not a.no_tidy:  # nothing is published that tidy has not looked at: junk, repeats and stale notes stay out
        res = tidy.gate(r)
        out("tidy before publishing: " + ", ".join(x for x in (
            f"archived {len(res['triage']['archived'])} junk or repeated entr{'y' if len(res['triage']['archived']) == 1 else 'ies'}" if res["triage"]["archived"] else "",
            f"{len(res['status'].get('applied', []))} status(es) stored" if res["status"].get("applied") else "",
            f"queued {len(res['queue']['queued'])}" if res["queue"]["queued"] else "",
            f"took {len(res['queue']['removed'])} out of the queue" if res["queue"]["removed"] else "") if x) or "nothing to tidy")
        if res["blocked"]:
            raise SystemExit(f"logbook: nothing was published: tidy could not check the log ({res['blocked']}). Try again after the pause, or pass --no-tidy to publish unchecked.")
    ready = []
    tidy.queue_pass(r)  # the queue is what publish shares: bring it up to date even when tidy did not run
    if getattr(a, "branch", None) or getattr(a, "merged", False):
        from . import branches
        if a.merged:
            picked = [(b, es) for b, es, _ in branches.merged(r)]
        else:
            picked = [(a.branch, [e for e in r.queued() if e.anchor.get("branch") == a.branch])]
        ids = [e for _, es in picked for e in es]
        if ids:
            out("from branch " + ", ".join(b for b, es in picked if es) + ":")
    elif getattr(a, "all", False):
        ids = r.queued()
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
        if e.kind == "log":
            out(f"skipped {eid}: a log stays on this machine; only notes are published.")
            continue
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
    remote = "origin" in sync.remotes(r)
    if remote:  # tidy -> sync -> move -> push: bring in what teammates shared before writing
        try:
            for line in sync.sync(r, "origin")["news"]:
                out("news: " + line)
        except (SystemExit, OSError, ValueError):
            pass
    out("Published entries cannot be fully recalled: forks and mirrors may keep copies. Rotate any secret that appears above.")
    if not a.yes and _ask("Publish exactly the text above? [y/N] ").strip().lower() != "y":
        raise SystemExit("aborted; nothing published")
    for c, h in ready:
        if digest_hash(c.to_json()) != h:
            raise SystemExit("logbook: entry changed after preview; aborting")
    try:
        ref = r.publish([c for c, _ in ready])
    except ValueError as ex:
        raise SystemExit(f"logbook: nothing was published: {ex}")
    outbox.drop(r, [c.id for c, _ in ready])
    outbox.clear_pending(r)
    keep = getattr(a, "keep", False)
    if not keep:  # a move, not a copy: the shared (redacted) text replaces the private original
        for c, _ in ready:
            r.drop_private(c.id)
    out(f"published {len(ready)} entr{'y' if len(ready) == 1 else 'ies'} to {ref}"
        f"{'' if keep else ' (the private copy was removed, --keep leaves it)'}.")
    if remote and not a.no_push:
        res = sync.push(r)
        out("pushed." if res["ok"] else "not pushed: " + res.get("error", "")[:200] + " (publish again once the remote is reachable)")
    elif not remote:
        out("no remote named origin: the entries stay on this machine until you add one.")


def _ask(prompt):
    try:
        return input(prompt)
    except EOFError:
        return ""


def _pick_unpublished(r):
    """Numbered list of private notes not shared yet; asks which ones when a person is at the keyboard."""
    q = sorted(r.queued(), key=lambda e: e.id, reverse=True)
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
    res = sync.sync(r, a.remote, True, a.depth)
    if a.json:
        out(json.dumps(res, indent=2))
    elif not res["fetch"]["ok"]:
        out("logbook: could not fetch from " + a.remote + ": " + res["fetch"]["error"][:200])
    else:
        out(f"fetched: {res['entries']} shared entr{'y' if res['entries'] == 1 else 'ies'} from {res['writers']} writer(s); your own shelf: {res.get('merge', 'same')}. Nothing was pushed (`logbook publish` pushes).")
        for line in res["news"] or ["no news since you last looked."]:
            out("  " + line)
    return 0 if res["fetch"]["ok"] else 1


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
    head = f"{txt(v, v['topic'], 120)}  ({who}, {v['created'][:10]})" + (f"  [{v['status']}]" if v.get("status", "open") != "open" else "")
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
    """A savepoint: summarize what the observer collected on this branch since the last one and store it as a private log."""
    from . import running, savepoint
    r = need_repo()
    branch = running.branch_now(r)[0]
    res = savepoint.save(r, branch, use_model=not a.no_model, observe=not a.no_observe, commit=a.commit)
    if "saved" not in res:
        if not a.quiet:
            out("logbook: " + res["skipped"])
        return 0 if res["skipped"].startswith("nothing") else 1
    if not a.quiet:
        out(f"saved log {res['saved']} on {res['branch']} ({'commit ' + res['commit'][:8] if res['commit'] else 'no commit yet'}): {res['title']}")
        out(f"  covers {res['observations']} observation(s), summarized by {res['by']}; private until `logbook publish`.")
    return 0


def cmd_history(a):
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
    out(f"you: {r.user}  attribution: {r.attribution()}  transport: {r.cfg().get('transport', 'refs')}")
    out(f"entries: {len(vs)} visible ({sum(1 for v in vs if v['scope'] == 'private')} private, "
        f"{sum(1 for v in vs if v['scope'] == 'shared')} shared) from {len({l.user for l in shared})} writers")
    from . import running
    run = running.Running(r, running.branch_now(r)[0])
    out(f"observer: {run.pending_bytes()} bytes of tool uses queued, {len(running.own(run))} observation(s) since the last log on {run.branch}")
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
    out(f"  git hooks   : pre-push {'installed' if ins.git_hook_installed(r, 'pre-push') else 'missing'}, "
        f"post-merge {'installed' if ins.git_hook_installed(r, 'post-merge') else 'missing'}, "
        f"post-commit {'installed' if ins.git_hook_installed(r, 'post-commit') else 'missing'}")
    for sm in tree.summaries(views(r)[0]):
        node = "repo" if sm["level"] == "repo" else "branch " + sm["branch"]
        out(f"  summary     : {node}: {'up to date' if sm['fresh'] else str(sm['new_notes']) + ' newer note(s), stale (logbook summarize)'}")
    for t, st in ins.status(r).items():
        out(f"  {t:<12}: {st}")
    out("  Only Claude Code has hooks (it captures sessions and shows notes automatically). The other agents get the rules")
    out("  file only, so they rely on the agent following it; the git hook is the same for everyone.")
    return 1 if bad else 0


def cmd_capture(a):
    try:
        text = capture.handle_hook(a.event, a.agent, sys.stdin.read() if not sys.stdin.isatty() else "")
        if text:
            sys.stdout.write(text)
    except Exception:
        pass
    return 0  # a hook must never fail the agent


def cmd_post_commit(a):
    from . import hookmain
    return hookmain.run(["post-commit"])  # the git hook's entry point: save a log in the background in ask and auto mode


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
        out("Claude Code sessions are now observed per branch (private; `logbook worker --status`). `logbook log` saves a log of the session so far.")
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


CONFIG_KEYS = {"tidy_model": "text", "quota_pause": None, "publish": PUBLISH_MODES,
               "worker": ("off", "on"), "tidy": ("manual", "auto"), "worker_calls": None, "worker_chars": None, "worker_days": None}


def cmd_queue(a):
    """The publish queue: what `logbook publish` will share. Tidy keeps it; --add and --remove change it by hand."""
    r = need_repo()
    if not a.hook:
        tidy.queue_pass(r)  # the queue is tidy's: show it as tidy would leave it
    if a.add or a.remove:
        mine = {e.id for e in r.unpublished()}
        bad = [i for i in (a.add or []) if i not in mine]
        if bad:
            raise SystemExit(f"logbook: {bad[0]} is not a private entry of yours that is waiting to be shared")
        if a.add:
            out(f"queued {len(outbox.add(r, a.add, 'user'))} entr{'y' if len(a.add) == 1 else 'ies'}")
        if a.remove:
            out(f"took {len(outbox.drop(r, a.remove))} out of the queue (tidy may queue an entry again if it passes its checks)")
    q = r.queued() if r.publish_mode() != "never" else []
    if a.hook:
        said = []
        waiting = r.unpublished() if r.publish_mode() != "never" else []  # the push reminder must stay cheap, so it counts what is private, not what tidy has queued
        if waiting:
            said.append(f"{len(waiting)} private note(s) are not shared with your team yet (`logbook publish` shows what would be shared and asks first).")
        if "origin" in sync.remotes(r) and sync.unpushed(r):
            said.append("your published notes are not pushed yet (`logbook sync` pushes them).")
        if said:
            print("logbook: " + " ".join(said), file=sys.stderr)
        return 0
    left = len(r.unpublished()) - len(q)
    if not q:
        out("nothing queued: " + (f"{left} private entr{'y is' if left == 1 else 'ies are'} not in the queue (tidy leaves out what fails its checks; `logbook queue --add <id>` puts one in)."
                                  if left else "every entry of yours is shared, or publishing is off for this repo."))
        return 0
    out(f"{len(q)} queued for publishing (newest first): note id, commit, branch, note")
    for e in sorted(q, key=lambda x: x.id, reverse=True):
        out(f"  {e.id}  {(e.anchor.get('sha') or '-')[:8]:<8}  {e.anchor.get('branch') or '-':<20}  {e.kind}: {safety_sanitize(e.topic, 80)}")
    if left:
        out(f"{left} more private entr{'y is' if left == 1 else 'ies are'} not queued.")
    out("`logbook publish --all` previews the queue with redaction and asks once; `logbook publish <id>` does one.")
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
    if allowed == "text":  # a free-form value, such as a model name
        c[a.key] = a.value
        r.save_cfg(c)
        out(f"{a.key} = {a.value}")
        return 0
    if a.key == "publish":
        a.value = LEGACY_MODES.get(a.value, a.value)  # never -> manual, claude -> ask
    if allowed and a.value not in allowed:
        raise SystemExit(f"logbook: {a.key} must be one of {', '.join(allowed)}")
    if not allowed and not a.value.isdigit():
        raise SystemExit(f"logbook: {a.key} must be a number")
    c[a.key] = False if a.value == "off" else int(a.value) if a.value.isdigit() else a.value
    r.save_cfg(c)
    out(f"{a.key} = {a.value}")
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


def cmd_worker(a):
    """The observer: `--status` shows what it has spent and whether it is on; `--drain [--branch B] [--flush]` observes what is queued now (what the hooks start in the background)."""
    from . import observer, running, worker
    r = need_repo()
    if a.drain:
        branch = a.branch or running.branch_now(r)[0]
        out(json.dumps(observer.drain(r, branch, flush=a.flush)))
        return 0
    s = worker.status(r)
    out(f"worker {s['worker']}, tidy {s['tidy']}: {s['calls_today']} call(s) and {s['cost_today']:.3f} USD today, {s['notes_written']} note(s) written")
    lp = s["last_pass"]
    if lp:
        out("  last pass: " + (lp.get("skipped") or lp.get("error") or f"{len(lp.get('observations', []))} observation(s) kept") + f" ({time.strftime('%H:%M', time.localtime(lp['t']))})")
    for name, w in sorted(s["usage"].items()):
        if name in ("five_hour", "seven_day"):
            out(f"  {name.replace('_', '-')} usage: {round(w['u'] * 100)}% (resets {time.strftime('%a %H:%M', time.localtime(w['resets']))}; as of the last call)")
    if s["cooling_down"]:
        out(f"  paused until {time.strftime('%H:%M', time.localtime(s['paused_until']))}: {s['pause_reason'] or 'the usage allowance ran out'}")
    if s["last_error"]:
        out("  last error: " + safety_sanitize(s["last_error"], 200))
    return 0


def cmd_tidy(a):
    """Notes that may be out of date, repeated or junk, each with the reason. Plain `tidy` and `--brief` only read; `--apply` stores the statuses
    the person approved, all or none."""
    r = need_repo()
    if not a.no_sync and "origin" in sync.remotes(r):  # first bring in what teammates and your other machines shared; a failure here must not stop the tidy
        try:
            sync.sync(r, "origin", fetch_only=True)
        except (SystemExit, OSError, ValueError):
            pass
    if a.work:  # the tidy worker's pass: judge, archive junk (what the hooks start in `tidy auto`)
        res = tidy.auto(r, judge=not a.no_judge) if tidy.mode(r.cfg()) == "auto" else tidy.run(r, judge=not a.no_judge)
        if not a.quiet:
            out(json.dumps(res))
        return 0
    vs = views(r)[0]
    if a.restore:
        out(f"restored {tidy.restore(r, a.restore)} of {len(a.restore)} entr{'y' if len(a.restore) == 1 else 'ies'} from .git/logbook/archive/")
        return 0
    if a.proposals or a.accept:
        if a.accept:
            stored, errors = tidy.accept(r)
            for nid in stored:
                out(f"  {nid} status stored (private until you publish it)")
            for e in errors:
                out("  ! " + e)
            moved = tidy.accept_archives(r)
            for eid in moved:
                out(f"  {eid} archived (still readable in .git/logbook/archive/; `logbook tidy --restore {eid}` puts it back)")
            return 0
        waiting, drops = tidy.proposals(r), tidy.archive_proposals(r)
        out(f"{len(waiting)} status proposal(s) and {len(drops)} archive proposal(s) from the tidy worker, already checked (`logbook tidy --accept` applies them)")
        for b in waiting:
            out(f"  {b['status_of']}  ->  {b['status']}  ({safety_sanitize(b.get('reason', ''), 160)})")
        for d in drops:
            out(f"  {d['entry']}  ->  archive as {d['verdict']}" + (f" of {d['redundant_of']}" if d.get("redundant_of") else "") + f"  ({safety_sanitize(d.get('reason', ''), 160)})")
        return 0
    if a.garbage:  # the worker's private drafts that are no longer worth keeping; --apply moves them to the archive, nothing is deleted
        junk = tidy.garbage(r, vs)
        if a.apply:
            out(f"archived {tidy.archive(r, [c['id'] for c in junk])} worker draft(s) to .git/logbook/archive/")
            return 0
        out(f"{len(junk)} worker draft(s) no longer worth keeping (nothing was changed; `tidy --garbage --apply` archives them)")
        for c in junk:
            out(f"  {c['id']}  {safety_sanitize(c['topic'], 80)}  ({c['reason']})")
        return 0
    if a.apply:
        done, errors = tidy.apply(r, vs, sys.stdin.read())
        if errors:
            for e in errors:
                out("  ! " + e)
            raise SystemExit("logbook: nothing was changed; fix the proposals above and run it again")
        for nid, state, e in done:
            out(f"  {nid} is now {state} (record {e.id}, private until you publish it)")
        return 0
    if a.brief:
        out(tidy.brief(r, vs, a.limit))
        return 0
    found = tidy.candidates(r, vs)
    waiting = len(tidy.proposals(r)) + len(tidy.archive_proposals(r))
    if waiting:
        out(f"{waiting} proposal(s) from the tidy worker are waiting: `logbook tidy --proposals` shows them, `logbook tidy --accept` applies them")
    out(f"{len(found)} candidate{'' if len(found) == 1 else 's'} (nothing was changed; whether each one is really outdated or repeated is for an agent to judge and you to approve)")
    for c in found[:a.limit]:
        out(f"  {c['id']}  {'yours' if c['mine'] else 'a teammate'}  {safety_sanitize(c['topic'], 80)}")
        out(f"      {c['reason']}")
        for d in c["detail"]:
            out("      - " + safety_sanitize(d, 120))
    if len(found) > a.limit:
        out(f"  ... {len(found) - a.limit} more (--limit {len(found)})")
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
    mine = [l.entry for l in r.all_entries() if l.user == r.user]
    out(f"your notes: {sum(1 for e in mine if e.provenance != 'auto-copied')} written, "
        f"{sum(1 for e in mine if e.provenance == 'auto-copied')} auto-copied")


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


HIDDEN = {"init", "join", "query", "explain", "path", "doctor", "queue", "stats", "install", "capture", "post-commit",
          "inject", "summarize", "trust", "purge", "gc", "config", "uninstall", "snippet", "demo",
          "cites", "tidy", "worker", "history"}
HELP_MORE = """more (run `logbook <name> -h`):
  trust purge gc config uninstall snippet demo
agents and hooks call these; you rarely need to:
  summarize inject cites capture
older names that still work:
  init join query explain path doctor queue stats install
the old `log` view of notes next to commits is now `history`"""


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
    s = add("log", cmd_log, "save a log: summarize this branch's session since the last one (private until you publish)")
    s.add_argument("--no-model", action="store_true", help="put the summary together by code, without asking a model")
    s.add_argument("--no-observe", action="store_true", help="do not first observe the tool uses still queued")
    s.add_argument("--commit", help="the commit this savepoint is about (the git post-commit hook passes it)")
    s.add_argument("--quiet", action="store_true")
    s = add("history", cmd_history, "the notes next to your commits, newest first")
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
    s.add_argument("--commit", help="write the note about this earlier commit instead of HEAD")
    s.add_argument("--sources", help="comma-separated ids of the findings this note was written from")
    s.add_argument("--from-stdin", action="store_true", help="read the summary from stdin (for agents without hooks)")
    s.add_argument("--json", action="store_true", help="read the whole note as a JSON object on stdin")
    s.add_argument("--fields", action="store_true", help="read the whole note as `key: value` lines on stdin (no braces or quotes: what an agent should use)")
    s.add_argument("--supersedes", help="comma-separated ids of your own notes this one replaces")
    s.add_argument("--check", action="store_true", help="only look up what the note names and report; save nothing")
    s.add_argument("--allow-ungrounded", action="store_true", help="save a finding or change with no evidence line, marked unverified")
    s.add_argument("-q", "--queue", action="store_true", help="also put the note in the publish queue")
    s = add("publish", cmd_publish, "share private entries (preview + redaction, per entry)")
    s.add_argument("ids", nargs="*")
    s.add_argument("--all", action="store_true", help="every private note not shared yet (same preview and one confirmation)")
    s.add_argument("--branch", help="every private log and note filed under this branch (once it has been merged)")
    s.add_argument("--merged", action="store_true", help="the logs and notes of every branch that looks merged into the main line")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--push", action="store_true")
    s.add_argument("--include-evidence", action="store_true")
    s.add_argument("--allow-table", action="store_true")
    s.add_argument("--keep", action="store_true", help="leave the private copy in place after publishing")
    s.add_argument("--no-tidy", action="store_true", help="in auto mode, publish without running tidy first")
    s.add_argument("--no-push", action="store_true", help="write to your shared ref but do not push it")
    s.add_argument("--force", action="store_true", help="publish even if a teammate already shared the same text")
    s = add("sync", cmd_sync, "fetch teammates' entries and merge them in; never pushes (publish does); says what is new")
    s.add_argument("--remote", default="origin")
    s.add_argument("--fetch-only", action="store_true", help="kept for older scripts: sync never pushes now")
    s.add_argument("--json", action="store_true")
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
    s = add("capture", cmd_capture, "hook entry point (reads JSON on stdin; never fails)")
    s.add_argument("--event", required=True)
    s.add_argument("--agent", default="")
    add("post-commit", cmd_post_commit, "git hook entry point")
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
    s = add("summarize", cmd_summarize, "brief an agent on the notes under the repo or a branch so it can write the summary")
    s.add_argument("--repo", action="store_true", help="the whole repo even when on a branch")
    s.add_argument("--branch", help="a named branch")
    s = add("worker", cmd_worker, "the observer: --status, or --drain to observe what is queued now")
    s.add_argument("--drain", action="store_true")
    s.add_argument("--branch", help="the branch whose queue to observe (default: the current one)")
    s.add_argument("--flush", action="store_true", help="also take a batch too small to be worth a call")
    s.add_argument("--status", action="store_true")
    s = add("tidy", cmd_tidy, "list notes that may be out of date, repeated or junk; --brief for an agent; --apply stores approved statuses")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--no-sync", action="store_true", help="do not fetch shared logs first")
    s.add_argument("--work", action="store_true", help="run the tidy worker's pass now: judge changed notes with a cheap model, archive junk in auto mode")
    s.add_argument("--quiet", action="store_true")
    s.add_argument("--no-judge", action="store_true", help="with --work: skip the junk judgment (a model call); a publish does it")
    s.add_argument("--proposals", action="store_true", help="show what the tidy worker proposed and kept for you")
    s.add_argument("--accept", action="store_true", help="store the worker's proposals (each is checked against git again; asks first in Claude Code)")
    s.add_argument("--restore", nargs="+", metavar="ID", help="put archived entries back in the private log")
    s.add_argument("--garbage", action="store_true", help="list your worker drafts that are no longer worth keeping (with --apply: archive them)")
    s.add_argument("--brief", action="store_true", help="the candidates with the notes' words, for an agent to judge")
    s.add_argument("--apply", action="store_true", help="read approved proposals on stdin and store them as statuses (asks first in Claude Code)")
    s = add("queue", cmd_queue, "show what `logbook publish` will share (the publish queue)")
    s.add_argument("--show", action="store_true", help="list the queue (the default)")
    s.add_argument("--add", nargs="+", metavar="ID", help="put private entries in the queue")
    s.add_argument("--remove", nargs="+", metavar="ID", help="take entries out of the queue")
    s.add_argument("--hook", action="store_true", help="the quiet one-line reminder the pre-push hook prints")
    s = add("config", cmd_config, "show or set: publish (manual|ask|auto), worker (on|off), tidy (manual|auto), worker_calls, quota_pause (percent), tidy_model")
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
    s = add("convo", cmd_convo, "the conversation behind a log: what was typed and the agent's final replies")
    s.add_argument("id")
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
