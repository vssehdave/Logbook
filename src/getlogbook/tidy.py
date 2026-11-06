"""Keeping notes true: candidates for tidying, and the validated way to change a note's status.

Python finds candidates and says why, from git and from the notes alone, and checks every proposal before anything is stored. Whether a later commit
really outdates a note is a judgment: the tidy worker asks a cheap model (`tidy_model`) for it, an agent can do it from `tidy --brief`, and either way
Python checks the proposals against git. In `manual` mode the proposals wait for the person (`tidy --proposals`, then `tidy --accept`, a command Claude
Code asks about); in `auto` mode the valid ones are stored by the worker. A status is a small record written by the note's own author; the note itself
is never edited, so nothing already shared changes under a teammate. Nothing is deleted: merged and junk private entries move to `.git/logbook/archive/`.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time

from . import capture, ground, worker
from .safety import redact
from . import git as g
from .entry import HEX_RE, ID_RE, STATES
from .safety import sanitize

OLD_DRAFT_DAYS = 30  # an auto-copied draft this old and never turned into a real note is junk until shown otherwise
MAX_CHECKED = 200  # notes asked about their files, newest first: one `git log` each. shortcut: no index, upgrade if a repo has far more live notes
MAX_COMMITS = 20  # commits looked up per note: enough to cite from, and the shown list is the first few
SHOWN_COMMITS = 5
MAX_FILES = 20
MAX_APPLY = 50
_KEYS = ("status_of", "status", "commits", "reason")


def tracked(repo, v):
    """The files a note is about. A change note is about its commit, so those files. A finding is about the files it names (and a finding is anchored
    to whatever HEAD was when it was written, which says nothing about its subject); one that names none falls back to its commit's files."""
    sha = v["placed"] or v["sha"]
    named = list(dict.fromkeys(((v["checks"] or {}).get("files") or []) + (v["paths"] or [])))
    if v["kind"] == "change" and sha:
        return g.changed_paths(repo.root, sha) or named
    return named or (g.changed_paths(repo.root, sha) if sha else [])


def later_commits(repo, v):
    """[(full sha, subject)] of commits after the note's own commit (or after HEAD when it was written) that touched its files, newest first."""
    base = v["placed"] or v["sha"] or (v["checks"] or {}).get("at") or ""
    files = [f for f in tracked(repo, v) if f and not f.startswith("-")][:MAX_FILES]
    if not files or not g.commit_exists(repo.root, base):  # the id came from a note, possibly a teammate's: only a real commit goes near git's arguments
        return []
    rc, out, _ = g.try_run(["log", f"-n{MAX_COMMITS}", "--format=%H %s", f"{base}..HEAD", "--"] + files, repo.root)
    return [tuple(line.split(" ", 1)) for line in out.splitlines() if line.strip()] if rc == 0 else []


def candidates(repo, views):
    """[{id, topic, mine, reason, detail, commits}] in this order: repeated notes, notes whose files changed since, old drafts. A note that is
    already resolved, and a status record, are not candidates."""
    live = [v for v in views if v["kind"] != "summary" and not v.get("is_status") and v.get("status") != "resolved"]
    notes = [v for v in live if v["provenance"] != "auto-copied"]
    out, seen = [], set()
    for v in notes:
        for o in ground.overlaps([w for w in notes if w["id"] != v["id"]], v["topic"], v["body"].get("summary", ""), v["paths"]):
            pair = tuple(sorted((v["id"], o["id"])))
            if pair not in seen:
                seen.add(pair)
                out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": "may say the same as another note",
                            "detail": [f"{o['id']} ({'yours' if o['mine'] else 'a teammate'}): {o['topic'][:70]}"], "commits": []})
    for v in sorted(notes, key=lambda x: x["created"] or "", reverse=True)[:MAX_CHECKED]:
        later = later_commits(repo, v)
        if later and not (v.get("status") == "in-progress" and v["status_commits"] and later[0][0] in v["status_commits"]):  # already looked at up to the newest of these
            out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": "files it is about changed in later commits",
                        "detail": [f"{sha[:8]} {subject[:70]}" for sha, subject in later[:SHOWN_COMMITS]], "commits": [sha for sha, _ in later]})
    for v in live:
        if v["provenance"] == "auto-copied" and (v["age_days"] or 0) >= OLD_DRAFT_DAYS:
            out.append({"id": v["id"], "topic": v["topic"], "mine": v["mine"], "reason": f"auto-copied draft, {v['age_days']} days old", "detail": [], "commits": []})
    return out


def parse(text, keys=_KEYS):
    """Proposals as blocks of `key: value` lines (status_of, status, commits, reason; or a triage verdict's keys) separated by a line of `---`. A value may run over several lines."""
    blocks, cur, key = [], {}, None
    for line in text.splitlines() + ["---"]:
        if line.strip() == "---":
            if cur:
                blocks.append({k: v.strip() for k, v in cur.items()})
            cur, key = {}, None
            continue
        m = re.match(r"^([a-z_]+):[ \t]?(.*)$", line)
        if m and m.group(1) in keys:
            key = m.group(1)
            cur[key] = m.group(2)
        elif key:
            cur[key] += "\n" + line
    return blocks


def check(repo, views, blk):
    """(error, target view, full commit ids) for one proposal. A proposal is accepted only when the note is the proposer's own, and a resolved or
    in-progress one cites commits that exist and touched the note's files after it was written, with a reason."""
    nid, state = blk.get("status_of", ""), blk.get("status", "")
    if not ID_RE.match(nid):
        return f"{nid!r} is not a note id", None, []
    t = next((v for v in views if v["id"] == nid), None)
    if not t or t.get("is_status"):
        return f"{nid}: no such note", None, []
    if not t["mine"]:
        return f"{nid}: not your note; only the author can change its status", None, []
    if state not in STATES:
        return f"{nid}: status must be one of {', '.join(STATES)}", None, []
    if not blk.get("reason"):
        return f"{nid}: a reason is required", None, []
    shas = []
    if state != "open":
        asked = [c for c in re.split(r"[,\s]+", blk.get("commits", "")) if c]
        if not asked:
            return f"{nid}: {state} needs the commit or commits that justify it", None, []
        touching = [sha for sha, _ in later_commits(repo, t)]
        for c in asked:
            full = [s for s in touching if HEX_RE.match(c) and s.startswith(c.lower())]
            if len(full) != 1:
                return f"{nid}: commit {c} did not touch this note's files after it was written", None, []
            shas.append(full[0])
    return "", t, shas


def apply(repo, views, text):
    """([(note id, status, the new record)], [errors]). Nothing is stored unless every proposal is valid, so what the person approved is what happens."""
    blocks = parse(text)
    if not blocks:
        return [], ["no proposals on stdin (blocks of status_of / status / commits / reason lines, separated by ---)"]
    if len(blocks) > MAX_APPLY:
        return [], [f"{len(blocks)} proposals; at most {MAX_APPLY} at a time"]
    return apply_blocks(repo, views, blocks)


def apply_blocks(repo, views, blocks):
    checked = [(b, *check(repo, views, b)) for b in blocks]
    errors = [e for _, e, _, _ in checked if e]
    if errors:
        return [], errors
    done = []
    for b, _, t, shas in checked:
        state = b["status"]
        cited = [f"{s[:8]} {subj[:60]}" for s, subj in later_commits(repo, t) if s in shas]
        body = {"summary": b["reason"][:1000], "evidence": ("later commits: " + "; ".join(cited)) if cited else "reopened by its author"}
        e = capture.make_entry(repo, "finding", f"{state}: {t['topic']}"[:200], body, paths=t["paths"], via="tidy", status={"of": t["id"], "state": state, "commits": shas})
        done.append((t["id"], state, e))
    return done, []


def brief(repo, views, limit=20):
    """What an agent needs to judge the candidates: each note's text and the later commits to read with `git show`. Makes no model call."""
    by_id = {v["id"]: v for v in views}
    lines = ["Candidates for tidying. For each, decide: still true (leave it), partly changed (in-progress), fixed or gone (resolved), or the same as another note.",
             "Read the commits with `git show <sha> -- <file>` before deciding. Give the person the whole list in chat and wait for a yes; then run",
             "`logbook tidy --apply` once, with blocks of lines  status_of: <id>  status: in-progress|resolved|open  commits: <sha>, <sha>  reason: why, citing the commit",
             "separated by a line of ---. A reason and, for resolved or in-progress, a commit that touched the note's files are required. Only your own notes can be changed.", ""]
    for c in candidates(repo, views)[:limit]:
        v = by_id[c["id"]]
        lines += [f"{c['id']}  {'yours' if c['mine'] else 'a teammate'}  {sanitize(v['topic'], 100)}", f"  why listed: {c['reason']}"]
        for k in ("summary", "why", "fix", "decided", "open"):  # a teammate's words reach the agent, so they are cleaned like any injected note
            if v["body"].get(k):
                lines.append(f"  {k}: {sanitize(v['body'][k], 300)}")
        lines += [f"  files: {sanitize(', '.join(tracked(repo, v)[:6]), 200)}"] + [f"  - {sanitize(d, 120)}" for d in c["detail"]] + [""]
    return "\n".join(lines)


RETENTION_DAYS = 30


def garbage(repo, views, days=None):
    """Your own private machine-made drafts (the observer's earlier per-turn notes, and the auto-copied session and commit drafts of 0.0.5 and earlier) that are no
    longer worth keeping, each with the reason: marked resolved, about files that are all gone, or older than the retention. Only private and yours: a note a
    person or an agent wrote, a saved log, or anything already shared is never listed here."""
    days = int(days or repo.cfg().get("worker_days", RETENTION_DAYS))
    out = []
    for v in views:
        if v.get("is_status") or not v["mine"] or v["provenance"] not in ("worker-written", "auto-copied") or v["scope"] != "private" or v["kind"] == "log":
            continue  # a saved log is the person's record of a session: it is kept, never dropped as junk
        files = tracked(repo, v)[:MAX_FILES]
        if v.get("status") == "resolved":
            reason = "resolved"
        elif files and all(g.try_run(["cat-file", "-e", f"HEAD:{f}"], repo.root)[0] != 0 for f in files):
            reason = "every file it is about is gone"
        elif (v["age_days"] or 0) >= days:
            reason = f"{v['age_days']} days old (kept {days})"
        else:
            continue
        out.append({"id": v["id"], "topic": v["topic"], "reason": reason})
    return out


def archive(repo, ids):
    """Move private notes out of the log into .git/logbook/archive/, where they stay readable; nothing is deleted. Returns how many moved."""
    d = repo.cdir / "archive"
    d.mkdir(parents=True, exist_ok=True)
    moved = 0
    for i in ids:
        src = repo.pdir / f"{i}.json"
        if src.exists():
            shutil.copy2(src, d / src.name)
            moved += repo.drop_private(i)
    return moved


def mode(cfg):
    """`config tidy`: auto (the default: the worker applies what it decides, and the person is shown it) or manual (it keeps proposals for the person)."""
    return cfg.get("tidy", "auto")


# ---- the tidy worker --------------------------------------------------------------------------------------------
TIDY_MODEL = "haiku"  # `config tidy_model` changes it; it is a different setting from the observer's model on purpose
MAX_JUDGED = 12  # candidates shown to the model in one call
SYSTEM = """You help keep a team's recorded notes true. You cannot use tools. Below are notes written earlier in this repo, each with the later commits that touched the files it is about. Decide, for each note, only from what is shown:
- nothing at all if it still looks true or you cannot tell;
- status: in-progress if a later commit changed part of what it says;
- status: resolved if a later commit clearly fixed, removed or replaced what it describes.
Cite only commits listed under that note (the 8-character id is enough). Give a reason that names what the commit changed. Do not guess. Answer with blocks separated by a line of ---, each exactly:

status_of: <note id>
status: in-progress or resolved
commits: <commit id>, <commit id>
reason: one or two sentences

If no note needs a status, answer with exactly: NONE
"""


def _dir(repo):
    return repo.cdir / "tidy"


def _state(repo):
    try:
        st = json.loads((_dir(repo) / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    st.setdefault("judged", {})
    st.setdefault("proposals", [])
    st.setdefault("triaged", {})  # entry id -> what was shown about it when the model last judged it
    st.setdefault("archives", [])  # triage proposals kept for the person in manual mode
    return st


def _save(repo, st):
    capture.atomic_write(_dir(repo) / "state.json", json.dumps(st))


def _fingerprint(c):
    """What was shown about a candidate: asked again only when a newer commit turns up."""
    return hashlib.sha1((c["reason"] + "|" + ",".join(c["commits"])).encode("utf-8")).hexdigest()[:12]


def build_prompt(repo, views, cands):
    by_id = {v["id"]: v for v in views}
    lines = [SYSTEM, "NOTES:"]
    for c in cands:
        v = by_id[c["id"]]
        lines += ["", f"note {c['id']}: {sanitize(v['topic'], 100)}"]
        lines += [f"  {k}: {sanitize(v['body'][k], 300)}" for k in ("summary", "what", "why", "fix", "decided", "open") if v["body"].get(k)]
        lines.append("  files: " + sanitize(", ".join(tracked(repo, v)[:6]), 200))
        lines += [f"  later commit {sha[:8]}: {sanitize(subj, 100)}" for sha, subj in later_commits(repo, v)[:SHOWN_COMMITS]]
    return "\n".join(lines) + "\n"


def work(repo, call=None, now=time.time):
    """One pass: ask the cheap model about my notes whose files changed in later commits, check every answer against git, then store the valid ones
    (tidy auto) or keep them for the person (tidy manual). Never raises for a model problem; shares the observer's budget and its pause."""
    from . import tree
    if not worker.enabled(repo):
        return {"skipped": "the observer is off"}
    cfg = repo.cfg()
    call = call or (lambda p: worker.call_model(p, cfg.get("tidy_model", TIDY_MODEL)))
    with capture._lock(_dir(repo) / ".lock", timeout=0.2, stale=worker.LOCK_STALE) as got:
        if not got:
            return {"skipped": "another tidy pass is running"}
        led = worker.ledger(repo)
        if now() < led["cooldown_until"]:
            return {"skipped": "paused: " + (led.get("pause_reason") or "waiting after the usage allowance ran out")}
        if led["calls"] >= int(cfg.get("worker_calls", worker.MAX_CALLS)):
            return {"skipped": "today's call cap is reached"}
        views = tree.all_views(repo)[0]
        st = _state(repo)
        kinds = {v["id"]: v["kind"] for v in views}
        cands = [c for c in candidates(repo, views) if c["mine"] and c["commits"] and kinds.get(c["id"]) != "log"  # a saved log is history, not a claim to keep true
                 and st["judged"].get(c["id"]) != _fingerprint(c)][:MAX_JUDGED]
        if not cands:
            return {"skipped": "nothing new to judge"}
        sent, _ = redact(build_prompt(repo, views, cands), cfg.get("deny", []))
        text, cost, error = call(sent)
        worker.settle(repo, led, cost, error, now)
        if error:
            return {"error": error[:200]}  # nothing is marked as judged, so the next pass asks again
        good, bad = [], 0
        for b in parse(text)[:MAX_APPLY]:
            if check(repo, views, b)[0]:
                bad += 1
            else:
                good.append(b)
        for c in cands:
            st["judged"][c["id"]] = _fingerprint(c)
        applied = []
        if mode(cfg) == "auto":
            for b in good:  # one at a time: a proposal that went stale must not block the rest
                done, _ = apply_blocks(repo, views, [b])
                applied += [d[0] for d in done]
        else:
            kept = {b["status_of"]: b for b in st["proposals"]}
            kept.update({b["status_of"]: b for b in good})
            st["proposals"] = list(kept.values())
        _save(repo, st)
    return {"judged": len(cands), "proposed": 0 if applied else len(good), "applied": applied, "rejected": bad, "cost": round(cost, 6)}


def proposals(repo):
    return _state(repo)["proposals"]


def accept(repo):
    """Store the proposals the worker kept for the person, each checked again against git as it is now. Returns (stored note ids, errors)."""
    from . import tree
    st = _state(repo)
    views = tree.all_views(repo)[0]
    stored, errors = [], []
    for b in st["proposals"]:
        done, errs = apply_blocks(repo, views, [b])
        stored += [d[0] for d in done]
        errors += errs
    st["proposals"] = []
    _save(repo, st)
    return stored, errors


# ---- triage: junk and repeats in the private log ------------------------------------------------------------------
# A private log collects whatever sessions leave behind: test and probe runs, a greeting, an attempt that found nothing, the same thing saved twice. Nothing
# is deleted, but unless something looks at them and moves them out of the way they get published and injected like real records.
TRIAGE_MAX = 25  # entries shown to the model in one call
TRIAGE_ARCHIVE_MAX = 10  # entries one pass may archive: a model that calls everything junk must not empty the log
TRIAGE_KEYS = ("entry", "verdict", "redundant_of", "reason")
TRIAGE_SYSTEM = """You keep a person's private log of coding sessions clean. You cannot use tools. Below are entries from the log, each with facts worked out by code. Decide, only from what is shown, which entries are not worth keeping or sharing:
- junk: a test, probe, benchmark or throwaway session; a session that left nothing a later reader could use (a greeting, a one-word reply, a failed start, an attempt that found nothing); work that was abandoned (its branch is gone and was never merged, or its files are gone).
- redundant: says the same thing as another entry; name the entry to keep in redundant_of (keep the better one).
Do not call an entry junk because it is short or because you cannot tell: when in doubt, leave it out. An entry that records a decision, a cause, a gotcha, or what was built or fixed is worth keeping even when small. Answer with blocks separated by a line of ---, each exactly:

entry: <entry id>
verdict: junk or redundant
redundant_of: <id of the entry to keep; only for redundant>
reason: one sentence saying what makes it junk or a repeat

If every entry is worth keeping, answer with exactly: NONE
"""


def _norm(v):
    """What makes two entries the same: their words, ignoring case and spacing."""
    text = " ".join([v["topic"]] + [v["body"].get(k, "") for k in ("summary", "what", "why", "context", "open")])
    return " ".join(text.lower().split())


def triage_pool(views):
    """My own private notes that triage may archive: not logs (a log is the raw record of a session and is kept), not status records, not shared, not auto-copied drafts (`garbage` takes those)."""
    return [v for v in views if v["mine"] and v["scope"] == "private" and not v.get("is_status") and v["kind"] in ("finding", "change")
            and v["provenance"] != "auto-copied"]


def duplicates(pool):
    """[(id, id to keep)] for entries with exactly the same words as an older one. No model: an exact repeat needs no judgment."""
    first, out = {}, []
    for v in sorted(pool, key=lambda x: x["id"]):
        key = _norm(v)
        if len(key) < 20:
            continue
        if key in first:
            out.append((v["id"], first[key]))
        else:
            first[key] = v["id"]
    return out


def _branch_state(repo, branch, landed):
    if not branch:
        return "no branch"
    if branch in landed:
        return "merged into the main line"
    if g.try_run(["rev-parse", "--verify", "-q", f"refs/heads/{branch}"], repo.root)[0] == 0:
        return "branch exists, not merged"
    return "branch is gone and was never merged"


def triage_prompt(repo, views, cands):
    from . import branches
    landed = branches.landed(repo, views)
    lines = [TRIAGE_SYSTEM, "ENTRIES (newest first):"]
    for v in cands:
        files = [f for f in tracked(repo, v)[:6] if f and not f.startswith("-")]
        alive = sum(1 for f in files if g.try_run(["cat-file", "-e", f"HEAD:{f}"], repo.root)[0] == 0)
        lines += ["", f"entry {v['id']} ({v['kind']}, {v['age_days'] if v['age_days'] is not None else '?'} days old): {sanitize(v['topic'], 120)}",
                  f"  branch: {sanitize(v['branch'] or '-', 60)} ({_branch_state(repo, v['branch'], landed)})",
                  f"  covers {len(v['sources'])} recorded observation(s); files: {alive} of {len(files)} still exist"]
        lines += [f"  {k}: {sanitize(v['body'][k], 260)}" for k in ("context", "summary", "what", "why", "open") if v["body"].get(k)]
    return "\n".join(lines) + "\n"


def _fp(v):
    return hashlib.sha1(("|".join([v["id"], _norm(v), v["branch"] or ""])).encode("utf-8")).hexdigest()[:12]


def _record(repo, items):
    """Why each entry was archived, so a person can see it and put it back (`tidy --restore`)."""
    d = repo.cdir / "archive"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "reasons.jsonl", "a", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps({**it, "t": int(time.time())}) + "\n")


def _do_archive(repo, items):
    """Archive the entries named in items ([{entry, verdict, reason, redundant_of}]). Returns the ids that moved."""
    ids = [it["entry"] for it in items]
    moved = archive(repo, ids)
    _record(repo, items)
    return ids if moved else []


def triage(repo, call=None, now=time.time, apply=None):
    """Find the junk and the repeats in my private log. Exact repeats need no model. For the rest a cheap model judges what the code worked out about each entry
    (age, branch gone or merged, files still there), and Python accepts only a verdict about one of my own private, unpublished entries, with a reason, naming a
    real other entry for a repeat. With `apply` (tidy auto, and always before an automatic publish) the entries move to .git/logbook/archive/; otherwise the
    proposals wait for the person (`tidy --proposals`, `--accept`). Nothing is deleted. Never raises for a model problem; shares the observer's budget and pause."""
    from . import tree
    cfg = repo.cfg()
    apply = (mode(cfg) == "auto") if apply is None else apply
    views = tree.all_views(repo)[0]
    pool = triage_pool(views)
    by_id = {v["id"]: v for v in views}
    res = {"archived": [], "proposed": 0, "rejected": 0}
    st = _state(repo)
    items = [{"entry": i, "verdict": "redundant", "redundant_of": k, "reason": "says exactly the same as an older entry"} for i, k in duplicates(pool)][:TRIAGE_ARCHIVE_MAX]
    if not worker.enabled(repo):
        res["skipped"] = "the observer is off"
    else:
        call = call or (lambda p: worker.call_model(p, cfg.get("tidy_model", TIDY_MODEL)))
        with capture._lock(_dir(repo) / ".lock", timeout=0.2, stale=worker.LOCK_STALE) as got:
            led = worker.ledger(repo)
            if not got:
                res["skipped"] = "another tidy pass is running"
            elif now() < led["cooldown_until"]:
                res["skipped"] = "paused: " + (led.get("pause_reason") or "waiting after the usage allowance ran out")
            elif led["calls"] >= int(cfg.get("worker_calls", worker.MAX_CALLS)):
                res["skipped"] = "today's call cap is reached"
            else:
                taken = {i["entry"] for i in items}
                cands = [v for v in sorted(pool, key=lambda x: x["id"], reverse=True) if v["id"] not in taken and st["triaged"].get(v["id"]) != _fp(v)][:TRIAGE_MAX]
                if not cands:
                    res["skipped"] = "nothing new to judge"
                else:
                    sent, _ = redact(triage_prompt(repo, views, cands), cfg.get("deny", []))
                    text, cost, error = call(sent)
                    worker.settle(repo, led, cost, error, now)
                    if error:
                        res["error"] = error[:200]  # nothing is marked as judged, so the next pass asks again
                    else:
                        shown = {v["id"] for v in cands}
                        for b in parse(text, TRIAGE_KEYS)[:MAX_APPLY]:
                            eid, verdict, other = b.get("entry", ""), b.get("verdict", "").lower(), b.get("redundant_of", "")
                            ok = (eid in shown and verdict in ("junk", "redundant") and len(b.get("reason", "")) >= 8
                                  and (verdict == "junk" or (other in by_id and other != eid)))
                            if ok and len(items) < TRIAGE_ARCHIVE_MAX and eid not in taken:
                                taken.add(eid)
                                items.append({"entry": eid, "verdict": verdict, "redundant_of": other if verdict == "redundant" else "", "reason": b["reason"][:300]})
                            else:
                                res["rejected"] += 1
                        for v in cands:
                            st["triaged"][v["id"]] = _fp(v)
    if items:
        # a repeat of an entry that is itself archived in this pass must not leave nothing: follow it to the entry that stays, or drop the item if that one is junk
        by_entry = {i["entry"]: i for i in items}
        kept_items = []
        for i in items:
            target, hops = i["redundant_of"], 0
            while i["verdict"] == "redundant" and target in by_entry and hops < 5:
                nxt = by_entry[target]
                target, hops = (nxt["redundant_of"] if nxt["verdict"] == "redundant" else None), hops + 1
            if i["verdict"] == "junk" or (target and target != i["entry"]):
                kept_items.append({**i, "redundant_of": target or ""} if i["verdict"] == "redundant" else i)
        items = kept_items
        if apply:
            res["archived"] = _do_archive(repo, items)
        else:
            kept = {a["entry"]: a for a in st["archives"]}
            kept.update({i["entry"]: i for i in items})
            st["archives"] = list(kept.values())
            res["proposed"] = len(items)
    _save(repo, st)
    return res


def archive_proposals(repo):
    return _state(repo)["archives"]


def accept_archives(repo):
    """Archive what the worker proposed and the person accepted, if each is still mine, private and unpublished. Returns the ids that moved."""
    from . import tree
    st = _state(repo)
    live = {v["id"] for v in triage_pool(tree.all_views(repo)[0])}
    moved = _do_archive(repo, [a for a in st["archives"] if a["entry"] in live])
    st["archives"] = []
    _save(repo, st)
    return moved


def restore(repo, ids):
    """Put archived entries back in the private log. Returns how many came back."""
    n = 0
    for i in ids:
        src = repo.cdir / "archive" / f"{i}.json"
        if ID_RE.match(i) and src.exists() and not (repo.pdir / f"{i}.json").exists():
            shutil.copy2(src, repo.pdir / f"{i}.json")
            src.unlink()
            n += 1
    return n


def queue_pass(repo):
    """Keep the publish queue (outbox.py) right, with no model: a log is queued when it is saved; a note when it passes its checks (it names nothing that is missing and
    carries evidence), is not resolved, and is not a person's own note in manual mode (those go in with `note -q`); a status record when its note is queued or
    shared. An entry that was published, archived, or stopped passing leaves again, unless the person queued it. Returns {"queued": [ids], "removed": [ids]}."""
    from . import outbox, tree
    q = outbox.load(repo)
    mode = repo.publish_mode()
    waiting = {e.id: e for e in repo.unpublished()}
    views = {v["id"]: v for v in tree.all_views(repo)[0]}
    shared = {l.entry.id for l in repo.load_shared()[0]}

    def wants(e):
        if e.status:
            return False  # decided below, once the notes are
        if e.kind == "log":
            return True
        if (views.get(e.id) or {}).get("status") == "resolved":
            return False
        if e.provenance == "user-written":
            return mode in ("ask", "auto")  # in manual mode a person's note is queued by the person
        return bool(e.checks.get("evidence")) and not ground.problems(e.checks, True)

    want = {i for i, e in waiting.items() if wants(e)}
    want |= {i for i, e in waiting.items() if e.status and (e.status.get("of") in want or e.status.get("of") in shared or e.status.get("of") in q)}
    keep = {i for i in q if i in waiting and (q[i].get("by") == "user" or i in want)}
    added = outbox.add(repo, sorted(want - set(q)), "tidy")
    gone = outbox.drop(repo, [i for i in q if i not in keep])
    return {"queued": added, "removed": gone}


def run(repo, call=None, now=time.time):
    """The tidy worker's pass in manual mode: statuses for changed notes and triage, both kept as proposals for the person."""
    res = work(repo, call, now)
    res["triage"] = triage(repo, call, now, apply=False)
    res["queue"] = queue_pass(repo)
    return res


def gate(repo, call=None, now=time.time):
    """What runs before any publish in auto mode: fetch what teammates shared, archive the junk and the repeats, update statuses. If the model could not
    be asked (paused, over the day's cap, an error) the result says why in "blocked": publishing what has not been checked is what this exists to prevent."""
    from . import sync
    if "origin" in sync.remotes(repo):
        try:
            sync.sync(repo, "origin", fetch_only=True)
        except (SystemExit, OSError, ValueError):
            pass
    res = {"triage": triage(repo, call, now, apply=True)}
    res["status"] = work(repo, call, now)
    res["queue"] = queue_pass(repo)
    t = res["triage"]
    why = t.get("error") or (t.get("skipped") if str(t.get("skipped", "")).startswith(("paused", "today's call cap", "another tidy pass")) else "")
    res["blocked"] = why or ""
    return res


def auto(repo, call=None, now=time.time):
    """Everything the automatic mode does in one pass: judge changed notes, archive junk and repeats, archive old machine-made drafts."""
    from . import tree
    res = work(repo, call, now)
    res["triage"] = triage(repo, call, now, apply=True)
    res["archived"] = archive(repo, [c["id"] for c in garbage(repo, tree.all_views(repo)[0])])
    res["queue"] = queue_pass(repo)
    return res
