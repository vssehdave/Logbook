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


def parse(text):
    """Proposals as blocks of `key: value` lines (status_of, status, commits, reason) separated by a line of `---`. A value may run over several lines."""
    blocks, cur, key = [], {}, None
    for line in text.splitlines() + ["---"]:
        if line.strip() == "---":
            if cur:
                blocks.append({k: v.strip() for k, v in cur.items()})
            cur, key = {}, None
            continue
        m = re.match(r"^([a-z_]+):[ \t]?(.*)$", line)
        if m and m.group(1) in _KEYS:
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
            continue  # a saved log is the person's record of a session: it is merged (`merge_logs`), never dropped as junk
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


# ---- the tidy worker --------------------------------------------------------------------------------------------
TIDY_MODEL = "haiku"  # `config tidy_model` changes it; it is a different setting from the observer's model on purpose
MAX_JUDGED = 12  # candidates shown to the model in one call
MERGE_MIN = 4  # private logs on one branch before they are worth folding into one
MERGE_MAX = 12  # logs folded in one go
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
        if cfg.get("tidy", "manual") == "auto":
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


def mergeable(views):
    """{branch: [ids, newest first]} of my private saved logs, for branches that have enough of them to be worth folding into one."""
    by = {}
    for v in sorted(views, key=lambda x: x["id"], reverse=True):
        if v["kind"] == "log" and v["mine"] and v["scope"] == "private" and not v.get("is_status") and v["branch"]:
            by.setdefault(v["branch"], []).append(v["id"])
    return {b: ids for b, ids in by.items() if len(ids) >= MERGE_MIN}


def merge_logs(repo, call=None, now=time.time, limit=2):
    """Fold the older private logs of a branch into one new log (written by the cheap model, or by code without it). The originals move to the archive and
    the new log lists them as its sources. Returns [(branch, how many were folded, the new log id)]."""
    from . import savepoint, tree
    call = call or (lambda p: worker.call_model(p, repo.cfg().get("tidy_model", TIDY_MODEL)))
    views = tree.all_views(repo)[0]
    by_id = {v["id"]: v for v in views}
    done = []
    for branch, ids in list(mergeable(views).items())[:limit]:
        logs = [by_id[i] for i in reversed(ids[:MERGE_MAX])]  # oldest first
        obs = [{"id": v["id"], "type": "change", "title": v["topic"], "subtitle": "", "narrative": " ".join(v["body"].get(k, "") for k in ("what", "why", "summary") if v["body"].get(k))[:600],
                "facts": [], "files_read": [], "files_modified": v["paths"]} for v in logs]
        fields, how = savepoint.summarize(repo, branch, obs, call, now)
        e = savepoint._entry(repo, branch, logs[-1]["sha"] or "", obs, fields)
        e.supersedes = [v["id"] for v in logs]
        repo.add_private(e)
        archive(repo, e.supersedes)
        done.append((branch, len(logs), e.id))
    return done


def auto(repo, call=None, now=time.time):
    """Everything the automatic mode does in one pass: judge, fold logs, archive junk drafts."""
    from . import tree
    res = work(repo, call, now)
    res["folded"] = [(b, n) for b, n, _ in merge_logs(repo, call, now)]
    res["archived"] = archive(repo, [c["id"] for c in garbage(repo, tree.all_views(repo)[0])])
    return res
