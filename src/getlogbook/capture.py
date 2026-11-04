"""Capture: hook entry point, spool, reconcile, git post-commit floor, hook installers.

Design rules (from the review panels):
  * A hook only writes a small spool file and (maybe) spawns a detached worker. No model, no network, < 100 ms.
  * A hook never fails the agent: everything is caught, logged to errors.log, exit code 0.
  * `reconcile()` is the one sweep: spool -> transcript slices -> drafts; crash recovery; commits with no entry.
  * Drafts built without a model are provenance=auto-copied and are never injected (no 'why').
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import git as g
from .entry import BODY_FIELDS, LEVELS, Entry, from_json, new_id
from .store import Repo, atomic_write

MARK_BEGIN, MARK_END = "# >>> logbook >>>", "# <<< logbook <<<"
CLAUDE_EVENTS = ["SessionStart", "UserPromptSubmit", "Stop", "PreCompact", "SessionEnd"]


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ---- entries made by people/agents ---------------------------------------------------------------------------
def writer():
    """Who is writing a note: "agent-written" from inside an agent's session, else "user-written". Claude Code puts its session id in the
    environment of the commands it runs, which a person in their own terminal does not have. LOGBOOK_WRITER=agent|user says it outright (another
    agent, or a person running a command through an agent).  shortcut: only Claude Code is recognised by itself; others set LOGBOOK_WRITER."""
    forced = os.environ.get("LOGBOOK_WRITER", "").strip().lower()
    if forced in ("agent", "user"):
        return "agent-written" if forced == "agent" else "user-written"
    return "agent-written" if os.environ.get("CLAUDE_CODE_SESSION_ID") else "user-written"


def make_entry(repo, kind, topic, body, paths=None, provenance=None, via="cli", pending=False, supersedes=(), sha=None, level="", sources=(), checks=None):
    from . import tree
    body = {k: str(v)[:2000] for k, v in body.items() if k in BODY_FIELDS and v}
    e = Entry(id=new_id(), kind=kind, topic=topic[:200], body=body, provenance=provenance or writer(), captured_via=via,
              supersedes=list(supersedes), created=now(), level=level if level in LEVELS else "", sources=list(sources), v=2, checks=checks,
              display=repo.cfg().get("display", "") if repo.attribution() == "named" else "")
    if pending:  # change entries are written before the commit exists; post-commit attaches the sha
        e.anchor = {"paths": list(paths or [])}
        atomic_write(repo.cdir / "pending" / f"{e.id}.json", e.to_json())
    else:
        e.anchor = tree.anchor_for(repo, sha=sha, paths=paths, with_base=True)  # sha: note about an earlier commit
        repo.add_private(e)
    return e


def post_commit(repo):
    """Attach pending change entries to the commit that was just made. Infers nothing here (reconcile does)."""
    from . import tree
    n = 0
    pdir = repo.cdir / "pending"
    for p in sorted(pdir.glob("*.json")) if pdir.exists() else []:
        try:
            e = from_json(p.read_text(encoding="utf-8"))
            e.anchor = tree.anchor_for(repo, with_base=True)  # paths come from the commit itself
            repo.add_private(e)
            if repo.publish_mode() == "auto":  # the note is complete now: share it as auto mode promises
                from . import cli
                cli.auto_publish(repo, e)
            p.unlink()
            n += 1
        except (OSError, ValueError) as ex:
            repo.error(f"post-commit {p.name}: {ex}")
    return n


# ---- spool + detached worker ---------------------------------------------------------------------------------
@contextlib.contextmanager
def _lock(path, timeout=1.0):
    """Tiny cross-platform lock (O_EXCL file, stale after 10 s). Yields False if it could not be taken."""
    path.parent.mkdir(parents=True, exist_ok=True)
    end, fd = time.time() + timeout, None
    while time.time() < end:
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > 10:
                    path.unlink()
            except OSError:
                pass
            time.sleep(0.02)
    try:
        yield fd is not None
    finally:
        if fd is not None:
            os.close(fd)
            try:
                path.unlink()
            except OSError:
                pass


def spawn_detached(args, cwd):
    if os.environ.get("LOGBOOK_NO_SPAWN"):  # tests
        return
    kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True, cwd=str(cwd))
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        try:  # escape the agent's job object if allowed, otherwise fall back
            subprocess.Popen(args, creationflags=flags | 0x01000000, **kw)  # CREATE_BREAKAWAY_FROM_JOB
        except OSError:
            subprocess.Popen(args, creationflags=flags, **kw)
    else:
        subprocess.Popen(args, start_new_session=True, **kw)


def spool_event(repo, event, agent, payload):
    head, branch, paths, _ = g.state(repo.root)  # one subprocess
    item = {"event": event, "agent": agent, "t": time.time(), "head": head or "", "branch": branch,
            "paths": paths[:40], "session": str(payload.get("session_id", ""))[:80], "transcript": str(payload.get("transcript_path", "")),
            "prompt": str(payload.get("prompt", ""))[:2000], "last": str(payload.get("last_assistant_message", ""))[:4000]}
    atomic_write(repo.cdir / "spool" / f"{int(time.time() * 1000):013d}-{os.urandom(3).hex()}.json", json.dumps(item))
    if item["session"] and item["transcript"]:  # copy the new bytes now: agents prune old transcripts
        checkpoint(repo, item["session"], item["transcript"])


def handle_hook(event, agent, raw):
    """Entry point for `logbook capture`. Returns text for stdout (may be ''). Never raises."""
    repo = None
    try:
        payload = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(payload, dict):
            payload = {}
        repo = Repo(payload.get("cwd") or ".")
        cfg = repo.cfg()
        if not cfg.get("user"):
            return ""
        out = ""
        if event in ("SessionStart", "UserPromptSubmit", "PreToolUse"):
            from . import recall  # only the prompt-time hooks need retrieval; Stop/SessionEnd stay lean
            files = []
            ti = payload.get("tool_input")
            if event == "PreToolUse" and isinstance(ti, dict) and ti.get("file_path"):
                try:
                    files = [Path(ti["file_path"]).resolve().relative_to(repo.root.resolve()).as_posix()]
                except (ValueError, OSError):
                    files = []
            sid = str(payload.get("session_id", ""))
            text = recall.digest(repo, event, payload.get("prompt", ""), files, sid)
            if event == "UserPromptSubmit":
                from . import nudge
                text = nudge.join(text, nudge.nudge_text(repo, sid))
                nudge.new_turn(repo, sid)  # after the reminder has looked at the turn that just ended
            out = recall.hook_json(event, text)
        if event in ("Stop", "PreCompact", "SessionEnd"):  # prompt-time hooks stay read-only and fast
            spool_event(repo, event, agent, payload)
            if event == "Stop":
                from . import nudge
                out = nudge.stop_block(repo, payload)
        if event in ("SessionStart", "PreCompact", "SessionEnd"):
            spawn_detached([cfg.get("interpreter") or sys.executable, "-m", "getlogbook", "reconcile", "--quiet"], repo.root)
        return out
    except Exception as ex:  # a hook must never break the agent
        try:
            (repo.error if repo else (lambda m: None))(f"capture {event}: {ex!r}")
        except Exception:
            pass
        return ""


# ---- reconcile -----------------------------------------------------------------------------------------------
def _msg(obj):
    m = obj.get("message") if isinstance(obj.get("message"), dict) else obj
    role = m.get("role") or obj.get("type") or ""
    c = m.get("content")
    if isinstance(c, list):
        c = " ".join(p.get("text", "") for p in c if isinstance(p, dict) and p.get("type") == "text")
    return role, c.strip() if isinstance(c, str) else ""


def _sid(sid):
    return "".join(c for c in sid if c.isalnum() or c in "-_")[:80] or "nosession"


def _load(d):
    try:
        st = json.loads((d / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    st.setdefault("offset", 0)
    st.setdefault("paths", [])
    st.setdefault("summarized", 0)
    return st


def _copy_slice(d, st, transcript):
    """Copy transcript bytes added since the last checkpoint into the session folder; returns them (b'' if none)."""
    if transcript and Path(transcript).is_file():
        size = Path(transcript).stat().st_size
        if size < st["offset"]:
            st["offset"] = 0
        if size > st["offset"]:
            with open(transcript, "rb") as f:
                f.seek(st["offset"])
                data = f.read()
            d.mkdir(parents=True, exist_ok=True)
            (d / f"slice-{st['offset']:012d}.jsonl").write_bytes(data)
            st["offset"] = size
            return data
    return b""


def checkpoint(repo, sid, transcript, paths=(), meta=None):
    """Copy the transcript bytes added since the last checkpoint. Cheap; safe to call from a hook."""
    d = repo.cdir / "sessions" / _sid(sid)
    with _lock(d / ".lock") as got:
        if not got:
            return None
        st = _load(d)
        data = _copy_slice(d, st, transcript)
        if data:
            from . import nudge
            st["turn"] = nudge.add_stats(st.get("turn"), nudge.turn_stats(data))  # add to the turn: a checkpoint can come mid-turn
        st["paths"] = sorted(set(st["paths"]) | set(paths))[:200]
        st["last"] = time.time()
        st.update(meta or {})
        atomic_write(d / "state.json", json.dumps(st))
        return d, st


def _finalize(repo, sid, d, st, agent, head, branch):
    from . import tree
    texts = []
    for sl in sorted(d.glob("slice-*.jsonl")):
        if int(sl.stem.split("-")[1]) < st["summarized"]:
            continue
        for line in sl.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                role, text = _msg(json.loads(line))
            except ValueError:
                continue
            if text:
                texts.append((role, text))
    assistant = [t for r, t in texts if r == "assistant"]
    user = [t for r, t in texts if r == "user"]
    if not assistant:
        return None
    st["summarized"] = st["offset"]
    first_line = lambda s, n: (s.splitlines() or [""])[0][:n]
    e = Entry(id=new_id(), kind="finding", topic=(first_line(user[0], 80) if user else f"session {sid[:8]}"),
              body={"summary": assistant[-1][:300], "what": "\n".join("- " + first_line(a, 120) for a in assistant[:5])},
              provenance="auto-copied", captured_via=agent or "agent", created=now())
    a = tree.anchor_for(repo, sha=head or None, paths=st["paths"][:40], dirty=bool(st["paths"]))
    a["branch"] = branch or a["branch"]
    e.anchor = a
    repo.add_private(e)
    return e


def reconcile(repo, quiet=True):
    """Process spooled hook events, recover crashed sessions, and record commits that have no entry."""
    done = {"drafts": 0, "floor": 0, "pending": 0}
    sessions = {}
    spool = repo.cdir / "spool"
    for p in sorted(spool.glob("*.json")) if spool.exists() else []:
        try:
            it = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            p.unlink(missing_ok=True)
            continue
        sid = it.get("session") or "nosession"
        s = sessions.setdefault(sid, {"agent": it.get("agent", ""), "transcript": "", "final": False, "head": "", "branch": "", "paths": set()})
        s["transcript"] = it.get("transcript") or s["transcript"]
        s["head"], s["branch"] = it.get("head") or s["head"], it.get("branch") or s["branch"]
        s["paths"] |= set(it.get("paths", []))
        s["final"] |= it.get("event") in ("PreCompact", "SessionEnd")
        p.unlink(missing_ok=True)
    for sid, s in sessions.items():
        safe = _sid(sid)
        got = checkpoint(repo, safe, s["transcript"], s["paths"], {"agent": s["agent"], "head": s["head"], "branch": s["branch"]})
        if got and s["final"]:
            d = got[0]
            with _lock(d / ".lock") as ok:
                st = _load(d)
                if ok and _finalize(repo, safe, d, st, s["agent"], s["head"], s["branch"]):
                    done["drafts"] += 1
                    st["paths"] = []
                if ok:
                    atomic_write(d / "state.json", json.dumps(st))
    # crash recovery: sessions with unsummarised bytes and no activity for 30 minutes
    sdir = repo.cdir / "sessions"
    for d in sdir.iterdir() if sdir.exists() else []:
        if not d.is_dir():
            continue
        with _lock(d / ".lock") as ok:
            st = _load(d)
            if ok and st["offset"] > st["summarized"] and time.time() - st.get("last", 0) > 1800:
                if _finalize(repo, d.name, d, st, st.get("agent", ""), st.get("head", ""), st.get("branch", "")):
                    done["drafts"] += 1
                atomic_write(d / "state.json", json.dumps(st))
    done["pending"] = post_commit(repo) if (repo.cdir / "pending").exists() else 0
    done["floor"] = _commit_floor(repo)
    return done


def _commit_floor(repo):
    """Inferred entries for my own commits since init that have no entry yet (covers web-UI/hook-less commits)."""
    from . import tree
    base = repo.cfg().get("floor_base")
    if not base or not g.commit_exists(repo.root, base):
        return 0
    email = g.config_get(repo.root, "user.email")
    rc, out, _ = g.try_run(["log", "--first-parent", "-n50", f"--author={email}", "--format=%H", f"{base}..HEAD"], repo.root)
    covered = {l.entry.anchor.get("sha") for l in repo.all_entries()}
    n = 0
    for sha in (out.split() if rc == 0 else []):
        if sha in covered:
            continue
        info = g.commit_info(repo.root, sha) or {}
        paths = g.changed_paths(repo.root, sha)
        body = g.try_run(["show", "-s", "--format=%b", sha], repo.root)[1].strip()
        e = Entry(id=new_id(), kind="change", topic=info.get("subject", "")[:200],
                  body={"summary": info.get("subject", ""), "what": (body + f"\nfiles: {len(paths)}").strip()},
                  provenance="auto-copied", captured_via="reconcile", created=now())
        e.anchor = tree.anchor_for(repo, sha=sha, paths=paths)
        repo.add_private(e)
        n += 1
    return n


# ---- installers ---------------------------------------------------------------------------------------------
def _py(repo):
    return (repo.cfg().get("interpreter") or sys.executable).replace("\\", "/")


def install_git_hook(repo):
    hooks = Path(g.run(["rev-parse", "--path-format=absolute", "--git-path", "hooks"], repo.root).strip())
    hooks.mkdir(parents=True, exist_ok=True)
    f = hooks / "post-commit"
    block = f'{MARK_BEGIN}\n"{_py(repo)}" -m getlogbook post-commit >/dev/null 2>&1 || true\n{MARK_END}\n'
    text = f.read_text(encoding="utf-8") if f.exists() else "#!/bin/sh\n"
    if MARK_BEGIN not in text:  # chain, never overwrite
        f.write_text(text.rstrip("\n") + "\n" + block, encoding="utf-8", newline="\n")
    try:
        f.chmod(f.stat().st_mode | 0o111)
    except OSError:
        pass
    c = repo.cfg()
    c.setdefault("floor_base", g.head_sha(repo.root) or "")
    repo.save_cfg(c)
    return f


def _hooks_dir(repo):
    return Path(g.run(["rev-parse", "--path-format=absolute", "--git-path", "hooks"], repo.root).strip())


def _strip_hook_block(f):
    """Remove our marked block from a hook file; delete the file if nothing but the shebang is left."""
    if not (f.exists() and MARK_BEGIN in f.read_text(encoding="utf-8")):
        return
    t = f.read_text(encoding="utf-8")
    a, _, rest = t.partition(MARK_BEGIN)
    _, _, b = rest.partition(MARK_END)
    left = (a + b.lstrip("\n")).rstrip("\n") + "\n"
    if left.strip() in ("", "#!/bin/sh"):
        f.unlink()
    else:
        f.write_text(left, encoding="utf-8", newline="\n")


def uninstall_git_hook(repo):
    f = _hooks_dir(repo) / "post-commit"
    _strip_hook_block(f)
    return f


def install_pre_push_hook(repo):
    """A reminder on stderr of notes that are still private, or published but not pushed. It never blocks a push and never shares
    anything: `logbook publish` and `logbook sync` are the only ways notes leave this clone."""
    hooks = _hooks_dir(repo)
    hooks.mkdir(parents=True, exist_ok=True)
    f = hooks / "pre-push"
    block = f'{MARK_BEGIN}\n"{_py(repo)}" -m getlogbook queue --hook >&2 || true\n{MARK_END}\n'
    _strip_hook_block(f)  # replace the 0.0.3 block, which also pushed notes, rather than keep it
    text = f.read_text(encoding="utf-8") if f.exists() else "#!/bin/sh\n"
    f.write_text(text.rstrip("\n") + "\n" + block, encoding="utf-8", newline="\n")  # chain, never overwrite
    with contextlib.suppress(OSError):
        f.chmod(f.stat().st_mode | 0o111)
    return f


def uninstall_pre_push_hook(repo):
    f = _hooks_dir(repo) / "pre-push"
    _strip_hook_block(f)
    return f


def claude_snippet(repo, pretool=False):
    py = _py(repo)
    mk = lambda ev: [{"hooks": [{"type": "command", "command": f'"{py}" -m getlogbook capture --event {ev} --agent claude-code'}]}]
    hooks = {ev: mk(ev) for ev in CLAUDE_EVENTS}
    if pretool:
        hooks["PreToolUse"] = [{"matcher": "Read|Edit|Write|MultiEdit", **mk("PreToolUse")[0]}]
    return {"hooks": hooks}


# Commands Claude may run without asking: they only read, or write to your own private notes. Anything that shares, removes or changes
# settings (publish, sync, purge, gc, trust, config, tidy --apply) is left out, so it still asks.
ALLOW = ("Bash(logbook note:*)", "Bash(logbook ask:*)", "Bash(logbook context:*)", "Bash(logbook cites:*)", "Bash(logbook log:*)",
         "Bash(logbook status:*)", "Bash(logbook summarize:*)", "Bash(logbook backfill:*)")


def install_claude(repo, path=None, pretool=False, write=False, remove=False):
    path = Path(path or repo.root / ".claude" / "settings.local.json")  # local: it holds a machine-specific interpreter path
    try:
        cur = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except ValueError:
        raise SystemExit(f"logbook: {path} is not valid JSON; refusing to touch it")
    hooks = cur.setdefault("hooks", {})
    snippet = claude_snippet(repo, pretool)["hooks"]
    for ev, entries in list(hooks.items()):  # always drop our previous entries so install is idempotent
        keep = [e for e in entries if "getlogbook capture" not in json.dumps(e)]
        if keep:
            hooks[ev] = keep
        else:
            del hooks[ev]
    if not remove:
        for ev, entries in snippet.items():
            hooks.setdefault(ev, []).extend(entries)
    if not hooks:
        cur.pop("hooks")
    perms = cur.setdefault("permissions", {})
    allow = perms.get("allow", [])
    if isinstance(allow, list):  # the allow list is the person's own: only our exact entries are touched
        allow = [x for x in allow if x not in ALLOW] + ([] if remove else list(ALLOW))
        if allow:
            perms["allow"] = allow
        else:
            perms.pop("allow", None)
    if not perms:
        cur.pop("permissions")
    if write:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, json.dumps(cur, indent=2))
    return path, cur
