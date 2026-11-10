"""Repo handle, private log, shared log on custom refs. Everything is plain files + git plumbing.

Shared layout (one writer per ref, so no merge conflicts):
    refs/logbook/log/<user>/<device>            own writes (never overwritten by fetch)
    refs/logbook-remote/<remote>/log/<u>/<d>    everyone else's, fetched with a separate refspec
Each ref's tip tree holds every entry as entries/<id>.json (state lives in the tree, history is not needed).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from . import git as g
from .entry import BODY_FIELDS, ID_RE, Entry, from_dict, from_json

PREFIX = "refs/logbook/log"
REMOTE_NS = "refs/logbook-remote"
BRANCH_PREFIX = "refs/heads/logbook/log"
_REF_RE = re.compile(r"/(?:branch)?log/([0-9a-f]{6,16})/([0-9a-f]{2,16})$")
# One shelf per person. The second path part used to be a per-clone device id; it is now this constant, still hex so that
# 0.0.2 readers match it, and git refuses `log/<user>` next to `log/<user>/<device>`, so the path shape cannot change.
SHELF = "000000"
PUBLISH_MODES = ("manual", "ask", "auto")  # least to most hands-off
MAX_BLOB = 65536
MAX_PER_REF = 5000
DEFAULT_POLICY = {"publish": True, "inject_from": "trusted", "attribution": "named",
                  "max_entry_bytes": 32768, "retention_days": 0}


def _apply_tombstones(files):
    """A purge must win a merge: an entry with a tombstone in the same tree is dropped, so purged notes never come back."""
    dead = {p[len("tombstones/"):] for p in files if p.startswith("tombstones/")}
    return {p: o for p, o in files.items() if not (p.startswith("entries/") and p[len("entries/"):] in dead)}


def _norm(e):
    return " ".join(" ".join([e.topic, *(e.body.get(k, "") for k in BODY_FIELDS)]).lower().split())


def user_id(email):
    """Stable, pseudonymous id for a person: same on every machine, derived from their git email."""
    return hashlib.sha256(email.strip().lower().encode()).hexdigest()[:10]


_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_NOREPLY_RE = re.compile(r"^(?:\d+\+)?([A-Za-z0-9-]+)@users\.noreply\.github\.com$")


def github_login(root):
    """Your GitHub login, or '' when it cannot be found. In order: LOGBOOK_GITHUB_LOGIN (an override, empty means "none"), `git config github.user`, a
    users.noreply.github.com commit email, then `gh api user` when the gh CLI is signed in (the only one that touches the network, once, at setup)."""
    if "LOGBOOK_GITHUB_LOGIN" in os.environ:
        found = os.environ["LOGBOOK_GITHUB_LOGIN"].strip()
        return found if _LOGIN_RE.match(found) else ""
    found = g.config_get(root, "github.user").strip()
    if not _LOGIN_RE.match(found):
        m = _NOREPLY_RE.match(g.config_get(root, "user.email").strip())
        found = m.group(1) if m else ""
    if not found and shutil.which("gh"):
        try:
            p = subprocess.run(["gh", "api", "user", "--jq", ".login"], capture_output=True, text=True, timeout=8, cwd=str(root))
            found = p.stdout.strip() if p.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            found = ""
    return found if _LOGIN_RE.match(found) else ""


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(2).hex()}.tmp")
    tmp.write_text(data, encoding="utf-8", newline="\n")
    for i in range(6):  # antivirus / OneDrive can briefly lock the target on Windows
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.05 * (i + 1))
    os.replace(tmp, path)


class Loaded:
    __slots__ = ("entry", "scope", "user", "device", "ref")

    def __init__(self, entry, scope, user="", device="", ref=""):  # scope: shared | private
        self.entry, self.scope, self.user, self.device, self.ref = entry, scope, user, device, ref


class Repo:
    def __init__(self, cwd="."):
        self.root, self.common = g.repo_paths(cwd)
        self.cdir = self.common / "logbook"  # shared by all worktrees of this clone
        self._memo = None  # set inside `snapshot()`: the config and policy files read once
        self._db = None

    # config ---------------------------------------------------------------
    def _json(self, path):
        """A small JSON file ({} when missing or not JSON). Inside `snapshot()` it is read once."""
        if self._memo is not None and path in self._memo:
            return self._memo[path]
        try:
            val = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            val = {}
        if self._memo is not None:
            self._memo[path] = val
        return val

    @contextlib.contextmanager
    def snapshot(self):
        """Inside this block the config and the policy are read from disk once, not once per note: placing thousands of notes asked for the
        config seven times each (measured: 2 s of a 2.5 s prompt at 1,000 notes). Nothing else changes; save_cfg drops what it saved."""
        outer = self._memo
        if outer is None:
            self._memo = {}
        try:
            yield
        finally:
            if outer is None:
                self._memo = None

    def cfg(self):
        return dict(self._json(self.cdir / "config.json"))

    def save_cfg(self, c):
        atomic_write(self.cdir / "config.json", json.dumps(c, indent=2, sort_keys=True))
        if self._memo is not None:
            self._memo.pop(self.cdir / "config.json", None)

    def init(self):
        c = self.cfg()
        email = g.config_get(self.root, "user.email").lower()
        if not email:
            raise SystemExit("logbook: set `git config user.email` first (used only to derive a stable pseudonymous id).")
        c.setdefault("user", user_id(email))
        c.setdefault("device", os.urandom(3).hex())
        login = github_login(self.root)
        if login:
            c.setdefault("github", login)
        c.setdefault("display", login or g.config_get(self.root, "user.name"))  # what teammates see: your GitHub login, else your git name
        c.setdefault("trusted", [])
        c.setdefault("deny", [])
        c.setdefault("transport", "refs")
        c.setdefault("interpreter", __import__("sys").executable)
        self.save_cfg(c)
        return c

    @property
    def user(self):
        return self.cfg().get("user", "")

    @property
    def device(self):
        return self.cfg().get("device", "")

    def policy(self):
        """Repo policy (tracked file, owner-controlled). Only ever *restricts* the client."""
        p = dict(DEFAULT_POLICY)
        p.update(self._json(self.root / ".logbook" / "policy.json"))
        return p

    def attribution(self):
        order = ["none", "pseudonym", "named"]  # policy sets the ceiling
        want = self.cfg().get("attribution", "named")
        cap = self.policy().get("attribution", "named")
        return order[min(order.index(want) if want in order else 1, order.index(cap) if cap in order else 1)]

    def publish_mode(self):
        """How logs and notes are saved and shared: manual (you run `logbook log` and `logbook publish`), ask (the agent asks you, then runs them; the
        default), auto (it saves and publishes by itself). A repo policy that turns publishing off wins and reads as "never"."""
        if not self.policy().get("publish", True):
            return "never"
        mode = self.cfg().get("publish", "ask")
        return mode if mode in PUBLISH_MODES else "ask"

    def committers(self):
        """Ids of people with commits on this branch's first-parent line (set for free by the Anchorer, else one git log)."""
        if getattr(self, "_committers", None) is None:
            out = g.try_run(["log", "--first-parent", "-n500", "--format=%ae"], self.root)[1]
            self._committers = {user_id(e) for e in out.split() if e.strip()}
        return self._committers

    def trusted(self):
        """Whose notes may be injected into an agent's context. Storage and search cover everyone regardless.
        Default: you, anyone with a commit on this line of history, and anyone you ran `trust` on.
        policy inject_from=self narrows it to you; cfg trust_committers=false turns the committer rule off."""
        t = {self.user}
        if self.policy().get("inject_from") != "self":
            t |= set(self.cfg().get("trusted", []))
            if self.cfg().get("trust_committers", True):
                t |= self.committers()
        return t

    def own_ref(self):
        base = BRANCH_PREFIX if self.cfg().get("transport") == "branches" else PREFIX
        return f"{base}/{self.user}/{SHELF}"

    # private log ---------------------------------------------------------
    @property
    def db(self):
        if self._db is None:
            from .notesdb import NoteDB
            self._db = NoteDB(self)
        return self._db

    def add_private(self, e, shelf=None):
        self.db.add_private(e, shelf=shelf)

    def get_private(self, eid):
        return self.db.get_private(eid)

    def drop_private(self, eid):
        return self.db.drop_private(eid)

    def load_private(self):
        return self.db.load_private()

    def audit(self, line):
        with open(self.cdir / "audit.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {line}\n")

    def error(self, line):
        try:
            with open(self.cdir / "errors.log", "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {line}\n")
        except OSError:
            pass

    # shared log ----------------------------------------------------------
    def _tree_files(self, ref):
        """{path: oid} for the tip tree of ref (empty if the ref is missing)."""
        rc, out, _ = g.try_run(["ls-tree", "-r", "--long", ref], self.root)
        files = {}
        if rc:
            return files
        for line in out.splitlines():
            meta, _, path = line.partition("\t")
            parts = meta.split()
            if len(parts) == 4 and parts[1] == "blob" and parts[3].isdigit() and int(parts[3]) <= MAX_BLOB:
                files[path] = parts[2]
        return files

    def _write_ref(self, ref, files, message, parent):
        """Create a commit whose tree is exactly `files` ({path: bytes_or_oid}) and point `ref` at it."""
        idx = self.cdir / f"tmp-index-{os.getpid()}-{os.urandom(2).hex()}"
        env = {"GIT_INDEX_FILE": str(idx), "GIT_AUTHOR_NAME": "logbook", "GIT_AUTHOR_EMAIL": "logbook@localhost",
               "GIT_COMMITTER_NAME": "logbook", "GIT_COMMITTER_EMAIL": "logbook@localhost"}
        try:
            lines = []
            for path, val in sorted(files.items()):
                oid = val if isinstance(val, str) else g.run(["hash-object", "-w", "--stdin"], self.root, input=val).strip()
                lines.append(f"100644 {oid}\t{path}\n")
            g.run(["update-index", "--index-info"], self.root, input="".join(lines), env=env) if lines else None
            tree = g.run(["write-tree"], self.root, env=env).strip() if lines else \
                g.run(["hash-object", "-t", "tree", "-w", "--stdin"], self.root, input=b"").strip()
            parents = [parent] if isinstance(parent, str) else list(parent or [])
            args = ["commit-tree", tree, "-m", message] + [x for p in parents for x in ("-p", p)]
            commit = g.run(args, self.root, env=env).strip()
            g.run(["update-ref", ref, commit], self.root)
            return commit
        finally:
            try:
                idx.unlink()
            except OSError:
                pass

    def duplicate_of(self, e):
        """Why `e` should not be published again: ("same-id", loaded) when any writer's ref already holds that id, or
        ("same-text", loaded) when someone else already shared the same words. None if it is new."""
        shared, tombs = self.load_shared()
        text = _norm(e)
        for l in shared:
            if (l.user, l.entry.id) in tombs:
                continue
            if l.entry.id == e.id:
                return "same-id", l
            if l.user != self.user and text and _norm(l.entry) == text:
                return "same-text", l
        return None

    def publish(self, entries):
        """Write notes to your shared ref. A savepoint note is refused here, whoever asks: it and the log behind it stay on this machine."""
        if any(e.kind == "savepoint" for e in entries):
            raise ValueError("a savepoint note stays on this machine; only notes are published")
        ref = self.own_ref()
        tip = g.try_run(["rev-parse", "--verify", "-q", ref], self.root)[1].strip() or None
        files = self._tree_files(ref) if tip else {}
        for e in entries:
            data = e.to_json().encode("utf-8")
            if len(data) > self.policy()["max_entry_bytes"]:
                raise ValueError(f"entry {e.id} is {len(data)} bytes; policy max is {self.policy()['max_entry_bytes']}")
            files[f"entries/{e.id}.json"] = data
        self._write_ref(ref, files, f"logbook: +{len(entries)} entries", tip)
        self.db.mark_published([e.id for e in entries], ref)
        for e in entries:
            self.audit(f"publish {e.id} -> {ref}")
        return ref

    def purge(self, eid, reason="author request"):
        """Rewrite own ref as a parentless commit without the entry; leave an id-only tombstone."""
        ref = self.own_ref()
        files = self._tree_files(ref)
        if f"entries/{eid}.json" not in files:
            return None
        del files[f"entries/{eid}.json"]
        files[f"tombstones/{eid}.json"] = json.dumps({"id": eid, "reason": reason[:100], "date": time.strftime("%Y-%m-%d")}).encode()
        self._write_ref(ref, files, f"logbook: purge {eid}", None)
        self.drop_private(eid)
        self.audit(f"purge {eid} {ref}")
        return ref

    def squash_own_ref(self):
        """Parentless commit with the same tree (gc). Caller force-pushes with lease."""
        ref = self.own_ref()
        files = self._tree_files(ref)
        if not files:
            return None
        self._write_ref(ref, files, "logbook: squash", None)
        return ref

    def ref_tips(self):
        out = g.try_run(["for-each-ref", "--format=%(objectname) %(refname)", "refs/logbook", REMOTE_NS, "refs/heads/logbook"], self.root)[1]
        return [tuple(l.split(" ", 1)) for l in out.splitlines() if " " in l and _REF_RE.search(l)]

    def load_shared(self):
        """Every shared note and the tombstones, from the local mirror of the shelves in git (notesdb.py), brought up to date first."""
        return self.db.shared()

    def unpublished(self):
        """Your private notes that are not on your shared ref yet. Auto-copied entries carry no reason, so they are not offered (or counted in the push reminder). A log is never one of them: logs stay on this machine."""
        shared, _ = self.load_shared()
        done = {l.entry.id for l in shared if l.user == self.user}
        return [e for e in self.load_private() if e.id not in done and e.kind != "savepoint"]

    def queued(self):
        """The private entries in the publish queue (outbox.py) that are not shared yet: what `logbook publish` shares."""
        from . import outbox
        q = outbox.load(self)
        return [e for e in self.unpublished() if e.id in q]

    def all_entries(self):
        """Shared (merged at read time, deduped by id) + private overlay. Superseded/purged entries are hidden."""
        shared, tombs = self.load_shared()
        by_id = {}
        for l in shared:
            if (l.user, l.entry.id) in tombs:
                continue
            by_id.setdefault(l.entry.id, l)
        me = self.user
        for e in self.load_private():
            by_id.setdefault(e.id, Loaded(e, "private", me, self.device, ""))
        # only the same author may supersede (hide) an entry, so a hostile writer cannot hide others' work
        hidden = {s for l in by_id.values() for s in l.entry.supersedes if by_id.get(s) and by_id[s].user == l.user}
        return [l for l in by_id.values() if l.entry.id not in hidden]

    def label(self, l):
        """Human label for an author under the repo/user attribution setting."""
        if l.user == self.user:
            return "you"
        mode = self.attribution()
        if mode == "none":
            return "teammate"
        return (l.entry.display or l.user) if mode == "named" else l.user
