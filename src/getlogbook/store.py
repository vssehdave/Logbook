"""Repo handle, private log, shared log on custom refs. Everything is plain files + git plumbing.

Shared layout (one writer per ref, so no merge conflicts):
    refs/logbook/log/<user>/<device>            own writes (never overwritten by fetch)
    refs/logbook-remote/<remote>/log/<u>/<d>    everyone else's, fetched with a separate refspec
Each ref's tip tree holds every entry as entries/<id>.json (state lives in the tree, history is not needed).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from . import git as g
from .entry import BODY_FIELDS, Entry, from_dict, from_json

PREFIX = "refs/logbook/log"
REMOTE_NS = "refs/logbook-remote"
BRANCH_PREFIX = "refs/heads/logbook/log"
_REF_RE = re.compile(r"/(?:branch)?log/([0-9a-f]{6,16})/([0-9a-f]{2,16})$")
# One shelf per person. The second path part used to be a per-clone device id; it is now this constant, still hex so that
# 0.0.2 readers match it, and git refuses `log/<user>` next to `log/<user>/<device>`, so the path shape cannot change.
SHELF = "000000"
PUBLISH_MODES = ("manual", "ask", "auto")  # least to most hands-off
LEGACY_MODES = {"never": "manual", "claude": "ask"}  # the 0.0.4 names, read as their nearest new mode
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

    # config ---------------------------------------------------------------
    def cfg(self):
        try:
            return json.loads((self.cdir / "config.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def save_cfg(self, c):
        atomic_write(self.cdir / "config.json", json.dumps(c, indent=2, sort_keys=True))

    def init(self):
        c = self.cfg()
        email = g.config_get(self.root, "user.email").lower()
        if not email:
            raise SystemExit("logbook: set `git config user.email` first (used only to derive a stable pseudonymous id).")
        c.setdefault("user", user_id(email))
        c.setdefault("device", os.urandom(3).hex())
        c.setdefault("display", g.config_get(self.root, "user.name"))
        c.setdefault("trusted", [])
        c.setdefault("deny", [])
        c.setdefault("transport", "refs")
        c.setdefault("interpreter", __import__("sys").executable)
        self.save_cfg(c)
        for d in ("private", "sessions", "spool", "seen"):
            (self.cdir / d).mkdir(parents=True, exist_ok=True)
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
        try:
            p.update(json.loads((self.root / ".logbook" / "policy.json").read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
        return p

    def attribution(self):
        order = ["none", "pseudonym", "named"]  # policy sets the ceiling
        want = self.cfg().get("attribution", "named")
        cap = self.policy().get("attribution", "named")
        return order[min(order.index(want) if want in order else 1, order.index(cap) if cap in order else 1)]

    def publish_mode(self):
        """How logs and notes are saved and shared: manual (you run `logbook log` and `logbook publish`), ask (the agent asks you, then runs them; the
        default), auto (it saves and publishes by itself). A repo policy that turns publishing off wins and reads as "never"; 0.0.4's names still read."""
        if not self.policy().get("publish", True):
            return "never"
        mode = self.cfg().get("publish", "ask")
        mode = LEGACY_MODES.get(mode, mode)
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

    def legacy_refs(self):
        """Your own local per-device refs from 0.0.2 (one per clone), which `adopt_legacy` folds into the single shelf."""
        own = self.own_ref()
        out = g.try_run(["for-each-ref", "--format=%(refname)", f"{PREFIX}/{self.user}", f"{BRANCH_PREFIX}/{self.user}"], self.root)[1]
        return [r for r in out.split() if r != own and _REF_RE.search(r)]

    def adopt_legacy(self):
        """Move entries from old per-device refs into the shelf, then delete the old local refs. Returns the refs that were folded."""
        old = self.legacy_refs()
        if not old:
            return []
        ref = self.own_ref()
        tip = g.try_run(["rev-parse", "--verify", "-q", ref], self.root)[1].strip() or None
        files = self._tree_files(ref) if tip else {}
        for r in old:
            files.update(self._tree_files(r))
        files = _apply_tombstones(files)
        self._write_ref(ref, files, "logbook: adopt per-device refs", tip)
        for r in old:
            g.run(["update-ref", "-d", r], self.root)
        c = self.cfg()  # `sync` deletes these names on the remote after the shelf has been pushed
        c["legacy_remote"] = sorted(set(c.get("legacy_remote", [])) | set(old))
        self.save_cfg(c)
        return old

    # private log ---------------------------------------------------------
    @property
    def pdir(self):
        return self.cdir / "private"

    def add_private(self, e):
        atomic_write(self.pdir / f"{e.id}.json", e.to_json())

    def get_private(self, eid):
        try:
            return from_json((self.pdir / f"{eid}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def drop_private(self, eid):
        try:
            (self.pdir / f"{eid}.json").unlink()
            return True
        except OSError:
            return False

    def load_private(self):
        out = []
        for p in sorted(self.pdir.glob("*.json")) if self.pdir.exists() else []:
            try:
                out.append(from_json(p.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                continue
        return out

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
        self.adopt_legacy()
        ref = self.own_ref()
        tip = g.try_run(["rev-parse", "--verify", "-q", ref], self.root)[1].strip() or None
        files = self._tree_files(ref) if tip else {}
        for e in entries:
            data = e.to_json().encode("utf-8")
            if len(data) > self.policy()["max_entry_bytes"]:
                raise ValueError(f"entry {e.id} is {len(data)} bytes; policy max is {self.policy()['max_entry_bytes']}")
            files[f"entries/{e.id}.json"] = data
        self._write_ref(ref, files, f"logbook: +{len(entries)} entries", tip)
        for e in entries:
            self.audit(f"publish {e.id} -> {ref}")
        return ref

    def purge(self, eid, reason="author request"):
        """Rewrite own ref as a parentless commit without the entry; leave an id-only tombstone."""
        self.adopt_legacy()
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
        self.adopt_legacy()
        ref = self.own_ref()
        files = self._tree_files(ref)
        if not files:
            return None
        self._write_ref(ref, files, "logbook: squash", None)
        return ref

    def refs(self):
        return [r for _, r in self.ref_tips()]

    def ref_tips(self):
        out = g.try_run(["for-each-ref", "--format=%(objectname) %(refname)", "refs/logbook", REMOTE_NS, "refs/heads/logbook"], self.root)[1]
        return [tuple(l.split(" ", 1)) for l in out.splitlines() if " " in l and _REF_RE.search(l)]

    def load_shared(self):
        """Parsed shared entries, cached on disk keyed by every ref tip (a hook should not re-read every blob)."""
        tips = self.ref_tips()
        key = hashlib.sha1("\n".join(f"{o} {r}" for o, r in tips).encode()).hexdigest()
        cache = self.cdir / "shared-cache.json"
        try:
            c = json.loads(cache.read_text(encoding="utf-8"))
            if c.get("key") == key and c.get("v") == 1:
                return [Loaded(from_dict(d), "shared", u, dev, ref) for d, u, dev, ref in c["entries"]], {tuple(t) for t in c["tombs"]}
        except (OSError, ValueError, KeyError, TypeError):
            pass
        loaded, tombs = self._load_shared_uncached([r for _, r in tips])
        try:
            atomic_write(cache, json.dumps({"v": 1, "key": key, "entries": [[l.entry.to_dict(), l.user, l.device, l.ref] for l in loaded],
                                            "tombs": sorted(tombs)}))
        except OSError:
            pass
        return loaded, tombs

    def _load_shared_uncached(self, refs):
        loaded, tombs = [], set()
        for ref in refs:
            m = _REF_RE.search(ref)
            files = self._tree_files(ref)
            ents = {p: o for p, o in files.items() if p.startswith("entries/") and p.endswith(".json")}
            blobs = g.cat_blobs(self.root, list(ents.values())[:MAX_PER_REF])
            for path, oid in list(ents.items())[:MAX_PER_REF]:
                try:
                    e = from_json(blobs[oid].decode("utf-8"))
                except (KeyError, ValueError, UnicodeDecodeError):
                    continue
                if path != f"entries/{e.id}.json":
                    continue
                loaded.append(Loaded(e, "shared", m.group(1), m.group(2), ref))
            for path, oid in files.items():
                if path.startswith("tombstones/"):
                    tombs.add((m.group(1), path[len("tombstones/"):-len(".json")]))
        return loaded, tombs

    def unpublished(self):
        """Your private notes that are not on your shared ref yet. Auto-copied entries carry no reason, so they are not offered (or counted in the push reminder)."""
        shared, _ = self.load_shared()
        done = {l.entry.id for l in shared if l.user == self.user}
        return [e for e in self.load_private() if e.id not in done and e.provenance != "auto-copied"]

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
