"""The local SQLite store for notes (`.git/logbook/notes.sqlite`).

Two kinds of rows live in it, and they are not equal:
  * private notes (scope `private`) are STORED here; this file is their only copy. Older versions kept one JSON file per note in
    `.git/logbook/private/`; the first open imports those files and moves them to `.git/logbook/private.imported/`.
  * shared notes (scope `shared`) are a MIRROR of the git refs `refs/logbook/log/<author>/000000` (and what a fetch brought in). Git stays
    the authority: every shared row carries its ref and the git blob it was read from, `refresh_shared()` brings the mirror up to date from the
    ref tips (only blobs it has not seen are read), and the whole mirror can be dropped and rebuilt from git at any time. Publishing still writes
    git objects (store.Repo.publish) from the stored note; the row is not trusted to be the source of what is shared.

Why: reading every note on every prompt (one file per private note, every shared blob parsed, a view built for each) cost about 1 s at 1,000
notes and grows linearly (bench/retrieval.py). Here a prompt asks the index for the few notes it could be about and builds views for those only.
Full-text search needs FTS5 (in nearly every Python build); without it `usable()` is False and callers scan everything, as before.
Nothing here keeps a note from being read back with its author, ref, blob, commit, time and checks exactly as stored.
"""
from __future__ import annotations

import contextlib
import functools
import shutil
import sqlite3

from . import git as g
from .entry import from_json

SCHEMA = """
create table if not exists note(
  pk integer primary key autoincrement, id text not null, scope text not null, author text not null default '', device text not null default '',
  ref text not null default '', blob text not null default '', kind text, topic text, created text, branch text, sha text,
  provenance text, status_of text not null default '', published_ref text not null default '', json text not null,
  unique(scope, ref, id));
create index if not exists note_id on note(id);
create index if not exists note_status_of on note(status_of) where status_of != '';
create table if not exists note_name(pk integer not null, name text not null, kind text not null);
create index if not exists note_name_name on note_name(name);
create index if not exists note_name_pk on note_name(pk);
create table if not exists note_path(pk integer not null, path text not null);
create index if not exists note_path_path on note_path(path);
create index if not exists note_path_pk on note_path(pk);
create table if not exists shelf(ref text primary key, tip text not null);
create table if not exists tomb(ref text not null, author text not null, id text not null);
create index if not exists tomb_ref on tomb(ref);
create table if not exists supersedes(hidden text not null, author text not null, by_id text not null);
create index if not exists supersedes_hidden on supersedes(hidden);
create table if not exists meta(k text primary key, v text);
"""
FTS = "create virtual table if not exists note_fts using fts5(topic, body, paths, names, tokenize=\"unicode61 tokenchars '_'\")"
CANDIDATES = 200  # the most full-text hits taken for one prompt before the usual ranking runs over them
CHUNK = 400


def _marks(n):
    return ",".join("?" * n)


def _closing(f):
    """A public method opens the database if it is not open and closes it when the outermost one returns: no connection is held between
    calls, so nothing keeps the file open (Windows cannot delete an open file) and a long-lived process never holds a lock."""
    @functools.wraps(f)
    def run(self, *a, **k):
        self._depth += 1
        try:
            return f(self, *a, **k)
        finally:
            self._depth -= 1
            if self._depth == 0 and self._con is not None:
                self._con.close()
                self._con = None
    return run


class NoteDB:
    def __init__(self, repo):
        self.repo = repo
        self.path = repo.cdir / "notes.sqlite"
        self._con, self._depth, self._ready, self.fts = None, 0, False, None

    @property
    def con(self):
        if self._con is None:
            self.repo.cdir.mkdir(parents=True, exist_ok=True)
            self._con = sqlite3.connect(str(self.path), timeout=15, isolation_level=None)
            self._con.execute("pragma busy_timeout=15000")
            if not self._ready:
                self._ready = True
                self._con.execute("pragma journal_mode=wal")
                self._con.executescript(SCHEMA)
                try:
                    self._con.execute(FTS)
                    self.fts = True
                except sqlite3.OperationalError:  # this Python's SQLite has no FTS5
                    self.fts = False
                self._import_private()
        return self._con

    @_closing
    def usable(self):
        if self.fts is None:
            self.con
        return self.fts

    @contextlib.contextmanager
    def _tx(self):
        self.con.execute("begin immediate")
        try:
            yield
        except BaseException:
            self.con.execute("rollback")
            raise
        self.con.execute("commit")

    def _meta(self, k):
        r = self.con.execute("select v from meta where k=?", (k,)).fetchone()
        return r[0] if r else None

    # rows ----------------------------------------------------------------------------------------------------------------------
    def _del(self, scope, ref, eid):
        r = self.con.execute("select pk, author from note where scope=? and ref=? and id=?", (scope, ref, eid)).fetchone()
        if not r:
            return False
        pk = r[0]
        if self.fts:
            self.con.execute("delete from note_fts where rowid=?", (pk,))
        for t in ("note_name", "note_path"):
            self.con.execute(f"delete from {t} where pk=?", (pk,))
        self.con.execute("delete from supersedes where by_id=? and author=?", (eid, r[1]))
        self.con.execute("delete from note where pk=?", (pk,))
        return True

    def _put(self, e, scope, author, device="", ref="", blob=""):
        from . import tree
        self._del(scope, ref, e.id)
        a = e.anchor
        paths = [p.replace("\\", "/") for p in a.get("paths", [])]
        cur = self.con.execute(
            "insert into note(id, scope, author, device, ref, blob, kind, topic, created, branch, sha, provenance, status_of, json) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (e.id, scope, author, device, ref, blob, e.kind, e.topic, e.created, a.get("branch", ""), a.get("sha", ""), e.provenance,
             (e.status or {}).get("of", ""), e.to_json()))
        pk = cur.lastrowid
        names = {n.lower() for n in a.get("names", [])}
        stems = {n.lower() for n in tree.names_of(paths)}
        self.con.executemany("insert into note_name(pk, name, kind) values (?,?,?)", [(pk, n, "n") for n in names] + [(pk, n, "s") for n in stems - names])
        self.con.executemany("insert into note_path(pk, path) values (?,?)", [(pk, p) for p in paths])
        self.con.executemany("insert into supersedes(hidden, author, by_id) values (?,?,?)", [(s, author, e.id) for s in e.supersedes])
        if self.fts:
            self.con.execute("insert into note_fts(rowid, topic, body, paths, names) values (?,?,?,?,?)",
                             (pk, e.topic, " ".join([*e.body.values(), a.get("subject", "")]), " ".join(paths), " ".join(sorted(names | stems))))
        return pk

    # private notes: stored here -----------------------------------------------------------------------------------------------
    @_closing
    def add_private(self, e):
        with self._tx():
            self._put(e, "private", self.repo.user, self.repo.device)

    @_closing
    def get_private(self, eid):
        r = self.con.execute("select json from note where scope='private' and id=?", (eid,)).fetchone()
        try:
            return from_json(r[0]) if r else None
        except ValueError:
            return None

    @_closing
    def drop_private(self, eid):
        with self._tx():
            return self._del("private", "", eid)

    @_closing
    def load_private(self):
        out = []
        for (js,) in self.con.execute("select json from note where scope='private' order by id"):
            try:
                out.append(from_json(js))
            except ValueError:
                continue
        return out

    def _import_private(self):
        """One time: the JSON files an older version kept become rows, and the folder is set aside (not deleted)."""
        if self._meta("private_imported"):
            return
        pdir = self.repo.cdir / "private"
        files = sorted(pdir.glob("*.json")) if pdir.exists() else []
        with self._tx():
            if self._meta("private_imported"):
                return
            for p in files:
                try:
                    e = from_json(p.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                self._put(e, "private", self.repo.user, self.repo.device)
            self.con.execute("insert or replace into meta values('private_imported', ?)", (str(len(files)),))
        if files:
            dest = self.repo.cdir / "private.imported"
            dest.mkdir(exist_ok=True)
            for p in files:
                try:
                    shutil.move(str(p), str(dest / p.name))
                except OSError:
                    pass

    @_closing
    def mark_published(self, ids, ref):
        with self._tx():
            self.con.executemany("update note set published_ref=? where scope='private' and id=?", [(ref, i) for i in ids])

    # shared notes: a mirror of the git refs --------------------------------------------------------------------------------------
    @_closing
    def refresh_shared(self):
        """Bring the mirror up to date with the shelves in git. Cheap when nothing moved (one `for-each-ref`); otherwise only the blobs
        not seen before are read. Returns True when anything changed."""
        from .store import _REF_RE, MAX_PER_REF
        repo = self.repo
        tips = {r: o for o, r in repo.ref_tips()}
        have = dict(self.con.execute("select ref, tip from shelf"))
        if tips == have:
            return False
        with self._tx():
            for ref in set(have) - set(tips):
                self._drop_shelf(ref)
            for ref, tip in tips.items():
                if have.get(ref) == tip:
                    continue
                m = _REF_RE.search(ref)
                if not m:
                    continue
                files = repo._tree_files(ref)
                ents = dict(list({p: o for p, o in files.items() if p.startswith("entries/") and p.endswith(".json")}.items())[:MAX_PER_REF])
                known = {b: i for b, i in self.con.execute("select blob, id from note where scope='shared' and ref=?", (ref,))}
                on_shelf = set(ents.values())
                for blob, eid in known.items():
                    if blob not in on_shelf:
                        self._del("shared", ref, eid)
                new = [o for o in ents.values() if o not in known]
                blobs = g.cat_blobs(repo.root, new)
                for path, oid in ents.items():
                    if oid in known:
                        continue
                    try:
                        e = from_json(blobs[oid].decode("utf-8"))
                    except (KeyError, ValueError, UnicodeDecodeError):
                        continue
                    if path != f"entries/{e.id}.json":
                        continue
                    self._put(e, "shared", m.group(1), m.group(2), ref, oid)
                self.con.execute("delete from tomb where ref=?", (ref,))
                self.con.executemany("insert into tomb(ref, author, id) values (?,?,?)",
                                     [(ref, m.group(1), p[len("tombstones/"):-len(".json")]) for p in files if p.startswith("tombstones/")])
                self.con.execute("insert or replace into shelf values (?,?)", (ref, tip))
        return True

    @_closing
    def drop_mirror(self):
        """Forget every shared note held here; the next `refresh_shared()` reads the shelves from git again. Private notes are not touched."""
        with self._tx():
            for ref in [r for (r,) in self.con.execute("select ref from shelf").fetchall()] + [r for (r,) in self.con.execute("select distinct ref from note where scope='shared'").fetchall()]:
                self._drop_shelf(ref)

    def _drop_shelf(self, ref):
        for (eid,) in self.con.execute("select id from note where scope='shared' and ref=?", (ref,)).fetchall():
            self._del("shared", ref, eid)
        self.con.execute("delete from tomb where ref=?", (ref,))
        self.con.execute("delete from shelf where ref=?", (ref,))

    @_closing
    def shared(self):
        """(Loaded for every shared note, {(author, id)} tombstones), read from the mirror after bringing it up to date."""
        from .store import Loaded
        self.refresh_shared()
        out = []
        for js, author, device, ref in self.con.execute("select json, author, device, ref from note where scope='shared' order by ref, id"):
            try:
                out.append(Loaded(from_json(js), "shared", author, device, ref))
            except ValueError:
                continue
        return out, {(a, i) for a, i in self.con.execute("select author, id from tomb")}

    # the prompt path: only the notes a prompt could be about ------------------------------------------------------------------------
    @_closing
    def names_in(self, tokens):
        """Names held by notes (a name given on a note, or a file stem from its paths; at least 4 letters) that the prompt mentions."""
        toks = sorted(t for t in tokens if len(t) >= 4)[:300]
        if not toks:
            return set()
        return {r[0] for r in self.con.execute(f"select distinct name from note_name where name in ({_marks(len(toks))})", toks)}

    @_closing
    def candidates(self, names, paths, tokens, limit=CANDIDATES):
        """The notes that name one of `names`, sit on one of `paths`, or match the `tokens` in full text (best `limit` of those), as Loaded,
        shared before private, hidden ones left out (purged by tombstone, or superseded by a note of the same author), with the status
        records that are about them."""
        pks = set()
        names, paths = sorted(names), sorted(paths)
        for i in range(0, len(names), CHUNK):
            part = names[i:i + CHUNK]
            pks |= {r[0] for r in self.con.execute(f"select pk from note_name where kind='n' and name in ({_marks(len(part))})", part)}
        for i in range(0, len(paths), CHUNK):
            part = paths[i:i + CHUNK]
            pks |= {r[0] for r in self.con.execute(f"select pk from note_path where path in ({_marks(len(part))})", part)}
        if tokens and self.fts:
            match = " OR ".join(f'"{t}"' for t in sorted(tokens)[:60])
            pks |= {r[0] for r in self.con.execute("select rowid from note_fts where note_fts match ? order by bm25(note_fts) limit ?", (match, limit))}
        rows = self._rows(sorted(pks))
        ids = sorted({r[1] for r in rows})
        for i in range(0, len(ids), CHUNK):
            part = ids[i:i + CHUNK]
            rows += [r for r in self.con.execute(self._SELECT + f" where status_of in ({_marks(len(part))})" + self._VISIBLE, part)]
        return self._loaded(rows)

    _SELECT = "select pk, id, scope, author, device, ref, json from note"
    _VISIBLE = (" and (scope != 'shared' or not exists(select 1 from tomb t where t.author=note.author and t.id=note.id))"
                " and not exists(select 1 from supersedes s where s.hidden=note.id and s.author=note.author)")

    def _rows(self, pks):
        out = []
        for i in range(0, len(pks), CHUNK):
            part = pks[i:i + CHUNK]
            out += self.con.execute(self._SELECT + f" where pk in ({_marks(len(part))})" + self._VISIBLE, part).fetchall()
        return out

    def _loaded(self, rows):
        from .store import Loaded
        seen, out = set(), []
        for pk, eid, scope, author, device, ref, js in sorted(rows, key=lambda r: (r[2] != "shared", r[5], r[1])):
            if eid in seen:
                continue
            seen.add(eid)
            try:
                out.append(Loaded(from_json(js), scope, author, device, ref))
            except ValueError:
                continue
        return out
