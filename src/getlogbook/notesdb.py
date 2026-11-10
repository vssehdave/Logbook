"""The library: one SQLite file (`.git/logbook/library.sqlite`) that holds everything Logbook knows on this machine, private and shared.

  * a LOG is a saved conversation: what was typed and answered up to a savepoint, with the branch it was on. It never leaves this machine.
  * a SHELF is a collection of notes. A private shelf is what the note-taker extracted from one log (it carries the branch, the commit that triggered it,
    and the log). On the shared side every author's ref in git is one shelf (it has no log here); together they make the one big shelf of a team.
  * a NOTE sits on a shelf, so its log is found through the shelf, and it gets the shelf's branch and commit when its own anchor has none.
    Private notes are STORED here (this file is their only copy); shared notes are a MIRROR of git, which stays the authority: every shared row carries its
    ref and the git blob it was read from, `refresh_shared()` brings the mirror up to date from the ref tips (only blobs it has not seen are read), and the
    mirror can be dropped and rebuilt from git at any time. Publishing still writes git objects (store.Repo.publish) from the stored note.
  * a CHAT is one agent conversation in this repo, and its citations are its page: `cite` rows number the notes the agent was shown (the superscript it writes after a
    claim), kept for the whole chat. A chat is `open` while it is going and `archived` when its session ends; a resumed chat opens again.
  * vectors for search by meaning (`note_vec`) are derived from the notes, never published, and rebuilt on demand (embed.py).
  * the raw queue of tool uses an observer reads (`.git/logbook/running/`) and archived notes stay plain files.

Why: reading every note on every prompt cost about 1 s at 1,000 notes and grows linearly (bench/retrieval.py). Here a prompt asks the index for the few notes it
could be about and builds views for those only. Full-text search needs FTS5 (in nearly every Python build); without it `usable()` is False and callers scan
everything, as before. Nothing here keeps a note from being read back with its author, ref, blob, commit, time and checks exactly as stored.
"""
from __future__ import annotations

import contextlib
import functools
import sqlite3
import time

from . import git as g
from .entry import from_json

SCHEMA = """
create table if not exists note(
  pk integer primary key autoincrement, id text not null, scope text not null, author text not null default '', device text not null default '',
  ref text not null default '', blob text not null default '', kind text, topic text, created text, branch text, sha text,
  provenance text, status_of text not null default '', published_ref text not null default '', shelf_id text references shelf(id), json text not null,
  unique(scope, ref, id));
create index if not exists note_id on note(id);
create index if not exists note_shelf on note(shelf_id);
create index if not exists note_status_of on note(status_of) where status_of != '';
create table if not exists note_name(pk integer not null, name text not null, kind text not null);
create index if not exists note_name_name on note_name(name);
create index if not exists note_name_pk on note_name(pk);
create table if not exists note_path(pk integer not null, path text not null);
create index if not exists note_path_path on note_path(path);
create index if not exists note_path_pk on note_path(pk);
create table if not exists log(
  id text primary key, branch text not null default '', created text not null default '', n integer not null default 0, body text not null default '');
create table if not exists shelf(
  id text primary key, scope text not null, author text not null default '', ref text not null default '', tip text not null default '',
  branch text not null default '', commit_id text not null default '', created text not null default '', log_id text references log(id));
create table if not exists tomb(ref text not null, author text not null, id text not null);
create index if not exists tomb_ref on tomb(ref);
create table if not exists supersedes(hidden text not null, author text not null, by_id text not null);
create index if not exists supersedes_hidden on supersedes(hidden);
create table if not exists chat(
  id text primary key, branch text not null default '', status text not null default 'open', started text not null default '', updated text not null default '',
  seq integer not null default 0);  -- seq goes up each time a chat is touched, so "the latest chat" never depends on clock resolution
create table if not exists cite(
  chat_id text not null references chat(id), n integer not null, note_id text not null, shown text not null default '',
  primary key (chat_id, n), unique (chat_id, note_id));
create table if not exists note_vec(pk integer primary key, model text not null, vec blob not null);
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
        self.path = repo.cdir / "library.sqlite"
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
                self._con.execute("pragma foreign_keys=on")
                try:
                    self._con.execute(FTS)
                    self.fts = True
                except sqlite3.OperationalError:  # this Python's SQLite has no FTS5
                    self.fts = False
            else:
                self._con.execute("pragma foreign_keys=on")
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

    # rows ----------------------------------------------------------------------------------------------------------------------
    def _del(self, scope, ref, eid):
        r = self.con.execute("select pk, author from note where scope=? and ref=? and id=?", (scope, ref, eid)).fetchone()
        if not r:
            return False
        pk = r[0]
        if self.fts:
            self.con.execute("delete from note_fts where rowid=?", (pk,))
        for t in ("note_name", "note_path", "note_vec"):
            self.con.execute(f"delete from {t} where pk=?", (pk,))
        self.con.execute("delete from supersedes where by_id=? and author=?", (eid, r[1]))
        self.con.execute("delete from note where pk=?", (pk,))
        return True

    def _put(self, e, scope, author, device="", ref="", blob="", shelf=None):
        from . import tree
        if shelf is None:  # saving a note again keeps it on its shelf
            old = self.con.execute("select shelf_id from note where scope=? and ref=? and id=?", (scope, ref, e.id)).fetchone()
            shelf = old[0] if old else None
        self._del(scope, ref, e.id)
        a = e.anchor
        sb = self.con.execute("select branch, commit_id from shelf where id=?", (shelf,)).fetchone() if shelf else None
        branch = a.get("branch") or (sb[0] if sb else "")
        sha = a.get("sha") or (sb[1] if sb and e.level != "branch" else "")  # a note filed under its branch (work not committed yet) keeps no commit
        paths = [p.replace("\\", "/") for p in a.get("paths", [])]
        cur = self.con.execute(
            "insert into note(id, scope, author, device, ref, blob, kind, topic, created, branch, sha, provenance, status_of, shelf_id, json) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (e.id, scope, author, device, ref, blob, e.kind, e.topic, e.created, branch, sha, e.provenance,
             (e.status or {}).get("of", ""), shelf, e.to_json()))
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
    def add_private(self, e, shelf=None):
        with self._tx():
            self._put(e, "private", self.repo.user, self.repo.device, shelf=shelf)

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
        have = dict(self.con.execute("select ref, tip from shelf where scope='shared'"))
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
                self.con.execute("insert into shelf(id, scope, author, ref, tip) values (?,?,?,?,?) on conflict(id) do update set tip=excluded.tip",
                                 (ref, "shared", m.group(1), ref, tip))
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
                    self._put(e, "shared", m.group(1), m.group(2), ref, oid, shelf=ref)
                self.con.execute("delete from tomb where ref=?", (ref,))
                self.con.executemany("insert into tomb(ref, author, id) values (?,?,?)",
                                     [(ref, m.group(1), p[len("tombstones/"):-len(".json")]) for p in files if p.startswith("tombstones/")])
        return True

    @_closing
    def drop_mirror(self):
        """Forget every shared note held here; the next `refresh_shared()` reads the shelves from git again. Private notes are not touched."""
        with self._tx():
            for ref in [r for (r,) in self.con.execute("select id from shelf where scope='shared'").fetchall()] + [r for (r,) in self.con.execute("select distinct ref from note where scope='shared'").fetchall()]:
                self._drop_shelf(ref)

    def _drop_shelf(self, ref):
        for (eid,) in self.con.execute("select id from note where scope='shared' and ref=?", (ref,)).fetchall():
            self._del("shared", ref, eid)
        self.con.execute("delete from tomb where ref=?", (ref,))
        self.con.execute("delete from shelf where id=? and scope='shared'", (ref,))

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
        """The visible rows for these pks, plus any other row holding the same note id (a note you published is in your private rows and on the shelf; the shelf copy wins)."""
        out = []
        for i in range(0, len(pks), CHUNK):
            part = pks[i:i + CHUNK]
            out += self.con.execute(self._SELECT + f" where pk in ({_marks(len(part))})" + self._VISIBLE, part).fetchall()
        have = {r[0] for r in out}
        ids = sorted({r[1] for r in out})
        for i in range(0, len(ids), CHUNK):
            part = ids[i:i + CHUNK]
            out += [r for r in self.con.execute(self._SELECT + f" where id in ({_marks(len(part))})" + self._VISIBLE, part) if r[0] not in have]
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

    # logs and shelves: the conversation behind a savepoint and the notes taken from it (private to this machine) ---------------------------------
    @_closing
    def add_log(self, log_id, lines, branch="", created=""):
        with self._tx():
            self.con.execute("insert into log(id, branch, created, n, body) values (?,?,?,?,?) on conflict(id) do update set n=excluded.n, body=excluded.body",
                             (log_id, branch, created, len(lines), "\n".join(lines) + "\n"))

    @_closing
    def add_shelf(self, shelf_id, branch="", commit_id="", log_id=None, created=""):
        """A private shelf: the notes taken from one log, filed under the branch and (when a commit triggered it) the commit."""
        with self._tx():
            self.con.execute("insert into shelf(id, scope, author, branch, commit_id, created, log_id) values (?,?,?,?,?,?,?) "
                             "on conflict(id) do update set branch=excluded.branch, commit_id=excluded.commit_id, log_id=excluded.log_id",
                             (shelf_id, "private", self.repo.user, branch, commit_id, created, log_id))

    @_closing
    def load_log(self, log_id):
        r = self.con.execute("select body from log where id=?", (log_id,)).fetchone()
        return r[0] if r else ""

    @_closing
    def logs_of_notes(self):
        """{note id: log id} for your own notes that were taken from a log kept here: the log is found through the note's shelf."""
        return dict(self.con.execute("select n.id, s.log_id from note n join shelf s on s.id=n.shelf_id where n.scope='private' and s.log_id is not null"))

    # chats and their citations: the numbered notes behind an answer ----------------------------------------------------------------------------
    @_closing
    def cite_items(self, chat_id):
        """{note id: number} for this chat."""
        return {i: n for i, n in self.con.execute("select note_id, n from cite where chat_id=?", (chat_id,))}

    @_closing
    def cite_peek(self, chat_id, note_id):
        """The number a note has in this chat, or the one it would get, without recording anything."""
        r = self.con.execute("select n from cite where chat_id=? and note_id=?", (chat_id, note_id)).fetchone()
        return r[0] if r else self.con.execute("select coalesce(max(n), 0) + 1 from cite where chat_id=?", (chat_id,)).fetchone()[0]

    @_closing
    def cite_number(self, chat_id, note_id, branch=""):
        """The number of a note in this chat, giving it the next one the first time it is shown. Opens the chat (again, when it was archived)."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._tx():
            self.con.execute("insert into chat(id, branch, status, started, updated, seq) values (?,?,?,?,?, (select coalesce(max(seq), 0) + 1 from chat)) "
                             "on conflict(id) do update set status='open', updated=excluded.updated, seq=excluded.seq", (chat_id, branch, "open", now, now))
            r = self.con.execute("select n from cite where chat_id=? and note_id=?", (chat_id, note_id)).fetchone()
            if r:
                return r[0]
            n = self.con.execute("select coalesce(max(n), 0) + 1 from cite where chat_id=?", (chat_id,)).fetchone()[0]
            self.con.execute("insert into cite(chat_id, n, note_id, shown) values (?,?,?,?)", (chat_id, n, note_id, now))
            return n

    @_closing
    def latest_chat(self):
        r = self.con.execute("select id from chat order by seq desc limit 1").fetchone()
        return r[0] if r else ""

    @_closing
    def archive_stale_chats(self, days=20):
        """Archive the citations page of every chat that has not cited anything for `days` days. The page is kept; citing in that chat again reopens it. Returns how many."""
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days * 86400))
        with self._tx():
            return self.con.execute("update chat set status='archived' where status='open' and updated < ?", (cutoff,)).rowcount

    # vectors: search by meaning ---------------------------------------------------------------------------------------------------
    @_closing
    def vector_count(self, model):
        return self.con.execute("select count(*) from note_vec where model=?", (model,)).fetchone()[0]

    @_closing
    def index_vectors(self, embedder, limit=0, batch=128):
        """Embed the notes that have no vector from this model yet (status records are about another note and are skipped). Returns how many were embedded."""
        from .embed import note_text
        from .entry import from_json as parse
        done = 0
        while not limit or done < limit:
            n = batch if not limit else min(batch, limit - done)
            rows = self.con.execute("select n.pk, n.json from note n left join note_vec v on v.pk=n.pk and v.model=? where v.pk is null and n.status_of='' and not (n.scope='private' and exists(select 1 from note s where s.id=n.id and s.scope='shared')) limit ?",
                                    (embedder.name, n)).fetchall()
            if not rows:
                break
            texts = []
            for _, js in rows:
                try:
                    texts.append(note_text(parse(js)) or " ")
                except ValueError:
                    texts.append(" ")
            vecs = embedder.encode(texts)
            with self._tx():
                self.con.executemany("insert or replace into note_vec(pk, model, vec) values (?,?,?)", [(pk, embedder.name, v) for (pk, _), v in zip(rows, vecs)])
            done += len(rows)
        return done

    @_closing
    def vector_search(self, embedder, query, k=100):
        """[(Loaded, similarity)] for the notes whose meaning is closest to the query, best first; hidden notes (purged, superseded) are left out.
        Uses numpy when it is installed (the semantic extra brings it); without it the scan is plain Python and only suits a few thousand notes."""
        q = embedder.encode([query])[0]
        sims = dict(self._top(q, embedder.name, k * 3))
        rows = self._rows(sorted(sims))
        by_id, score = {}, {}
        for r in rows:
            by_id.setdefault(r[1], []).append(r)
            if r[0] in sims:
                score[r[1]] = max(score.get(r[1], -1.0), sims[r[0]])
        out = []
        for eid in sorted(score, key=lambda i: -score[i]):
            out += [(loaded, score[eid]) for loaded in self._loaded(by_id[eid])[:1]]
        return out[:k]

    def _top(self, q, model, k, chunk=20000):
        try:
            import numpy as np
        except ImportError:
            np = None
        qa = np.frombuffer(q, dtype="float32") if np else None
        if not np:
            from array import array
            qa = array("f")
            qa.frombytes(q)
        heap, last = [], 0
        while True:
            rows = self.con.execute("select pk, vec from note_vec where model=? and pk>? order by pk limit ?", (model, last, chunk)).fetchall()
            if not rows:
                break
            last = rows[-1][0]
            if np:
                m = np.frombuffer(b"".join(r[1] for r in rows), dtype="float32").reshape(len(rows), -1)
                s = m @ qa
                top = np.argpartition(-s, min(k, len(rows) - 1))[:k] if len(rows) > k else range(len(rows))
                heap += [(rows[i][0], float(s[i])) for i in top]
            else:
                from array import array
                for pk, blob in rows:
                    v = array("f")
                    v.frombytes(blob)
                    heap.append((pk, sum(x * y for x, y in zip(v, qa))))
            heap = sorted(heap, key=lambda x: -x[1])[:k]
        return heap

    @_closing
    def drop_vectors(self, model=None):
        with self._tx():
            if model:
                self.con.execute("delete from note_vec where model=?", (model,))
            else:
                self.con.execute("delete from note_vec")

    @_closing
    def provenance(self, ids):
        """{note id: {scope, author, ref, blob, tip, published_ref}} for the row a search would show (shared before private): where it is held and, for a shared
        note, the git blob and shelf tip it was read from."""
        out = {}
        for i in range(0, len(ids), CHUNK):
            part = list(ids[i:i + CHUNK])
            q = ("select n.id, n.scope, n.author, n.ref, n.blob, case when n.scope='shared' then coalesce(s.tip, '') else '' end, n.published_ref from note n left join shelf s on s.id=n.shelf_id "
                 f"where n.id in ({_marks(len(part))}) order by n.scope != 'shared', n.ref")
            for eid, scope, author, ref, blob, tip, pub in self.con.execute(q, part):
                out.setdefault(eid, {"scope": scope, "author": author, "ref": ref, "blob": blob, "tip": tip, "published_ref": pub})
        return out

    @_closing
    def vector_missing(self, model):
        """How many notes have no vector from this model yet."""
        return self.con.execute("select count(*) from note n left join note_vec v on v.pk=n.pk and v.model=? where v.pk is null and n.status_of='' and not (n.scope='private' and exists(select 1 from note s where s.id=n.id and s.scope='shared'))", (model,)).fetchone()[0]

