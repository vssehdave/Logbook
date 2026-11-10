"""The library (`library.sqlite`): a log is a saved conversation, a shelf is the notes taken from it (or one author's notes on git), and a note sits on a shelf."""
from __future__ import annotations

import json
import sqlite3
import unittest

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from test_notesdb import DbBase  # noqa: E402
from getlogbook.entry import Entry  # noqa: E402

OLD_SCHEMA = """
create table note(pk integer primary key autoincrement, id text not null, scope text not null, author text not null default '', device text not null default '',
  ref text not null default '', blob text not null default '', kind text, topic text, created text, branch text, sha text, provenance text,
  status_of text not null default '', published_ref text not null default '', json text not null, unique(scope, ref, id));
create table note_name(pk integer not null, name text not null, kind text not null);
create table note_path(pk integer not null, path text not null);
create table note_vec(pk integer primary key, model text not null, vec blob not null);
create table shelf(ref text primary key, tip text not null);
create table tomb(ref text not null, author text not null, id text not null);
create table supersedes(hidden text not null, author text not null, by_id text not null);
create table meta(k text primary key, v text);
create table convo(log_id text primary key, n integer not null, body text not null);
"""


class TestLibrary(DbBase):
    def entry(self, eid, **kw):
        return Entry(id=eid, topic=kw.pop("topic", "a note"), body={"summary": "s", "why": "w"}, provenance="worker-written", v=2, **kw)

    def row(self, eid):
        return self.r.db.con.execute("select kind, branch, sha, shelf_id from note where id=?", (eid,)).fetchone()

    def test_a_note_finds_its_log_through_its_shelf_and_takes_the_shelfs_branch_and_commit(self):
        db = self.r.db
        db.add_log("18bcfe5917f-00000001", ['{"role": "user", "text": "why?"}'], "feat/x", "2026-11-10T01:00:00")
        db.add_shelf("18bcfe5917f-00000001", "feat/x", "abc1234", "18bcfe5917f-00000001", "2026-11-10T01:00:00")
        committed = self.entry("18bcfe5917f-00000002", level="commit")
        pending = self.entry("18bcfe5917f-00000003", level="branch")  # work not committed yet: filed under the branch only
        for e in (committed, pending):
            db.add_private(e, shelf="18bcfe5917f-00000001")
        self.assertEqual(self.row(committed.id), ("finding", "feat/x", "abc1234", "18bcfe5917f-00000001"))
        self.assertEqual(self.row(pending.id), ("finding", "feat/x", "", "18bcfe5917f-00000001"))
        self.assertEqual(db.logs_of_notes(), {committed.id: "18bcfe5917f-00000001", pending.id: "18bcfe5917f-00000001"})
        self.assertTrue(db.has_log("18bcfe5917f-00000001"))
        db.add_private(committed)  # saving a note again keeps it on its shelf
        self.assertEqual(self.row(committed.id)[3], "18bcfe5917f-00000001")

    def test_a_note_cannot_sit_on_a_shelf_that_does_not_exist(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.r.db.add_private(self.entry("18bcfe5917f-00000004"), shelf="no-such-shelf")

    def test_a_shelf_with_no_conversation_has_a_log_that_says_so(self):
        self.r.db.add_log("18bcfe5917f-00000005", [], "main")
        self.r.db.add_shelf("18bcfe5917f-00000005", "main", "", "18bcfe5917f-00000005")
        self.assertFalse(self.r.db.has_log("18bcfe5917f-00000005"))
        self.assertEqual(self.r.db.load_log("18bcfe5917f-00000005").strip(), "")

    def test_a_file_from_before_the_library_is_renamed_and_every_log_and_shelf_is_made_from_it(self):
        if self.r.db._con:
            self.r.db._con.close()
        for f in self.r.cdir.glob("library.sqlite*"):
            f.unlink()
        old = self.r.cdir / "notes.sqlite"
        con = sqlite3.connect(str(old))
        con.executescript(OLD_SCHEMA)

        def put(e, kind, scope="private", ref="", branch="feat/old", sha=""):
            d = json.loads(e.to_json())
            d["kind"] = kind
            con.execute("insert into note(id, scope, author, ref, kind, topic, created, branch, sha, provenance, json) values (?,?,?,?,?,?,?,?,?,?,?)",
                        (e.id, scope, "me", ref, kind, e.topic, "2026-11-09T10:00:00", branch, sha, e.provenance, json.dumps(d)))

        log = self.entry("18bcfe5917f-0000000a", topic="a saved session")
        made = self.entry("18bcfe5917f-0000000b")
        made.sources = [log.id]
        theirs = self.entry("18bcfe5917f-0000000c")
        put(log, "log", sha="deadbee")
        put(made, "finding")
        put(theirs, "finding", scope="shared", ref="refs/logbook/log/bob/000000")
        con.execute("insert into shelf values ('refs/logbook/log/bob/000000', 'tip')")
        con.execute("insert into convo values (?,?,?)", (log.id, 2, '{"role": "user", "text": "q"}\n{"role": "assistant", "text": "a"}\n'))
        con.commit()
        con.close()
        self.r._db = None
        db = self.r.db
        db.con  # opening the file is what brings it forward
        self.assertFalse(old.exists(), "notes.sqlite is now library.sqlite")
        self.assertTrue((self.r.cdir / "library.sqlite").exists())
        self.assertEqual(self.row(log.id), ("savepoint", "feat/old", "deadbee", log.id), "the old log note is a savepoint note on its own shelf")
        self.assertEqual(self.row(made.id)[3], log.id, "the note taken at that savepoint joins the shelf its sources named")
        self.assertEqual(db.logs_of_notes()[made.id], log.id)
        self.assertEqual(db.con.execute("select n, branch from log where id=?", (log.id,)).fetchone(), (2, "feat/old"), "the conversation is a log, filed under the branch")
        self.assertEqual(db.con.execute("select branch, commit_id, scope from shelf where id=?", (log.id,)).fetchone(), ("feat/old", "deadbee", "private"))
        self.assertIsNone(db.con.execute("select 1 from note where id=?", (theirs.id,)).fetchone(), "the shared mirror is emptied: it is read from git again")
        self.assertIsNone(db.con.execute("select 1 from sqlite_master where name='convo'").fetchone())
        self.assertEqual(db.get_private(log.id).kind, "savepoint")


if __name__ == "__main__":
    unittest.main()
