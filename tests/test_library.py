"""The library (`library.sqlite`): a log is a saved conversation, a shelf is the notes taken from it (or one author's notes on git), and a note sits on a shelf."""
from __future__ import annotations

import sqlite3
import unittest

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from test_notesdb import DbBase  # noqa: E402
from getlogbook.entry import Entry  # noqa: E402


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
        self.assertTrue(db.load_log("18bcfe5917f-00000001").strip())
        db.add_private(committed)  # saving a note again keeps it on its shelf
        self.assertEqual(self.row(committed.id)[3], "18bcfe5917f-00000001")

    def test_a_note_cannot_sit_on_a_shelf_that_does_not_exist(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.r.db.add_private(self.entry("18bcfe5917f-00000004"), shelf="no-such-shelf")

    def test_a_shelf_with_no_conversation_has_a_log_that_says_so(self):
        self.r.db.add_log("18bcfe5917f-00000005", [], "main")
        self.r.db.add_shelf("18bcfe5917f-00000005", "main", "", "18bcfe5917f-00000005")
        self.assertEqual(self.r.db.load_log("18bcfe5917f-00000005").strip(), "")


if __name__ == "__main__":
    unittest.main()
