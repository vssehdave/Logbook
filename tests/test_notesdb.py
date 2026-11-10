"""The local SQLite note store: private notes live in it, shared notes are a mirror of the git shelves, and a prompt asks it for candidates only."""
from __future__ import annotations

import json
import unittest
from unittest import mock

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from getlogbook import capture, recall, tree  # noqa: E402
from getlogbook import git as g  # noqa: E402
from getlogbook.entry import Entry, from_json  # noqa: E402
from getlogbook.store import Repo  # noqa: E402


class DbBase(T.Base):
    def setUp(self):
        super().setUp()
        self.d = T.make_repo(self.root, "r", "a@x.io")
        T.commit(self.d, "base", {"shop/revenue.py": "x = 1\n", "shop/other.py": "y = 1\n"})
        self.r = Repo(self.d)
        self.r.init()
        self.addCleanup(lambda: self.r.db._con and self.r.db._con.close())  # a test that reads `db.con` directly leaves it open; Windows cannot delete an open file

    def note(self, topic, path="shop/revenue.py", **kw):
        return capture.make_entry(self.r, "finding", topic, {"summary": f"{topic} summary", "why": "because the total is wrong"}, paths=[path], provenance="user-written", **kw)


class TestPrivateStore(DbBase):
    def test_a_note_comes_back_exactly_and_the_order_is_by_id(self):
        a, b = self.note("first"), self.note("second")
        self.assertEqual(self.r.get_private(a.id).to_json(), from_json(a.to_json()).to_json(), "what was stored, as a reader parses it")
        self.assertEqual([e.id for e in self.r.load_private()], sorted([a.id, b.id]))
        self.assertTrue(self.r.drop_private(a.id))
        self.assertFalse(self.r.drop_private(a.id))
        self.assertIsNone(self.r.get_private(a.id))

    def test_files_an_older_version_wrote_are_imported_once_and_set_aside(self):
        e = Entry(id="18bcfe5917f-873b8d63", topic="old note", body={"summary": "s", "why": "w"}, provenance="user-written", v=2)
        self.r.pdir.mkdir(parents=True, exist_ok=True)
        (self.r.pdir / f"{e.id}.json").write_text(e.to_json(), encoding="utf-8")
        fresh = Repo(self.d)  # a new process: nothing has opened the database yet
        self.assertEqual(fresh.get_private(e.id).topic, "old note")
        self.assertFalse((self.r.pdir / f"{e.id}.json").exists())
        self.assertTrue((self.r.cdir / "private.imported" / f"{e.id}.json").exists(), "nothing is deleted")
        self.assertEqual(len(Repo(self.d).load_private()), 1, "a second open does not import again")

    def test_no_connection_is_held_between_calls(self):
        self.note("x")
        self.assertIsNone(self.r.db._con)
        self.r.db.usable()
        self.assertIsNone(self.r.db._con)


class TestSharedMirror(DbBase):
    def publish(self, *entries):
        self.r.publish(list(entries))

    def test_a_shared_row_says_who_wrote_it_where_it_lives_and_which_git_blob_it_came_from(self):
        e = self.note("shared one")
        self.publish(e)
        (loaded,) = [l for l in self.r.load_shared()[0] if l.entry.id == e.id]
        self.assertEqual((loaded.scope, loaded.user, loaded.ref), ("shared", self.r.user, self.r.own_ref()))
        row = self.r.db.con.execute("select author, ref, blob, published_ref from note where scope='shared' and id=?", (e.id,)).fetchone()
        self.assertEqual(row[:2], (self.r.user, self.r.own_ref()))
        self.assertEqual(row[2], g.run(["rev-parse", f"{self.r.own_ref()}:entries/{e.id}.json"], self.r.root).strip(), "the blob id is git's own")
        self.assertEqual(self.r.db.con.execute("select published_ref from note where scope='private' and id=?", (e.id,)).fetchone()[0], self.r.own_ref())

    def test_a_refresh_reads_only_the_blobs_it_has_not_seen(self):
        a, b = self.note("a"), self.note("b")
        self.publish(a)
        self.r.load_shared()
        self.publish(b)
        with mock.patch.object(g, "cat_blobs", wraps=g.cat_blobs) as spy:
            ids = {l.entry.id for l in self.r.load_shared()[0]}
        self.assertEqual(ids, {a.id, b.id})
        self.assertEqual(len(spy.call_args[0][1]), 1, "only the new note was read from git")
        with mock.patch.object(g, "cat_blobs") as spy:
            self.r.load_shared()
        spy.assert_not_called()

    def test_the_mirror_can_be_dropped_and_rebuilt_from_git(self):
        e = self.note("kept")
        self.publish(e)
        before = [(l.entry.id, l.user, l.ref) for l in self.r.load_shared()[0]]
        self.r.db.drop_mirror()
        self.assertEqual(self.r.db.con.execute("select count(*) from note where scope='shared'").fetchone()[0], 0)
        self.r.db._con.close()
        self.r.db._con = None
        self.assertEqual([(l.entry.id, l.user, l.ref) for l in self.r.load_shared()[0]], before)

    def test_a_purged_note_is_hidden_and_a_note_a_shelf_lost_leaves_the_mirror(self):
        e, f = self.note("purge me"), self.note("keep me", "shop/other.py")
        self.publish(e, f)
        self.r.load_shared()
        self.r.purge(e.id)
        shared, tombs = self.r.load_shared()
        self.assertIn((self.r.user, e.id), tombs)
        self.assertEqual({a.id for a in self.r.db.candidates({"revenue"}, set(), set())}, set(), "a tombstoned shared note is not a candidate")


class TestCandidates(DbBase):
    def test_names_paths_and_words_find_notes_and_a_name_in_a_prompt_is_known_only_if_a_note_holds_it(self):
        rev, oth = self.note("refund rounding", "shop/revenue.py"), self.note("tax table", "shop/other.py")
        db = self.r.db
        self.assertEqual(db.names_in({"revenue", "nothing", "xyz"}), {"revenue"})
        self.assertEqual({l.entry.id for l in db.candidates(set(), {"shop/other.py"}, set())}, {oth.id})
        self.assertEqual({l.entry.id for l in db.candidates(set(), set(), {"refund"})}, {rev.id})
        self.assertEqual(db.candidates(set(), set(), {"zzzz"}), [])

    def test_a_note_its_own_author_superseded_is_hidden_and_a_status_record_comes_with_its_note(self):
        old = self.note("old claim")
        new = Entry(id="ffffffffff0-aaaaaaaa", topic="newer claim", body={"summary": "s", "why": "w"}, supersedes=[old.id], provenance="user-written", v=2,
                    anchor={"paths": ["shop/revenue.py"], "names": []})
        self.r.add_private(new)
        got = {l.entry.id for l in self.r.db.candidates(set(), {"shop/revenue.py"}, set())}
        self.assertEqual(got, {new.id})
        rec = Entry(id="ffffffffff1-bbbbbbbb", topic="status", body={"summary": "done"}, status={"of": new.id, "state": "resolved", "commits": []}, provenance="user-written", v=2)
        self.r.add_private(rec)
        got = {l.entry.id for l in self.r.db.candidates(set(), {"shop/revenue.py"}, set())}
        self.assertEqual(got, {new.id, rec.id})


class TestPromptPath(DbBase):
    def test_the_prompt_path_says_the_same_as_scanning_every_note(self):
        a = self.note("refund rounding")
        self.note("tax table", "shop/other.py")
        self.r.publish([a])
        prompt = "why does revenue round refunds like that"
        fast = recall.digest(self.r, "UserPromptSubmit", prompt=prompt, session="s1")
        with mock.patch("getlogbook.notesdb.NoteDB.usable", lambda self: False):
            slow = recall.digest(self.r, "UserPromptSubmit", prompt=prompt, session="s2")
        self.assertIn("refund rounding", fast)
        self.assertEqual(fast, slow)

    def test_a_prompt_with_nothing_to_match_stays_silent_without_building_any_view(self):
        self.note("refund rounding")
        with mock.patch.object(tree, "view", side_effect=AssertionError("no view should be built")):
            self.assertEqual(recall.digest(self.r, "UserPromptSubmit", prompt="please can you do that for me now", session="s"), "")


if __name__ == "__main__":
    unittest.main()
