"""Search by meaning (vectors in the local database) and the conversations stored beside the logs. A stand-in model is used, so no download is needed."""
from __future__ import annotations

import json
import os
from array import array
import unittest
from unittest import mock

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from test_notesdb import DbBase  # noqa: E402
from getlogbook import embed, recall  # noqa: E402
from getlogbook.entry import Entry  # noqa: E402
from getlogbook.store import Repo  # noqa: E402

GROUPS = [{"cent", "rounding", "refund", "total", "totals", "money", "price"}, {"login", "logout", "session", "token", "expiry", "authentication"},
          {"stall", "hang", "slow", "chunk", "csv", "export"}]


def pack(values):
    """Floats to the packed unit-length form the library stores."""
    norm = sum(v * v for v in values) ** 0.5 or 1.0
    return array("f", [v / norm for v in values]).tobytes()


def fake_encode(texts):
    """A stand-in for a real model: a word counts toward the topic group it belongs to, so two texts about the same thing are close without sharing a word."""
    out = []
    for text in texts:
        v = [0.0] * (len(GROUPS) + 1)
        for w in text.lower().replace(",", " ").split():
            hit = [i for i, g in enumerate(GROUPS) if w in g]
            v[hit[0] if hit else len(GROUPS)] += 1.0 if hit else 0.05
        out.append(pack(v))
    return out


EMB = embed.Embedder("fake-v1", fake_encode)


class TestMeaning(DbBase):
    def setUp(self):
        super().setUp()
        self.money = self.note("refund rounding drops a cent")
        self.auth = self.note("session token expiry after logout", "shop/other.py")
        self.r.publish([self.money])

    def test_the_tidy_pass_embeds_the_notes_that_have_no_vector_yet(self):
        self.assertEqual(self.r.db.vector_count(EMB.name), 0)
        env = {k: v for k, v in os.environ.items() if k != "LOGBOOK_OFFLINE"}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(embed, "load", lambda cfg: EMB):
            self.run_cli("tidy", "--work", "--quiet", "--no-sync")
        self.assertEqual(self.r.db.vector_missing(EMB.name), 0)
        self.assertGreaterEqual(self.r.db.vector_count(EMB.name), 2, "both notes have a vector without anyone running a command for it")
        self.r.db.con.execute("delete from note_vec")
        self.run_cli("tidy", "--work", "--quiet", "--no-sync")  # offline (the tests' default): nothing is embedded, nothing fails
        self.assertEqual(self.r.db.vector_count(EMB.name), 0)
        self.run_cli("config", "semantic", "off")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(embed, "load", lambda cfg: EMB):
            self.run_cli("tidy", "--work", "--quiet", "--no-sync")
        self.assertEqual(self.r.db.vector_count(EMB.name), 0, "and not when search by meaning is off")

    def test_notes_are_embedded_once_and_a_status_record_is_skipped(self):
        rec = Entry(id="ffffffffff1-bbbbbbbb", topic="status", body={"summary": "done"}, status={"of": self.auth.id, "state": "resolved", "commits": []},
                    provenance="user-written", v=2)
        self.r.add_private(rec)
        n = self.r.db.index_vectors(EMB)
        self.assertEqual(n, self.r.db.vector_count(EMB.name))
        self.assertGreaterEqual(n, 2)
        self.assertEqual(self.r.db.index_vectors(EMB), 0, "nothing is embedded twice")
        self.assertEqual(self.r.db.vector_missing(EMB.name), 0)
        self.assertEqual(self.r.db.con.execute("select count(*) from note_vec v join note n on n.pk=v.pk where n.status_of != ''").fetchone()[0], 0)

    def test_the_vectors_find_a_note_that_shares_no_word_with_the_question(self):
        self.r.db.index_vectors(EMB)
        question = "why do totals lose money"
        self.assertEqual(self.r.db.candidates(set(), set(), recall.tokens(question) - recall._STOP), [], "no word in common: full text finds nothing")
        hits = recall.hybrid(self.r, question, EMB, 5)
        self.assertEqual([v["id"] for _, v, _, _ in hits][:1], [self.money.id])
        self.assertEqual(hits[0][2], ["meaning"])

    def test_a_hit_keeps_its_author_ref_blob_and_is_checked_against_git(self):
        self.r.db.index_vectors(EMB)
        (score, v, how, sim), = [h for h in recall.hybrid(self.r, "totals money", EMB, 5) if h[1]["id"] == self.money.id]
        self.assertEqual((v["scope"], v["author"], v["trusted"]), ("shared", "you", True))
        prov = self.r.db.provenance([self.money.id])[self.money.id]
        self.assertEqual((prov["scope"], prov["author"], prov["ref"]), ("shared", self.r.user, self.r.own_ref()))
        self.assertEqual(recall.verify(self.r, {self.money.id: prov}), {self.money.id: True})
        self.assertEqual(recall.verify(self.r, {self.money.id: dict(prov, tip="0" * 40)}), {self.money.id: False}, "a stale index is caught, not trusted")
        self.assertEqual(recall.verify(self.r, {self.auth.id: self.r.db.provenance([self.auth.id])[self.auth.id]}), {self.auth.id: None}, "a private note is not in git")

    def test_a_vector_goes_with_its_note_and_a_purged_note_is_never_returned(self):
        self.r.db.index_vectors(EMB)
        before = self.r.db.vector_count(EMB.name)
        self.assertTrue(self.r.drop_private(self.auth.id))
        self.assertEqual(self.r.db.vector_count(EMB.name), before - 1)
        self.r.purge(self.money.id)
        got = [l.entry.id for l, _ in self.r.db.vector_search(EMB, "totals money", 5)]
        self.assertNotIn(self.money.id, [i for i in got if self.r.get_private(i) is None], "a purged shared note is hidden")

    def test_without_numpy_the_same_notes_come_back_in_the_same_order(self):
        self.r.db.index_vectors(EMB)
        with_np = [l.entry.id for l, _ in self.r.db.vector_search(EMB, "slow csv export hang", 5)]
        with mock.patch.dict("sys.modules", {"numpy": None}):
            without = [l.entry.id for l, _ in self.r.db.vector_search(EMB, "slow csv export hang", 5)]
        self.assertEqual(with_np, without)

    def test_ask_uses_meaning_by_default_and_shows_where_a_hit_is_held(self):
        with mock.patch.object(embed, "load", lambda cfg: None):  # the model cannot start (no network yet): words only
            self.assertEqual(self.run_cli("ask", "why do totals lose money")[0], 4, "no model: words only, nothing in common")
        with mock.patch.object(embed, "load", lambda cfg: EMB):
            code, text = self.run_cli("ask", "why do totals lose money")
            self.assertEqual(code, 4, "nothing is embedded until the tidy pass has run, and nothing shares a word")
            self.assertIn("not in the meaning index yet", text, "and ask says so")
        self.r.db.index_vectors(EMB)  # what the background tidy pass does after a savepoint or a pull
        with mock.patch.object(embed, "load", lambda cfg: EMB):
            code, text = self.run_cli("ask", "why do totals lose money")  # nothing to switch on
            self.assertEqual(code, 0, text)
            self.assertIn(self.money.id, text)
            self.assertIn("found by meaning", text)
            self.assertIn(f"shelf {self.r.user}/000000", text)
            self.assertIn("the same note is in git", text)
            self.assertEqual(self.run_cli("ask", "why do totals lose money", "--exact")[0], 4, "--exact is words only")
            self.run_cli("config", "semantic", "off")
            self.assertEqual(self.run_cli("ask", "why do totals lose money")[0], 4, "off: words only")


class TestConversations(DbBase):
    def test_a_conversation_is_stored_as_a_log(self):
        from getlogbook import convo
        msgs = [{"role": "user", "text": "first question"}, {"role": "assistant", "text": "first answer"}]
        convo.save(self.r, "18bcfe5917f-873b8d63", msgs)
        self.assertEqual([m["text"] for m in convo.load(self.r, "18bcfe5917f-873b8d63")], ["first question", "first answer"])
        self.assertEqual(convo.load(self.r, "no-such-log"), [])


if __name__ == "__main__":
    unittest.main()
