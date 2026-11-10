"""Search by meaning (vectors in the local database) and the conversations stored beside the logs. A stand-in model is used, so no download is needed."""
from __future__ import annotations

import json
import os
from array import array
import unittest
from unittest import mock

import test_logbook as T  # noqa: F401  (puts the source on the path and sets the test environment)
from test_notesdb import DbBase  # noqa: E402
from getlogbook import capture, embed, recall  # noqa: E402
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


def strict_encode(texts):
    """Like fake_encode, but a word that belongs to no group counts for nothing, so two texts with no topic in common are not close."""
    return [pack([sum(1.0 for w in t.lower().replace(",", " ").split() if w in g) for g in GROUPS] + [0.0]) for t in texts]


EMB = embed.Embedder("fake-v1", fake_encode)
STRICT = embed.Embedder("fake-v1", strict_encode)


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


class TestHookMeaning(DbBase):
    """The hook that runs on every prompt: meaning decides for a prompt that names nothing the notes know; one shared common word never puts a note in front of the agent."""

    def setUp(self):
        super().setUp()
        self.money = self.plain("refund rounding drops a cent", "shop/ledger.py")
        self.login = self.plain("setup looks up the handle for teammates", "shop/people.py")

    def plain(self, topic, path):
        """A note whose words, apart from the topic, belong to no topic group, so the stand-in model sees only the topic."""
        return capture.make_entry(self.r, "finding", topic, {"summary": topic, "why": "because it matters"}, paths=[path], provenance="user-written")

    def digest(self, prompt, emb, session):
        with mock.patch.object(embed, "load", lambda cfg: emb), mock.patch.object(embed, "DEFAULT_MODEL", STRICT.name):
            return recall.digest(self.r, "UserPromptSubmit", prompt, session=session)

    def test_a_paraphrase_that_shares_no_word_is_injected_when_the_vectors_exist(self):
        self.assertEqual(self.digest("why do totals lose money", None, "s1"), "", "no vectors and no model: words only, nothing in common")
        self.r.db.index_vectors(STRICT)
        text = self.digest("why do totals lose money", STRICT, "s2")
        self.assertIn(self.money.id, text)
        self.assertNotIn(self.login.id, text)

    def test_chatter_is_silent_with_and_without_the_model(self):
        self.assertEqual(self.digest("ok thanks looks good", None, "s3"), "", "one shared word is not a topic")
        self.r.db.index_vectors(STRICT)
        self.assertEqual(self.digest("ok thanks looks good", STRICT, "s4"), "", "and far from every note in meaning")
        self.assertIn(self.login.id, self.digest("looks up login teammates", None, "s5"), "two shared words still count when there is no model")

    def test_a_word_match_alone_does_not_decide_when_the_model_runs(self):
        self.r.db.index_vectors(STRICT)
        self.assertEqual(self.digest("looks up login teammates", STRICT, "s6"), "", "the words match but the meaning is far: the model's view wins")

    def test_the_two_free_text_places_go_to_notes_that_can_be_shown(self):
        for i in range(3):  # drafts with no evidence are never shown; they must not use up the places
            capture.make_entry(self.r, "finding", f"refund rounding draft {i}", {"summary": "refund rounding draft", "why": "w"}, paths=["shop/x.py"], provenance="worker-written")
        text = self.digest("refund rounding cent", None, "s7")
        self.assertIn(self.money.id, text)

    def test_ask_drops_a_note_found_by_one_common_word_only(self):
        self.r.db.index_vectors(STRICT)
        self.assertEqual(recall.hybrid(self.r, "ok thanks looks good", STRICT, 5), [])


class TestModelFiles(unittest.TestCase):
    def test_a_cached_model_file_is_found_without_importing_the_downloader(self):
        import tempfile
        with tempfile.TemporaryDirectory() as hub:
            snap = os.path.join(hub, "models--a--b", "snapshots", "rev1", "onnx")
            os.makedirs(snap)
            open(os.path.join(snap, "model.onnx"), "w").close()
            with mock.patch.dict(os.environ, {"HF_HUB_CACHE": hub}):
                self.assertEqual(embed._cached("a/b", "rev1", "onnx/model.onnx"), os.path.join(snap, "model.onnx"))
                self.assertIsNone(embed._cached("a/b", "rev1", "tokenizer.json"), "a file that is not there is downloaded")
                self.assertIsNone(embed._cached("a/b", None, "onnx/model.onnx"), "another model follows its main branch, so the downloader checks it")

    def test_search_by_meaning_is_on_unless_turned_off(self):
        self.assertTrue(embed.semantic_on({}))
        self.assertFalse(embed.semantic_on({"semantic": False}))
        self.assertFalse(embed.semantic_on({"semantic": "off"}))


class TestConversations(DbBase):
    def test_a_conversation_is_stored_as_a_log(self):
        from getlogbook import convo
        msgs = [{"role": "user", "text": "first question"}, {"role": "assistant", "text": "first answer"}]
        convo.save(self.r, "18bcfe5917f-873b8d63", msgs)
        self.assertEqual([m["text"] for m in convo.load(self.r, "18bcfe5917f-873b8d63")], ["first question", "first answer"])
        self.assertEqual(convo.load(self.r, "no-such-log"), [])


if __name__ == "__main__":
    unittest.main()
