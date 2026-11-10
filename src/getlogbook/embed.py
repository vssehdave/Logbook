"""Embeddings for search by meaning (optional; the core of Logbook stays standard-library only).

An embedder turns text into a unit-length vector of 32-bit floats, packed as bytes, so that two texts about the same thing sit close together even
when they share no word ("totals lose a cent" finds "refund rounding drops a cent"). Nothing here runs unless `config semantic on` is set and the extra
is installed:

    pip install "getlogbook[semantic]"      # model2vec: a static embedding model, about 30 MB, no GPU, no network after the first download

The vectors are derived data. They live in the local SQLite file (notesdb.note_vec), never in git, are never published, and are rebuilt from the notes
at any time. They only add candidates to a search; every hit is still a stored note with its author, ref, git blob, commit, time and checks, and is
shown with them.

Starting the model takes about 2.5 s (imports and loading), so it is used by the commands a person or an agent runs on purpose (`logbook ask`, `logbook
index`), not by the hook that runs on every prompt.
"""
from __future__ import annotations

import importlib.util
import os
from array import array

DEFAULT_MODEL = "minishlab/potion-base-8M"
MAX_TEXT = 1500  # characters of one note that are embedded
FIELDS = ("summary", "what", "why", "wrong", "fix", "decided", "context", "open")


class Embedder:
    """`encode(texts)` returns one packed unit-length float32 vector (bytes) per text; `name` identifies the model, so vectors made by another one are not mixed in."""

    def __init__(self, name, encode):
        self.name, self.encode = name, encode


def installed():
    return all(importlib.util.find_spec(m) is not None for m in ("model2vec", "numpy"))


def note_text(e):
    """What is embedded for a note: its topic, its reasons and the subject of its commit. Not the evidence (commands and output) and not a teammate's links."""
    parts = [e.topic, *(e.body.get(k, "") for k in FIELDS), e.anchor.get("subject", "")]
    return " ".join(p for p in parts if p)[:MAX_TEXT]


def load(cfg):
    """The configured embedder, or None when the extra is not installed or the model cannot be loaded (the caller then falls back to text search)."""
    if not installed():
        return None
    os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
    name = cfg.get("semantic_model") or DEFAULT_MODEL
    try:
        import numpy as np
        from model2vec import StaticModel
        model = StaticModel.from_pretrained(name)
    except Exception:  # a missing download, a bad name, a broken install: text search still works
        return None

    def encode(texts):
        m = np.asarray(model.encode(list(texts)), dtype="float32").reshape(len(texts), -1)
        norms = np.linalg.norm(m, axis=1, keepdims=True)
        m = m / np.where(norms == 0, 1, norms)
        return [row.tobytes() for row in m]

    return Embedder(name, encode)


def pack(values):
    """Floats to the packed form, scaled to unit length (for a backend that returns plain lists)."""
    norm = sum(v * v for v in values) ** 0.5 or 1.0
    return array("f", [v / norm for v in values]).tobytes()
