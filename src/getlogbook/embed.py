"""Embeddings for search by meaning (on by default; `logbook config semantic off` turns it off).

An embedder turns text into a unit-length vector of 32-bit floats, packed as bytes, so that two texts about the same thing sit close together even
when they share no word ("totals lose a cent" finds "refund rounding drops a cent"). The packages come with `pip install getlogbook` (onnxruntime, tokenizers,
huggingface_hub, numpy) and the model, all-MiniLM-L6-v2 (90 MB, CPU only), is downloaded once, by `logbook setup` or the first search. LOGBOOK_OFFLINE=1 never downloads or loads it.

The vectors are derived data. They live in the local SQLite file (notesdb.note_vec), never in git, are never published, and are rebuilt from the notes
at any time. They only add candidates to a search; every hit is still a stored note with its author, ref, git blob, commit, time and checks, and is
shown with them.

Starting the model takes about a second once it is downloaded (the first run downloads 90 MB), so the hook that runs on every prompt starts it only for a prompt that
names nothing the notes know and whose words found too little (recall.by_meaning); `logbook ask` starts it on every search.
"""
from __future__ import annotations

import importlib.util
import os

DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"  # the commit of the default model that was tested; another `semantic_model` follows its main branch
MAX_TOKENS = 256  # the model's own limit; longer text is cut
MAX_TEXT = 1500  # characters of one note that are embedded
FIELDS = ("summary", "what", "why", "wrong", "fix", "decided", "context", "open")


class Embedder:
    """`encode(texts)` returns one packed unit-length float32 vector (bytes) per text; `name` identifies the model, so vectors made by another one are not mixed in."""

    def __init__(self, name, encode):
        self.name, self.encode = name, encode


def installed():
    return all(importlib.util.find_spec(m) is not None for m in ("onnxruntime", "tokenizers", "huggingface_hub", "numpy"))


def note_text(e):
    """What is embedded for a note: its topic, its reasons and the subject of its commit. Not the evidence (commands and output) and not a teammate's links."""
    parts = [e.topic, *(e.body.get(k, "") for k in FIELDS), e.anchor.get("subject", "")]
    return " ".join(p for p in parts if p)[:MAX_TEXT]


def semantic_on(cfg):
    """Search by meaning is on unless `config semantic off` (stored as False) turned it off."""
    return cfg.get("semantic", "on") not in (False, "off")


def _cached(name, rev, filename):
    """Path of a file of the pinned default model that is already in the Hugging Face cache, else None. Reading the cache directly skips importing
    huggingface_hub (about 0.8 s), which is only needed to download."""
    if rev is None:
        return None
    hub = os.environ.get("HF_HUB_CACHE") or os.path.join(os.environ.get("HF_HOME") or os.path.join(os.path.expanduser("~"), ".cache", "huggingface"), "hub")
    path = os.path.join(hub, "models--" + name.replace("/", "--"), "snapshots", rev, *filename.split("/"))
    return path if os.path.isfile(path) else None


def _file(name, rev, filename):
    path = _cached(name, rev, filename)
    if path:
        return path
    from huggingface_hub import hf_hub_download
    return hf_hub_download(name, filename, revision=rev)


def load(cfg):
    """The configured embedder, or None when the packages are missing, the model cannot be loaded or LOGBOOK_OFFLINE is set (the caller then falls back to text search)."""
    if os.environ.get("LOGBOOK_OFFLINE") or not installed():
        return None
    os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
    name = cfg.get("semantic_model") or DEFAULT_MODEL
    rev = MODEL_REVISION if name == DEFAULT_MODEL else None
    try:
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer
        tok = Tokenizer.from_file(_file(name, rev, "tokenizer.json"))
        tok.enable_truncation(MAX_TOKENS)
        tok.enable_padding()
        sess = ort.InferenceSession(_file(name, rev, "onnx/model.onnx"), providers=["CPUExecutionProvider"])
        wants_types = "token_type_ids" in {i.name for i in sess.get_inputs()}
    except Exception:  # a missing download, a bad name, a broken install: text search still works
        return None

    def encode(texts):
        texts, out = list(texts), []
        for i in range(0, len(texts), 32):  # small batches keep memory flat
            enc = tok.encode_batch(texts[i:i + 32])
            ids = np.array([e.ids for e in enc], dtype="int64")
            mask = np.array([e.attention_mask for e in enc], dtype="int64")
            feed = {"input_ids": ids, "attention_mask": mask}
            if wants_types:
                feed["token_type_ids"] = np.zeros_like(ids)
            hidden = sess.run(None, feed)[0]  # (batch, tokens, 384)
            m = (hidden * mask[..., None]).sum(axis=1) / np.maximum(mask.sum(axis=1, keepdims=True), 1)  # mean over real tokens only
            norms = np.linalg.norm(m, axis=1, keepdims=True)
            out += [row.tobytes() for row in (m / np.where(norms == 0, 1, norms)).astype("float32")]
        return out

    return Embedder(name, encode)

