"""The publish queue: the ids of the private entries that `logbook publish` will share, and nothing else.

    .git/logbook/queue.json    {id: {"by": "tidy" | "user", "t": epoch seconds}}

Tidy keeps it (tidy.queue_pass): a log goes in when it is saved, a note when its checks pass, and an entry that was archived, published or stopped passing
comes out again. A person's own note goes in with `logbook note -q`; tidy leaves what the person queued alone until it is published. `logbook queue` shows the
queue, `--add` and `--remove` change it by hand, and publish empties it of what it shared.
"""
from __future__ import annotations

import json
import time

from .entry import ID_RE
from .store import atomic_write


def _path(repo):
    return repo.cdir / "queue.json"


def load(repo):
    """{id: {"by", "t"}}; empty when there is no queue yet or the file is damaged (tidy rebuilds it)."""
    try:
        q = json.loads(_path(repo).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in q.items() if isinstance(k, str) and ID_RE.match(k) and isinstance(v, dict)} if isinstance(q, dict) else {}


def _save(repo, q):
    atomic_write(_path(repo), json.dumps(q, indent=1, sort_keys=True))


def add(repo, ids, by="tidy"):
    """Queue these ids; one already queued keeps its original `by`. Returns the ids that were new."""
    q = load(repo)
    new = [i for i in dict.fromkeys(ids) if ID_RE.match(i) and i not in q]
    for i in new:
        q[i] = {"by": by, "t": int(time.time())}
    if new:
        _save(repo, q)
    return new


def drop(repo, ids):
    """Take these ids out of the queue. Returns the ids that were in it."""
    q = load(repo)
    gone = [i for i in dict.fromkeys(ids) if i in q]
    for i in gone:
        del q[i]
    if gone:
        _save(repo, q)
    return gone
