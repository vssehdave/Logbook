"""Entry format. One small JSON file per entry; ids are unique so writers never collide.

Authorship is NOT stored in the entry: the ref path (<user>/<device>) is the authority,
because anyone with push access could otherwise claim any author inside a file.
"""
from __future__ import annotations

import json
import os
import re
import time

ID_RE = re.compile(r"^[0-9a-f]{11}-[0-9a-f]{8}$")
KINDS = ("change", "finding")
PROVENANCE = ("agent-written", "user-edited", "auto-copied")  # auto-copied: built by code from git data, carries no reason
LEVELS = ("", "commit", "branch", "repo", "path")  # which node a note is about; "" means: wherever its anchor places it
BODY_FIELDS = ("summary", "context", "what", "why", "wrong", "fix", "decided", "open", "scale", "evidence")
INJECTABLE = ("summary", "what", "why", "fix")  # evidence/wrong never enter agent context
MAX_FIELD = 2000
MAX_SUMMARY = 1000  # a few sentences, not a line
MAX_SCALE = 300
MAX_LIST = 40


def field_cap(name):
    return MAX_SUMMARY if name == "summary" else MAX_SCALE if name == "scale" else MAX_FIELD


def new_id():
    return f"{int(time.time() * 1000):011x}-{os.urandom(4).hex()}"


class Entry:
    """Plain class (not a dataclass): importing dataclasses/inspect costs ~45 ms on every hook invocation."""
    __slots__ = ("id", "kind", "topic", "body", "anchor", "provenance", "captured_via", "supersedes", "display", "created",
                 "redacted", "v", "level", "sources")

    def __init__(self, id, kind="finding", topic="", body=None, anchor=None, provenance="agent-written", captured_via="cli",
                 supersedes=None, display="", created="", redacted=False, v=1, level="", sources=None):
        self.id, self.kind, self.topic = id, kind, topic
        self.body = dict(body or {})
        self.anchor = dict(anchor or {})  # sha tree parent patch_id branch merge_base base subject date pr paths names dirty
        self.provenance, self.captured_via = provenance, captured_via
        self.level, self.sources = level, list(sources or [])  # sources: ids of the entries this one was written from
        self.supersedes = list(supersedes or [])
        self.display, self.created, self.redacted, self.v = display, created, redacted, v  # created: display only

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}

    def copy(self, **changes):
        d = self.to_dict()
        d.update(changes)
        return Entry(**d)

    def to_json(self):
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    def text(self):
        parts = [self.topic, *(self.body.get(k, "") for k in BODY_FIELDS)]
        a = self.anchor
        parts += [a.get("subject", ""), a.get("branch", ""), *a.get("paths", []), *a.get("names", [])]
        return " ".join(p for p in parts if p)


def _s(v, n=MAX_FIELD):
    return v[:n] if isinstance(v, str) else ""


def _strs(v):
    return [_s(x, 300) for x in v[:MAX_LIST] if isinstance(x, str)] if isinstance(v, list) else []


def from_dict(d):
    """Build an Entry from untrusted data: coerce types, cap sizes, reject bad ids."""
    if not isinstance(d, dict) or not isinstance(d.get("id"), str) or not ID_RE.match(d["id"]):
        raise ValueError("bad entry")
    body = d.get("body") if isinstance(d.get("body"), dict) else {}
    a = d.get("anchor") if isinstance(d.get("anchor"), dict) else {}
    anchor = {k: _s(a.get(k), 300) for k in ("sha", "tree", "parent", "patch_id", "range_pid", "branch", "merge_base", "base", "subject",
                                              "date", "pr")}
    # "models" is the 0.0.1 spelling of "names"; those files are already on people's refs
    anchor.update(paths=_strs(a.get("paths")), names=_strs(a.get("names") or a.get("models")),
                  old_paths=_strs(a.get("old_paths")), dirty=bool(a.get("dirty")))
    kind = d.get("kind") if d.get("kind") in KINDS else "finding"
    prov = d.get("provenance")
    prov = "auto-copied" if prov == "inferred" or prov not in PROVENANCE else prov  # "inferred" was the 0.0.1 spelling
    return Entry(id=d["id"], kind=kind, topic=_s(d.get("topic"), 200),
                 body={k: _s(body.get(k), field_cap(k)) for k in BODY_FIELDS if body.get(k)},
                 anchor=anchor, provenance=prov, captured_via=_s(d.get("captured_via"), 40),
                 supersedes=[x for x in _strs(d.get("supersedes")) if ID_RE.match(x)],
                 display=_s(d.get("display"), 60), created=_s(d.get("created"), 40), redacted=bool(d.get("redacted")),
                 level=d.get("level") if d.get("level") in LEVELS else "",
                 sources=[x for x in _strs(d.get("sources")) if ID_RE.match(x)])


def from_json(text):
    return from_dict(json.loads(text))
