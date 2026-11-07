"""Redaction (best-effort lint, not a guarantee) and sanitising of text that enters agent context."""
from __future__ import annotations

import hashlib
import math
import re

_SECRETS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("gh-token", re.compile(r"\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("conn-string", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@\S+", re.I)),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("long-number", re.compile(r"\b\d{9,}\b")),
]
_ASSIGN = re.compile(r"(?i)\b(api[_-]?key|secret|token|passwd|password|pwd|private[_-]?key)\b(\s*[:=]\s*)(\S+)")
_TOKENISH = re.compile(r"[A-Za-z0-9+/=_-]{24,}")


def _entropy(s):
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s)))


def redact(text, deny=()):
    """Return (text, findings). Findings are kinds only, never the secret itself."""
    found = []

    def sub(kind, pat, repl):
        nonlocal text
        text, n = pat.subn(repl, text)
        found.extend([kind] * n)

    for kind, pat in _SECRETS:
        sub(kind, pat, f"[REDACTED:{kind}]")
    sub("assignment", _ASSIGN, lambda m: f"{m.group(1)}{m.group(2)}[REDACTED:assignment]")
    for m in list(_TOKENISH.finditer(text)):
        t = m.group(0)
        if any(c.isdigit() for c in t) and any(c.isalpha() for c in t) and _entropy(t) > 3.8:
            text = text.replace(t, "[REDACTED:high-entropy]")
            found.append("high-entropy")
    for d in deny:
        if d and re.search(re.escape(d), text, re.I):
            text = re.sub(re.escape(d), "[REDACTED:deny-list]", text, flags=re.I)
            found.append("deny-list")
    return text, found


_HOME = re.compile(r"(?:[A-Za-z]:[\\/]+Users[\\/]+|/Users/|/home/)[^\\/\s\"'`]+")
_OUTSIDE = re.compile(r"^(?:[A-Za-z]:|/|~|\.\./|[A-Za-z][A-Za-z0-9+.-]*://)")  # a drive, a root, the home folder, outside the folder, or a web address


def scrub_paths(text):
    """Replace the person's home folder in a path with `~` (`C:/Users/ann/work/x.py` becomes `~/work/x.py`), so a shared note does not carry a user name."""
    return _HOME.sub("~", text) if isinstance(text, str) else text


def inside(files):
    """The paths that are inside the repository (relative ones). An absolute path, a path in the home folder and a web address are left out: they say nothing a teammate
    can use, and the first two carry a user name."""
    return [f for f in files if isinstance(f, str) and f and not _OUTSIDE.match(f)]


def looks_tabular(text, run=3):
    """True if >= `run` consecutive lines look like data rows (a pasted query result)."""
    streak = best = 0
    for line in text.splitlines():
        row = any(ch.isdigit() for ch in line) and (line.count("|") >= 2 or line.count("\t") >= 2 or line.count(",") >= 3)
        streak = streak + 1 if row else 0
        best = max(best, streak)
    return best >= run


_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_FENCE = re.compile(r"```[\s\S]*?(?:```|$)")
_MDLINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.I)
_IMPERATIVE = re.compile(
    r"^\s*(?:ignore|disregard|forget|override|run|execute|exec|curl|wget|sudo|rm|delete|you (?:must|should|are)|"
    r"system\s*:|assistant\s*:|human\s*:|important\s*:|new instructions?)\b", re.I)


def sanitize(text, cap=500):
    """Make untrusted text inert before it enters an agent's context. One path in, used for every field."""
    if not isinstance(text, str):
        return ""
    t = _FENCE.sub(" ", _CTRL.sub("", text))
    t = _URL.sub("[link removed]", _MDLINK.sub(r"\1", t)).replace("<", "(").replace(">", ")")
    lines = ["[removed]" if _IMPERATIVE.match(l) else l for l in t.splitlines()]
    return " ".join(" ".join(lines).split())[:cap]


def digest_hash(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()
