"""The background model call and its budget, shared by the observer (and later the tidy worker).

A model pass goes through the person's own `claude -p`, so no key is stored. It runs from an empty directory with settings, MCP servers and slash commands off,
which keeps the fixed cost of a call to a fraction of a cent, and with the guard variable set so that every Logbook hook ignores it. A daily call cap and a
one-hour pause after a usage-allowance error keep it from competing with the person's own session.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from .store import atomic_write

GUARD = "LOGBOOK_WORKER"  # set on the worker's own claude run: every Logbook hook returns at once when it is present
MODEL = "haiku"
MAX_CALLS = 120  # model calls per day
COOLDOWN = 3600  # seconds to stay quiet after the usage allowance runs out
TIMEOUT = 240
LOG_LINES = 200
_QUOTA = re.compile(r"usage (allowance|limit)|rate.?limit|quota|exhausted|overloaded|too many requests", re.I)
FLAGS = ["--output-format", "json", "--no-session-persistence", "--tools", "", "--strict-mcp-config", "--disable-slash-commands", "--setting-sources", ""]


def call_model(prompt, model=MODEL):
    """(text, cost in USD, error). The prompt goes on stdin: a command line is limited to about 32,000 characters on Windows."""
    env = dict(os.environ, **{GUARD: "1"})
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    with tempfile.TemporaryDirectory(prefix="logbook-worker-") as d:
        try:
            p = subprocess.run(["claude", "-p", "--model", os.environ.get("LOGBOOK_WORKER_MODEL", model), *FLAGS], input=prompt, cwd=d, env=env,
                               capture_output=True, text=True, encoding="utf-8", timeout=TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as ex:
            return "", 0.0, f"could not run claude: {ex}"
    try:
        j = json.loads(p.stdout)
    except ValueError:
        return "", 0.0, (p.stdout + p.stderr).strip()[:300] or f"claude exited {p.returncode}"
    if p.returncode or j.get("is_error"):
        return "", float(j.get("total_cost_usd") or 0), str(j.get("result") or p.stderr)[:300]
    return str(j.get("result") or ""), float(j.get("total_cost_usd") or 0), ""


def is_on(cfg):
    """The observer collects unless it is switched off (`logbook config worker off`); the config stores "off" as False."""
    return cfg.get("worker", "on") not in (False, "off")


def available():
    return shutil.which("claude") is not None


def enabled(repo):
    return is_on(repo.cfg()) and not os.environ.get(GUARD)


# ---- the ledger: what it has spent, and when to stay quiet -------------------------------------------------------
def _wdir(repo):
    return repo.cdir / "worker"


def ledger(repo):
    try:
        led = json.loads((_wdir(repo) / "ledger.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        led = {}
    day = time.strftime("%Y-%m-%d")
    if led.get("day") != day:
        led.update(day=day, calls=0, cost=0.0)
    for k, v in (("notes", 0), ("cooldown_until", 0), ("last_error", ""), ("last_run", 0)):
        led.setdefault(k, v)
    return led


def save(repo, led):
    _wdir(repo).mkdir(parents=True, exist_ok=True)
    atomic_write(_wdir(repo) / "ledger.json", json.dumps(led))


def log_pass(repo, session, res, now=time.time):
    """One line per pass in worker/log.jsonl: a skipped pass leaves no other trace."""
    from . import capture
    try:
        p = _wdir(repo) / "log.jsonl"
        _wdir(repo).mkdir(parents=True, exist_ok=True)
        old = p.read_text(encoding="utf-8").splitlines()[-(LOG_LINES - 1):] if p.exists() else []
        atomic_write(p, "\n".join(old + [json.dumps({"t": int(now()), "session": capture._sid(session)[:12], **res})]) + "\n")
    except OSError:
        pass


def last_pass(repo):
    try:
        return json.loads((_wdir(repo) / "log.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    except (OSError, ValueError, IndexError):
        return {}


def status(repo):
    led = ledger(repo)
    cfg = repo.cfg()
    return {"worker": "on" if is_on(cfg) else "off", "tidy": cfg.get("tidy", "manual"), "calls_today": led["calls"], "cost_today": led["cost"],
            "notes_written": led["notes"], "cooling_down": time.time() < led["cooldown_until"], "last_error": led["last_error"], "last_pass": last_pass(repo)}
