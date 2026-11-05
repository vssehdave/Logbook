"""The background model call and its budget, shared by the observer (and later the tidy worker).

A model pass goes through the person's own `claude -p`, so no key is stored and no API is called. It runs from an empty directory with settings, MCP servers and slash commands off,
which keeps the fixed cost of a call to a fraction of a cent, and with the guard variable set so that every Logbook hook ignores it. A daily call cap and a
one-hour pause after a usage-allowance error keep it from competing with the person's own session. Every call also reads the usage windows Claude reports
in its own output stream (five-hour and seven-day, as a fraction used and a reset time): when one reaches the pause threshold (95% by default, `config quota_pause`)
the observer and the log summaries stop until that window resets, and the person is told once.
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
PAUSE_AT = 95  # percent of a usage window at which background model calls stop
WINDOWS = ("five_hour", "seven_day")
last_rate = None  # {window: {"u": fraction used, "resets": epoch seconds}} from the most recent call_model, taken by settle()
FLAGS = ["--output-format", "stream-json", "--verbose", "--no-session-persistence", "--tools", "", "--strict-mcp-config", "--disable-slash-commands", "--setting-sources", ""]


def parse_stream(stdout):
    """(the final result object or None, {window: {"u", "resets"}}) from claude's stream-json lines. Only the figures Claude printed are used."""
    result, windows = None, {}
    for line in stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        if not isinstance(j, dict):
            continue
        if j.get("type") == "result":
            result = j
        info = j.get("rate_limit_info") if j.get("type") == "rate_limit_event" else None
        if isinstance(info, dict):
            found = dict(info.get("unifiedWindows") or {}) if isinstance(info.get("unifiedWindows"), dict) else {}
            if info.get("rateLimitType"):
                found.setdefault(info["rateLimitType"], info)
            for name, w in found.items():
                if isinstance(w, dict) and all(isinstance(w.get(k), (int, float)) and not isinstance(w.get(k), bool) for k in ("utilization", "resetsAt")):
                    windows[name] = {"u": float(w["utilization"]), "resets": int(w["resetsAt"])}
    return result, windows


def call_model(prompt, model=MODEL):
    """(text, cost in USD, error). The prompt goes on stdin: a command line is limited to about 32,000 characters on Windows."""
    global last_rate
    last_rate = None
    env = dict(os.environ, **{GUARD: "1"})
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    with tempfile.TemporaryDirectory(prefix="logbook-worker-") as d:
        try:
            p = subprocess.run(["claude", "-p", "--model", os.environ.get("LOGBOOK_WORKER_MODEL", model), *FLAGS], input=prompt, cwd=d, env=env,
                               capture_output=True, text=True, encoding="utf-8", timeout=TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as ex:
            return "", 0.0, f"could not run claude: {ex}"
    j, windows = parse_stream(p.stdout)
    last_rate = windows or None
    if j is None:
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


def settle(repo, led, cost, error, now=time.time):
    """Book one finished model call: its cost, the usage windows Claude reported, and a pause until the reset when a window is at the threshold
    or the call was refused for quota. Saves the ledger."""
    global last_rate
    rate, last_rate = last_rate, None
    led.update(calls=led["calls"] + 1, cost=round(led["cost"] + cost, 6), last_run=int(now()), last_error=error[:300])
    if rate:
        led["rate"] = {**rate, "seen": int(now())}
        limit = int(repo.cfg().get("quota_pause", PAUSE_AT)) / 100
        full = [(n, w) for n, w in rate.items() if n in WINDOWS and w["u"] >= limit and w["resets"] > now()]
        if full:
            n, w = max(full, key=lambda x: x[1]["resets"])
            led.update(cooldown_until=w["resets"], pause_reason=f"{n.replace('_', '-')} usage is {round(w['u'] * 100)}%, at or above the {round(limit * 100)}% pause threshold")
    if error and _QUOTA.search(error) and now() + COOLDOWN > led["cooldown_until"]:
        led.update(cooldown_until=now() + COOLDOWN, pause_reason="Claude refused a call: the usage allowance ran out")
    save(repo, led)


def pause_notice(repo, now=time.time):
    """(for the person, for the agent) the first time a pause is seen, else None. Said once per pause, so a prompt is not nagged."""
    led = ledger(repo)
    if now() >= led["cooldown_until"] or led.get("announced") == led["cooldown_until"]:
        return None
    led["announced"] = led["cooldown_until"]
    save(repo, led)
    until = time.strftime("%H:%M", time.localtime(led["cooldown_until"]))
    user = (f"logbook: observing and log summaries are paused until {until}: {led.get('pause_reason') or 'the usage allowance is nearly used'}. This keeps your "
            "allowance for your own work. Tool uses stay queued and are observed after that. It is not a failure and nothing needs restarting.")
    return user, f"[logbook] {user} Tell the user this in one sentence at the very start of your next reply. Do not restart or change anything."


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
    paused = time.time() < led["cooldown_until"]
    return {"worker": "on" if is_on(cfg) else "off", "tidy": cfg.get("tidy", "manual"), "calls_today": led["calls"], "cost_today": led["cost"],
            "notes_written": led["notes"], "cooling_down": paused, "paused_until": led["cooldown_until"] if paused else 0,
            "pause_reason": led.get("pause_reason", "") if paused else "", "usage": led.get("rate") or {}, "last_error": led["last_error"], "last_pass": last_pass(repo)}
