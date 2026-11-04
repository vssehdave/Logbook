"""Does the nudge fire, and is the note it gets right? Real `claude -p` sessions on a small fixture repo, one fresh clone per run.

Usage: python bench/real_session.py <path to logbook executable> [--n 1] [--tasks explain,debug,refactor,trivial] [--max-turns 30] [--model M]

Per run it records: whether a reminder fired (.git/logbook/nudges.log), whether a note was written, the note's grounding record, whether the note names the
planted cause (a keyword check: a heuristic, read the notes too), the tokens and the cost Claude Code reports. It spends real tokens: start with --n 1.
Writes bench/real_session.json next to this file. Targets (not yet agreed with the owner): every root-cause run ends with a grounded note that names the
cause; no reminder and no note on the trivial run.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FILES = {
    "shop/__init__.py": "",
    "shop/revenue.py": "def total(orders):\n    return sum(o['amount'] for o in orders)\n",
    "shop/checkout.py": "def price(items):\n    subtotal = sum(i['price'] * i['qty'] for i in items)\n    return round(subtotal + subtotal * 0.13, 2)\n",
    "tests/test_revenue.py": ("import unittest\nfrom shop.revenue import total\n\n\nclass T(unittest.TestCase):\n    def test_refunds_are_not_revenue(self):\n"
                              "        orders = [{'amount': 10, 'refunded': False}, {'amount': 5, 'refunded': True}]\n        self.assertEqual(total(orders), 10)\n"),
}
# kind, prompt, words a correct note must contain (any one), whether a note is expected
TASKS = {
    "explain": ("Explain how shop/checkout.py computes the price and where the tax comes from.", [], False),
    "debug": ("The test in tests/test_revenue.py fails. Find the root cause, fix it and say why it happened.", ["refund"], True),
    "refactor": ("In shop/checkout.py move the tax rate into a named constant and keep the behaviour the same.", [], False),
    "trivial": ("What does 2 + 2 equal? Answer in one word.", [], False),
}


def run(*a, cwd, env=None, timeout=900):
    r = subprocess.run(a, cwd=cwd, capture_output=True, text=True, encoding="utf-8", env=env, timeout=timeout, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout + r.stderr


def one(lb, name, args):
    prompt, words, expect_note = TASKS[name]
    d = Path(tempfile.mkdtemp(prefix=f"lb-real-{name}-"))
    for p, t in FILES.items():
        f = d / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(t, encoding="utf-8")
    for c in (["init", "-q"], ["config", "user.email", "bench@example.com"], ["config", "user.name", "Bench"], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
        run("git", *c, cwd=d)
    env = dict(os.environ, PATH=str(Path(lb).parent) + os.pathsep + os.environ["PATH"])
    env.pop("LOGBOOK_WRITER", None)
    run(lb, "setup", "--yes", "--agent", "claude-code", cwd=d, env=env)
    if args.no_scribe:  # the main-agent path: the nudge then tells the main agent to write the note itself
        (d / ".claude" / "agents" / "logbook-scribe.md").unlink(missing_ok=True)
    cmd =["claude", "-p", prompt, "--output-format", "json", "--max-turns", str(args.max_turns),
           "--allowedTools", "Read Grep Glob Edit Bash(python -m unittest:*) Bash(logbook:*)"]
    if args.model:
        cmd += ["--model", args.model]
    rc, out = run(*cmd, cwd=d, env=env)
    try:
        res = json.loads(out)
    except ValueError:
        res = {}
    private = d / ".git" / "logbook"
    notes = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((private / "private").glob("*.json"))] if (private / "private").exists() else []
    notes = [n for n in notes if n.get("provenance") != "auto-copied"]  # the end-of-session draft is not the agent's note
    log = private / "nudges.log"
    fired = len(log.read_text(encoding="utf-8").splitlines()) if log.exists() else 0
    text = " ".join(" ".join(str(v) for v in n.get("body", {}).values()) for n in notes).lower()
    u = res.get("usage") or {}
    slug = "".join(c if c.isalnum() else "-" for c in str(d))  # Claude Code keeps the transcript under ~/.claude/projects/<the path with symbols as dashes>
    scribe_used = any('"subagent_type":"logbook-scribe"' in p.read_text(encoding="utf-8", errors="replace").replace(": ", ":")
                      for p in (Path.home() / ".claude" / "projects" / slug).glob("*.jsonl"))
    return {"task": name, "dir": str(d), "no_scribe": args.no_scribe, "scribe_used": scribe_used,"claude_exit": rc, "turns": res.get("num_turns"), "reminders_fired": fired, "notes": len(notes),
            "grounding": [n.get("checks") for n in notes], "has_evidence": [bool((n.get("body") or {}).get("evidence")) for n in notes],
            "names_the_cause": (any(w in text for w in words) if words else None), "note_expected": expect_note,
            "tokens_in": u.get("input_tokens"), "tokens_out": u.get("output_tokens"), "cost_usd": res.get("total_cost_usd")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logbook")
    ap.add_argument("--n", type=int, default=1)
    ap.add_argument("--tasks", default=",".join(TASKS))
    ap.add_argument("--max-turns", type=int, default=30)
    ap.add_argument("--model", default="")
    ap.add_argument("--no-scribe", action="store_true", help="remove the logbook-scribe agent after setup, to measure the main-agent path")
    args = ap.parse_args()
    rows = []
    for name in args.tasks.split(","):
        for _ in range(args.n):
            row = one(args.logbook, name, args)
            rows.append(row)
            print(json.dumps(row))
    out = Path(__file__).with_name("real_session.json")
    out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    bad = [r for r in rows if (r["note_expected"] and (not r["notes"] or r["names_the_cause"] is False)) or (r["task"] == "trivial" and (r["reminders_fired"] or r["notes"]))]
    print(f"\n{len(rows)} runs, {len(bad)} outside the targets: {[r['task'] for r in bad]}  (details in {out.name})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
