"""A/B benchmark: does a recorded note save an agent the investigation?

Builds a small shop repo with a bug whose cause takes several reads to find, installs Logbook into it, and runs the same
question through `claude -p` twice per round: once with no notes (A) and once with one note that records the cause (B).
Both arms have the hooks installed, so the only difference is the note. It reports tool calls, tokens and cost per run.

Needs the `claude` CLI and a Logbook install on PATH or via --logbook. Every run spends real tokens: keep --runs small.
Results are noisy at small N; read them as a smoke test, not a proof.

    python bench/run_ab.py --runs 2
"""
from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path

FILES = {
    "shop/money.py": "def round_cents(x):\n    return round(x * 100) / 100\n",
    "shop/discounts.py": "from shop.money import round_cents\n\n\ndef apply(amount, pct):\n    return round_cents(amount * (1 - pct / 100))\n",
    "shop/orders.py": "def load_week():\n    return [{'id': i, 'amount': 10.0 * (i + 1)} for i in range(7)]\n",
    "shop/payments.py": "STATUSES = ('paid', 'refunded', 'failed')\n\n\ndef load_week():\n    # all rows, refunded included: finance reports need them\n"
                        "    return [{'id': i, 'amount': 10.0 * (i + 1), 'status': STATUSES[i % 2]} for i in range(7)]\n",
    "shop/refunds.py": "def refunded_ids(rows):\n    return [r['id'] for r in rows if r['status'] == 'refunded']\n",
    "shop/revenue.py": "from shop.money import round_cents\n\n\ndef total(payments):\n    return round_cents(sum(p['amount'] for p in payments))\n",
    "shop/exports.py": "def to_csv(rows):\n    return '\\n'.join(','.join(str(v) for v in r.values()) for r in rows)\n",
    "shop/reports/__init__.py": "",
    "shop/reports/weekly.py": "from shop import payments, revenue\n\n\ndef weekly_revenue():\n    return revenue.total(payments.load_week())\n",
    "shop/reports/daily.py": "from shop import orders\n\n\ndef daily_orders():\n    return len(orders.load_week())\n",
    "shop/__init__.py": "",
    "README.md": "A small shop. Reports live in shop/reports.\n",
}
PROMPT = ("The weekly revenue from shop/reports/weekly.py runs about 4% higher than the payment processor's own report. "
          "Find the root cause and answer in two sentences: which file and function, and why. Do not change any files.")
NOTE = {"kind": "finding", "topic": "weekly revenue ran high because refunded rows were summed",
        "summary": "Weekly revenue in shop/reports/weekly.py was about 4% above the processor report. The cause is in revenue.total: "
                   "it sums every row payments.load_week returns, and that loader deliberately keeps refunded rows for finance reports.",
        "context": "Compared one week of rows with the processor report; the gap matched the refunded rows exactly. Rounding in money.py "
                   "and discounts.py was checked first and is not involved.",
        "why": "revenue.total does not filter on status, and payments.load_week returns refunded rows on purpose.",
        "wrong": "Assumed the loader should drop refunded rows; other reports need them.",
        "fix": "Filter status != 'refunded' inside revenue.total, not in the loader.",
        "decided": "Fix in revenue.total because shop/refunds.py and exports still rely on refunded rows from the loader.",
        "scale": "about 4% overstated", "paths": ["shop/revenue.py", "shop/payments.py"]}


def sh(args, cwd, **kw):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", **kw)


def build(root, logbook, with_note):
    d = Path(root)
    for rel, text in FILES.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    sh(["git", "init", "-q", "."], d)
    sh(["git", "config", "user.email", "bench@example.com"], d)
    sh(["git", "config", "user.name", "bench"], d)
    sh(["git", "add", "-A"], d)
    sh(["git", "commit", "-q", "-m", "initial shop"], d)
    r = sh([logbook, "install", "--yes", "--agent", "claude-code"], d)
    if r.returncode:
        sys.exit("logbook install failed: " + r.stderr + r.stdout)
    if with_note:
        r = subprocess.run([logbook, "note", "--json"], cwd=d, input=json.dumps(NOTE), capture_output=True, text=True, encoding="utf-8")
        if r.returncode:
            sys.exit("logbook note failed: " + r.stderr + r.stdout)


def run_claude(d, model):
    cmd = ["claude", "-p", PROMPT, "--output-format", "stream-json", "--verbose", "--setting-sources", "project,local",
           "--strict-mcp-config", "--allowedTools", "Read", "Grep", "Glob"]
    if model:
        cmd += ["--model", model]
    r = sh(cmd, d, timeout=420)
    tools, result = {}, {}
    for line in r.stdout.splitlines():
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get("type") == "assistant":
            for b in (o.get("message") or {}).get("content") or []:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    tools[b["name"]] = tools.get(b["name"], 0) + 1
        elif o.get("type") == "result":
            result = o
    u = result.get("usage") or {}
    answer = str(result.get("result") or "")
    low = answer.lower()
    return {"tools": sum(tools.values()), "by_tool": tools, "turns": result.get("num_turns"), "cost": result.get("total_cost_usd"),
            "in": u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0),
            "out": u.get("output_tokens", 0),
            "correct": "refund" in low and ("revenue.py" in low or "total" in low), "answer": answer[:300], "error": bool(result.get("is_error"))}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--runs", type=int, default=2, help="rounds; each round is one run of A and one of B")
    ap.add_argument("--logbook", default=shutil.which("logbook") or "logbook")
    ap.add_argument("--model", default="")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    results = {"A (no notes)": [], "B (one note)": []}
    for i in range(a.runs):
        for arm, with_note in (("A (no notes)", False), ("B (one note)", True)):
            tmp = tempfile.mkdtemp(prefix="logbook-ab-")
            try:
                build(tmp, a.logbook, with_note)
                res = run_claude(tmp, a.model)
            finally:  # a detached reconcile worker may still hold the folder on Windows; leaving it behind is fine
                shutil.rmtree(tmp, ignore_errors=True)
            results[arm].append(res)
            print(f"round {i + 1} {arm}: tools={res['tools']} turns={res['turns']} cost=${res['cost']} correct={res['correct']}", flush=True)
    print()
    for arm, rs in results.items():
        ok = [r for r in rs if not r["error"]]
        med = lambda k: statistics.median([r[k] or 0 for r in ok]) if ok else float("nan")
        print(f"{arm:<14} runs={len(rs)} correct={sum(r['correct'] for r in ok)}/{len(ok)}  median tools={med('tools')}  "
              f"turns={med('turns')}  input tokens={med('in'):.0f}  output tokens={med('out'):.0f}  cost=${med('cost'):.3f}")
    if a.out:
        Path(a.out).write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
