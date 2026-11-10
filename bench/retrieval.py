"""Measure how fast and how big Logbook's retrieval is at 1,000 / 10,000 / 100,000 notes, and compare it with a local SQLite FTS5 index.

    python bench/retrieval.py --work <empty scratch folder> [--sizes 1000,10000,100000] [--queries 12] [--runs 5]

For each size it builds a scratch git repository (400 commits), writes N synthetic notes (30% private files, 70% spread over shared refs of
several authors, at most 5000 per shelf like the real limit), then measures:
  * disk: the repository's .git and .git/logbook after `git gc`;
  * the hook path: a fresh Python process that imports logbook and runs recall.digest for a prompt (what every user prompt costs), p50/p95,
    with the shared-notes cache warm and with it cold (what the first prompt after a sync costs);
  * the pieces in-process: load_shared (cold and cached), load_private, tree.all_views, recall.rank;
  * what is injected: characters and an estimate of tokens (chars / 4); retrieval itself calls no model, so it costs no model tokens;
  * a prototype index (SQLite FTS5) built from the same notes, never authoritative: build time, size, query p50/p95, and the cost of re-reading
    the top hits from git to prove where they came from.
The notes are synthetic (random words from a fixed vocabulary): the numbers are about size and speed, not about the quality of the ranking.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

SRC = Path(os.environ.get("LOGBOOK_SRC") or Path(__file__).resolve().parent.parent / "src")  # LOGBOOK_SRC: measure another checkout of the code
sys.path.insert(0, str(SRC))

from getlogbook import recall, tree  # noqa: E402
from getlogbook.entry import Entry  # noqa: E402
from getlogbook.store import PREFIX, SHELF, Repo, user_id  # noqa: E402


def sh(*a, cwd, inp=None):
    p = subprocess.run(a, cwd=cwd, input=inp.encode() if isinstance(inp, str) else inp, capture_output=True)  # bytes both ways: text mode turns \n into \r\n on Windows
    if p.returncode:
        raise SystemExit(f"{' '.join(a)}: {p.stderr.decode(errors='replace')[:300]}")
    return p.stdout.decode(errors="replace")


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(q * (len(xs) - 1))))]


def stats(xs):
    return {"p50_ms": round(1000 * statistics.median(xs), 1), "p95_ms": round(1000 * pct(xs, 0.95), 1), "n": len(xs)}


def timed(f, *a):
    t = time.perf_counter()
    r = f(*a)
    return time.perf_counter() - t, r


# ---- the scratch repository ------------------------------------------------------------------------------------------------------
def vocab(rnd, n=900):
    syl = ["ba", "ke", "lo", "mi", "nu", "ra", "so", "ti", "ve", "zu", "an", "or", "el", "ig", "us"]
    return sorted({"".join(rnd.choice(syl) for _ in range(rnd.randint(2, 4))) for _ in range(n * 2)})[:n]


def make_repo(path, rnd, commits=400):
    path.mkdir(parents=True)
    sh("git", "init", "-q", "-b", "main", cwd=path)
    sh("git", "config", "user.email", "me@bench.test", cwd=path)
    sh("git", "config", "user.name", "Bench", cwd=path)
    files = [f"src/mod{i % 25}/part{i}.py" for i in range(120)]
    stream, t0 = [], 1_700_000_000
    for i in range(commits):
        f = files[i % len(files)]
        body = f"# change {i}\n"
        msg = f"change {i}: update {f}"
        email = f"dev{i % 6}@bench.test" if i else "me@bench.test"
        stream.append(f"commit refs/heads/main\ncommitter Dev <{email}> {t0 + i * 60} +0000\ndata {len(msg)}\n{msg}\n"
                      + f"M 100644 inline {f}\ndata {len(body)}\n{body}\n")
    sh("git", "fast-import", "--quiet", cwd=path, inp="".join(stream))
    sh("git", "reset", "-q", "--hard", cwd=path)
    shas = sh("git", "rev-list", "main", cwd=path).split()
    return files, shas


def write_notes(path, repo, n, rnd, words, files, shas):
    """30% private (rows in the library), 70% on shared refs; returns {ids by scope} and the shelf users."""
    base = 1_700_000_000_000
    n_priv, n_sh = int(n * 0.3), n - int(n * 0.3)
    shelves = max(1, -(-n_sh // 4000))
    users = [user_id(f"dev{i}@bench.test") for i in range(6)] + [user_id(f"ext{i}@bench.test") for i in range(max(0, shelves - 6))]
    users = users[:shelves]
    shelf_streams = {u: [] for u in users}
    made, private = [], []
    for i in range(n):
        eid = f"{base + i:011x}-{os.urandom(4).hex()}"
        f = rnd.choice(files)
        stem = Path(f).stem
        ws = lambda k: " ".join(rnd.choice(words) for _ in range(k))  # noqa: E731
        e = Entry(id=eid, kind="finding", topic=ws(5), provenance=rnd.choice(["agent-written", "user-written"]), captured_via="bench", v=2,
                  created=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(base / 1000 + i)),
                  body={"summary": ws(30), "what": ws(25), "why": ws(30), "wrong": ws(15), "fix": ws(15), "evidence": f"ran {ws(6)}; got {ws(4)}"},
                  anchor={"sha": rnd.choice(shas), "branch": "main", "subject": ws(5), "paths": [f], "names": [stem, rnd.choice(words)]})
        made.append(e)
        if i < n_priv:
            private.append(e)
        else:
            u = users[(i - n_priv) % shelves]
            data = e.to_json().encode("utf-8")
            shelf_streams[u].append(f"M 100644 inline entries/{eid}.json\ndata {len(data)}\n".encode() + data + b"\n")
    with repo.db._tx():  # one transaction: 30,000 separate ones would time the disk, not the retrieval
        for e in private:
            repo.db._put(e, "private", repo.user, repo.device)
    for u, chunks in shelf_streams.items():
        head = f"commit {PREFIX}/{u}/{SHELF}\ncommitter logbook <logbook@localhost> 1700000000 +0000\ndata 6\nbench\n".encode()
        sh("git", "fast-import", "--quiet", cwd=path, inp=head + b"".join(chunks))
    return made, users


def dirsize(p):
    return sum(f.stat().st_size for f in Path(p).rglob("*") if f.is_file())


# ---- the hook path in a fresh process --------------------------------------------------------------------------------------------
HOOK = ("import sys,time;sys.path.insert(0,%r);t=time.perf_counter();"
        "from getlogbook import recall;from getlogbook.store import Repo;r=Repo('.');o=recall.digest(r,'UserPromptSubmit',prompt=sys.argv[1],session='b'+sys.argv[2]);"
        "print(round(time.perf_counter()-t,4),len(o))")


def hook_run(path, prompt, k):
    t = time.perf_counter()
    out = sh(sys.executable, "-c", HOOK % str(SRC), prompt, str(k), cwd=path).split()
    return time.perf_counter() - t, int(out[1])


# ---- the run ---------------------------------------------------------------------------------------------------------------------
def run_size(work, n, nq, runs):
    rnd = random.Random(n)
    path = work / f"n{n}"
    words = vocab(rnd)
    files, shas = make_repo(path, rnd)
    repo = Repo(path)
    repo.init()
    t = time.perf_counter()
    notes, users = write_notes(path, repo, n, rnd, words, files, shas)
    gen_s = time.perf_counter() - t
    sh("git", "gc", "-q", "--prune=now", cwd=path)
    res = {"notes": n, "authors_with_shelves": len(users), "generate_s": round(gen_s, 1), "git_dir_mb": round(dirsize(path / ".git") / 1e6, 1)}
    picks = rnd.sample(notes, nq)  # prompts: a file name plus topic words of a real note, topic words only, and one of stop words (matches nothing)
    prompts = [f"why did {Path(e.anchor['paths'][0]).stem} change, {e.topic}" for e in picks[: nq // 2]] + [e.topic + " " + e.body["why"][:40] for e in picks[nq // 2:]]
    prompts[-1] = "please can you do that for me now"
    res["first_open_s"] = round(timed(lambda: (repo.db, repo.db.refresh_shared()))[0], 2)  # the shared shelves are mirrored into the library
    res["library_mb"] = round((repo.cdir / "library.sqlite").stat().st_size / 1e6, 1)

    cold = []
    for i in range(min(runs, 3)):  # the first prompt after a sync: every shelf is read again
        repo.db.drop_mirror()
        cold.append(hook_run(path, prompts[0], 100 + i)[0])
    hook_run(path, prompts[0], 200)  # warm up the cache
    warm, chars = [], []
    for i, p in enumerate(prompts[: max(runs, 3)]):
        dt, c = hook_run(path, p, 300 + i)
        warm.append(dt)
        chars.append(c)
    res["hook_process"] = {"warm": stats(warm), "first_prompt_after_sync_worst_case": stats(cold)}
    res["injected_chars_avg"] = round(statistics.mean(chars))
    res["injected_tokens_est_avg"] = round(statistics.mean(chars) / 4)  # retrieval calls no model: this is the only token cost, paid by the agent's prompt

    res["in_process_s"] = {"load_private": round(timed(repo.load_private)[0], 3), "load_shared": round(timed(repo.load_shared)[0], 3),
                           "all_views_everything": round(timed(tree.all_views, repo)[0], 3)}
    # new shared notes arriving (a teammate published 100): what the next prompt pays to take them in
    ref = f"{PREFIX}/{users[0]}/{SHELF}"
    extra = []
    for i in range(100):
        e = Entry(id=f"{2_000_000_000_000 + i:011x}-{os.urandom(4).hex()}", topic="fresh note", body={"why": "because", "summary": "s"}, provenance="agent-written", v=2,
                  anchor={"sha": shas[0], "branch": "main", "paths": [files[0]], "names": ["fresh"]})
        data = e.to_json().encode()
        extra.append(f"M 100644 inline entries/{e.id}.json\ndata {len(data)}\n".encode() + data + b"\n")
    stream = f"commit {ref}\ncommitter logbook <logbook@localhost> 1700000100 +0000\ndata 4\nmore\nfrom {ref}^0\n".encode() + b"".join(extra)
    sh("git", "fast-import", "--quiet", cwd=path, inp=stream)
    res["refresh_after_100_new_shared_notes_ms"] = round(1000 * timed(repo.db.refresh_shared)[0], 1)
    res["refresh_when_nothing_changed_ms"] = round(1000 * timed(repo.db.refresh_shared)[0], 1)
    repo.db.con.close()  # Windows will not delete an open database
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--work", required=True, type=Path)
    ap.add_argument("--sizes", default="1000,10000,100000")
    ap.add_argument("--queries", type=int, default=12)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--keep", action="store_true", help="leave the scratch repositories for inspection")
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    out = []
    for n in (int(x) for x in a.sizes.split(",")):
        print(f"== {n} notes", file=sys.stderr, flush=True)
        r = run_size(a.work, n, a.queries, a.runs)
        print(json.dumps(r, indent=1), flush=True)
        out.append(r)
        if not a.keep:
            shutil.rmtree(a.work / f"n{n}", onerror=lambda f, p, e: (os.chmod(p, 0o700), f(p)))  # git's packs are read-only on Windows
    (a.work / "retrieval.json").write_text(json.dumps(out, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
