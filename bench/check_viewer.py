"""Load the real viewer in a headless browser and check it draws: no console errors, every tab renders, a note is findable.

No unit test covers viewer.html, and a JavaScript error blanks the page, so run this after changing it.
Needs the `playwright-cli` command (npm i -g @playwright/cli) and Edge or Chrome.

    python bench/check_viewer.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
PORT = "8793"


def run(*args, cwd=None, **kw):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", env=ENV, **kw)


def pw(*args, cwd):
    return run(shutil.which("playwright-cli"), *args, cwd=cwd).stdout


def main():
    if not shutil.which("playwright-cli"):
        sys.exit("playwright-cli not found: npm i -g @playwright/cli")
    work = Path(tempfile.mkdtemp(prefix="logbook-viewer-"))
    out = run(sys.executable, "-m", "getlogbook", "demo", "--dir", str(work / "demo")).stdout
    m = re.search(r"cd (\S+bob)", out)
    if "ALL CHECKS PASSED" not in out or not m:
        sys.exit("the demo failed:\n" + out[-800:])
    bob = m.group(1)
    server = subprocess.Popen([sys.executable, "-m", "getlogbook", "serve", "--port", PORT], cwd=bob, env=ENV,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    failures = []
    try:
        url = re.search(r"http://\S+", server.stdout.readline()).group(0)
        time.sleep(1)
        pw("open", url, "--browser", "msedge", cwd=work)
        base = url.split("?")[0]
        for tab in ("timeline", "files", "recent", "gaps"):
            pw("goto", f"{base}#{tab}", cwd=work)
            snap = pw("snapshot", cwd=work)
            if "Could not draw" in snap or not re.search(r"heading", snap):
                failures.append(f"tab {tab} did not draw")
        pw("goto", f"{base}#timeline", cwd=work)
        found = pw("find", "revenue", cwd=work)
        if "No matches" in found:
            failures.append("the demo's revenue note is not findable on the timeline")
        console = pw("console", cwd=work)
        if not re.search(r"Errors: 0", console):
            failures.append("console errors: " + console.strip()[:300])
        pw("close", cwd=work)
    finally:
        server.terminate()
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(ROOT / ".playwright-cli", ignore_errors=True)
    if failures:
        sys.exit("viewer check FAILED:\n  " + "\n  ".join(failures))
    print("viewer check passed: four tabs drew, a note was findable, 0 console errors")


if __name__ == "__main__":
    main()
