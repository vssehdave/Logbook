"""Lean entry for agent/git hooks. Never fails the caller: always returns 0."""
import sys


def run(argv):
    try:
        from . import capture
        from .store import Repo

        if argv[0] == "capture":
            ev = argv[argv.index("--event") + 1] if "--event" in argv else ""
            agent = argv[argv.index("--agent") + 1] if "--agent" in argv else ""
            text = capture.handle_hook(ev, agent, sys.stdin.read() if not sys.stdin.isatty() else "")
            if text:
                sys.stdout.write(text)
        elif argv[0] == "post-merge":  # after a pull: fetch the shared logs in the background; never push
            r = Repo(".")
            # in tidy auto the tidy pass does that fetch first, then judges what the pull changed
            more = ["tidy", "--work", "--quiet"] if r.cfg().get("tidy") == "auto" else ["sync", "--fetch-only"]
            capture.spawn_detached([r.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", *more], r.root)
        elif argv[0] == "post-commit":  # after a commit: save a log in the background (ask and auto mode; in manual the person runs `logbook log`)
            from . import running, worker
            r = Repo(".")
            if r.cfg().get("user") and r.publish_mode() in ("ask", "auto") and worker.enabled(r) and running.branch_now(r)[0] != "HEAD":
                capture.spawn_detached([r.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", "log", "--quiet"], r.root)
    except Exception:
        pass
    return 0
