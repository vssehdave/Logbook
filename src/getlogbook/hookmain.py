"""Lean entry for agent/git hooks. Never fails the caller: always returns 0."""
import os
import sys

PUBLISHING = "LOGBOOK_PUBLISHING"  # set while a hook's own publish runs, so the push it makes does not start another


def _publish(r, scope):
    from . import capture
    os.environ[PUBLISHING] = "1"  # the detached process inherits it
    capture.spawn_detached([r.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", "publish", scope, "--yes"], r.root)


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
            # in ask and auto mode the tidy pass does that fetch first, then judges what the pull changed
            more = ["tidy", "--work", "--quiet", "--no-judge"] if r.publish_mode() in ("ask", "auto") else ["sync", "--fetch-only"]
            capture.spawn_detached([r.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", *more], r.root)
            if r.cfg().get("user") and r.publish_mode() == "auto" and not os.environ.get(PUBLISHING):
                from . import branches
                if branches.merged(r):  # a branch of yours was merged: publish its queued entries (ask mode is told at the next session start instead)
                    _publish(r, "--merged")
        elif argv[0] == "pre-push":  # a `git push`: auto publishes the queue, ask leaves a note for the next prompt; never blocks the push
            r = Repo(".")
            if r.cfg().get("user") and r.publish_mode() in ("ask", "auto") and not os.environ.get(PUBLISHING) and r.queued():
                if r.publish_mode() == "auto":
                    _publish(r, "--all")
                else:
                    from . import outbox
                    outbox.mark_pending(r, "you pushed")
        elif argv[0] == "post-commit":  # after a commit: save a log in the background (ask and auto mode; in manual the person runs `logbook log`)
            from . import running, worker
            r = Repo(".")
            if r.cfg().get("user") and r.publish_mode() in ("ask", "auto") and worker.enabled(r) and running.branch_now(r)[0] != "HEAD":
                capture.spawn_detached([r.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", "log", "--quiet"], r.root)
    except Exception:
        pass
    return 0
