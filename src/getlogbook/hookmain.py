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
        # "post-commit": an older install still has a git hook that calls this; it does nothing now (setup removes the hook)
    except Exception:
        pass
    return 0
