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
        else:  # post-commit: the sweep for hook-less commits runs detached, so the commit never waits
            r = Repo(".")
            capture.spawn_detached([r.cfg().get("interpreter") or sys.executable, "-m", "getlogbook", "reconcile", "--quiet"], r.root)
    except Exception:
        pass
    return 0
