import sys

if len(sys.argv) > 1 and sys.argv[1] in ("capture", "post-commit", "post-merge", "pre-push"):
    # hook fast path: no argparse, no CLI imports (saves ~100 ms per invocation)
    from .hookmain import run

    raise SystemExit(run(sys.argv[1:]))

from .cli import main

raise SystemExit(main())
