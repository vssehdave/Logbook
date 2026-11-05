# Logbook: brief for Claude Code

Read `docs/ROADMAP.md` first: where we are, what is next, what was decided. Design of the next phases: `docs/TIDY-AND-MEMTREE.md`.

## What it is

A Python package (`getlogbook`, command `logbook`, standard library only, git 2.31+) that keeps findings and the reasons behind changes in git, anchored to
commits, so the next agent starts from them. Notes are private (`.git/logbook/private/<id>.json`) until published to the shared shelf
(`refs/logbook/log/<user>/000000`, one JSON file per note). Claude Code integration: hooks (`capture`), a skill and rules text, and an optional plugin in this repo
(`.claude-plugin/`, `hooks/band/register.tsx`: the bibliography band above the prompt). Not tied to dbt or warehouses (that is Almanac, folder `lodestone`).

Layout: `src/getlogbook/` (`cli.py` commands, `store.py` storage and sync, `sync.py`, `tree.py` anchoring and the tree, `nav.py` addresses, `recall.py` injection, `cites.py` citations,
`ground.py` grounding checks, `capture.py` hooks, `observer.py` / `running.py` / `savepoint.py` / `worker.py` (the observer and `logbook log`), `install.py`, `agent/skill.md` and `rules.md`), `tests/test_logbook.py` and `tests/band.test.tsx`, `bench/` (`e2e.py`,
`run_ab.py`), `docs/`.

## Commands

- Tests: `env -u CLAUDE_CODE_SESSION_ID python -m unittest discover -s tests` (about 6 minutes: run it in the background). `tests/test_day.py` simulates a working day through the real hooks with a fake `claude` on PATH (no allowance spent); set `LOGBOOK_SRC` to an installed build's site-packages to run the whole suite against that build instead of the checkout. Unset that variable or notes count as agent-written and tests that CI sees differently will pass wrongly.
- Demo: `PYTHONPATH=src python -m getlogbook demo` (must print ALL CHECKS PASSED).
- Band: `claude plugin validate .` and `claude plugin test .` (the validator does not catch what the engine refuses at run time).
- End to end against an installed build: `python bench/e2e.py <path to logbook executable>` (expects ALL PASSED; on Windows the closed-input check can differ, see the script).
- A real Claude session test: clone the repo to a temp dir, install the package into a venv, `logbook setup --yes --agent claude-code`, run `claude -p "..." --allowedTools "Read Grep Glob Edit Bash(python -m unittest:*)" --max-turns 30` with the venv on PATH, then read the note in `.git/logbook/private/` and the transcript in `~/.claude/projects/<slug>/`.

## Rules

- **Commits:** authored as the user only (`Veertej Sehdave <vssehdav@uwaterloo.ca>`); no Claude attribution, co-author or "Generated with" lines. Conventional Commits, subject up to 50 characters, body wrapped at 72 explaining why, imperative. Atomic where possible.
- **Never name reference tools** (the ones whose design inspired ours) in commits, names, comments or docs.
- **Branches and PRs:** one branch per piece, a PR into `main`, CI green on all six jobs, merge with a **merge commit** (not squash). Merging, tagging a release and force-pushing need the owner's explicit permission; run them one at a time (the auto-mode classifier can block a compound command).
- **Release:** bump `pyproject.toml` (and `.claude-plugin/plugin.json`), tag `vX.Y.ZrcN` first (publishes to TestPyPI), install it in a clean venv and run `bench/e2e.py`, then release PR, tag `vX.Y.Z`; the PyPI upload waits for the owner's approval on the `pypi` environment. A new version can take a minute or two to be installable.
- **Say plainly** what is untested or hardcoded before it affects results. Verify against the real thing (a real Claude session, a real build) before saying it works: the unit tests missed the two worst bugs so far.
- **Do not write code through a bash heredoc** (backslash sequences are mangled, a nested `EOF` ends it): use the Edit and Write tools or a script file.
- GitHub sometimes answers a push with an Internal Server Error: retry.
- Prefer the GitHub MCP server over `gh` for pull requests, issues and merge state when it is registered (`claude mcp add --transport http github https://api.githubcopilot.com/mcp/ --header "Authorization: Bearer $GITHUB_PERSONAL_ACCESS_TOKEN"`; the token lives in your environment, never in the repo).
- Credentials: never write any anywhere.

## The band (UI preferences the owner set, keep them)

Row above the prompt: underlined `bibliography`, then a dot shaded by mode (light grey manual, pale yellow ask, darker yellow auto) and the mode name, then the count in grey;
the dot button toggles details. With details on: the dot and count are replaced by the mode selector `manual [ ask ] auto` (chosen one light yellow in brackets, the rest grey, each a button), a rule
under the header, and the list of sources: `¹ title · commit header (grey, clickable, opens https) · author, date`. Clicking a citation shows a peek of the latest answer that cited it; the finder
`↑ ↓ [n] x/y` walks the others; clicking the peek scrolls there. Nothing can be typed into the finder (a text field forces an enter hint). Citations are bare superscripts.
