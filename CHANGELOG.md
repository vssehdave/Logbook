# Changelog

## Unreleased

- Removed the browser viewer (`logbook serve`, `demo --serve`). It lives on the `viewer` branch.

## 0.0.2

Logbook now helps the agent write the notes, instead of leaving it to chance.

### Changed (read this when upgrading)

- Notes no longer know about dbt models or layers. An anchor carries `names` (file names) in place of `models`; entries written by
  0.0.1 still load, their `models` become `names` and their `layers` are ignored.
- The `inferred` provenance is now `auto-copied`; files that say `inferred` load as `auto-copied`.
- `logbook install` sets everything up and asks first (`--yes` applies, `--dry-run` only looks). `--write` still works as `--yes`.
  The old hooks-only behaviour is now one step of it.
- The default size cap for a published note is 32,768 bytes (was 16,384) because notes can be longer.
- The Stop hook now asks Claude Code once to record a note before it finishes a turn that read or searched three or more times and
  wrote none. `logbook config nudge context` makes it a reminder on the next prompt, `off` removes it.

### Added

- One-command setup and removal: git post-commit and pre-push hooks, Claude Code hooks, a skill, and an always-on rules block for
  Claude Code, `AGENTS.md`, Copilot, Gemini and Cursor. Backups, atomic writes, symlink and line-ending safe, `uninstall`.
- Richer notes: `context`, `decided`, `open`, `scale`, a longer `summary`, `sources`, `level`. `logbook note --json` reads a whole
  note from stdin; `--commit <sha>` writes about an earlier commit; `--sources` cites findings.
- Following notes through a merge, a rebase, and a squash; a note about a branch's work waits with the branch until its merge.
- Coverage: chores, merges and whitespace or rename-only commits count as covered; `logbook doctor` counts the rest.
- `logbook context`, `logbook backfill`, `logbook summarize`, `logbook queue`, `logbook publish --all`, `logbook config`.
- Summaries of the repo or a branch, written by the agent, shown at session start while fresh.
- Prompt matching on free text, not only on file names.
- `bench/run_ab.py` (notes against none, and unprompted note-writing); real Claude Code hook payloads
  as test fixtures.

### Known limits

- Hooks exist only for Claude Code. A note written before its branch's first commit is lost to a squash merge.
- The measurements are two small smoke tests on a toy repo, not evidence about real work.

## 0.0.1

First public alpha: private and shared logs on git refs, anchoring with a re-anchor ladder, trust and redaction, the local viewer,
Claude Code hooks, and a demo.
