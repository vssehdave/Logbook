# Logbook

Commit-anchored shared memory for AI-assisted repos. It records **why** code changed
(what was wrong, how wrong, the fix) next to the git history, and keeps findings that never became a commit, so a
teammate or an AI agent can pick up where the last person left off. It works for any repo and knows nothing about any
particular stack.

- Python 3.10+, **standard library only**, git 2.31+. Windows, macOS, Linux. No server to host, no model calls (`backend none`):
  your own agent writes the notes.
- Two logs: a **private** one under `.git/logbook/` (never tracked), and a **shared** one on git refs
  (`refs/logbook/log/<user>/000000`, one shelf per person; two machines of the same person are merged on sync). Sharing is opt-in per entry.

**Status: alpha.** The engine, git-ref storage, sharing and the Claude Code integration work and are tested on Linux,
macOS and Windows. Notes are followed through a merge, a rebase and (when written at the branch tip) a squash; a note written before
its branch's first commit stays with the branch until a merge named for it appears, and is lost to a squash. Summaries of the repo
or a branch are written by your agent on request and go stale when a note is added. Hooks exist only for Claude Code; other agents
get a rules file. Entries marked `auto-copied` are copied from git or a truncated transcript: they carry no reason and are never
injected into an agent's prompt. The only measurements so far are two small smoke tests on a toy repo (see `docs/DESIGN.md`).

## Try it (no credentials, about 30 seconds)

    pip install getlogbook   # from a clone: pip install .   (or: PYTHONPATH=src python -m getlogbook ...)
                             # the command is `logbook`; the package name is getlogbook because `logbook` on PyPI is taken
    logbook demo           # Alice, Bob and a hostile Mallory on a scratch repo; every claim is checked

## Set it up in a repo

    logbook setup          # shows what it will change and asks; --yes to apply, --dry-run to only look
    logbook uninstall      # puts every file back (your notes are kept)

One command starts the repo, fetches teammates' notes when there is a remote, chains a git post-commit hook and a pre-push hook (it never
blocks a push and only sends notes you already published), and for each agent it finds writes that agent's hooks, an
always-on rules block and, for Claude Code, a skill (`.claude/skills/logbook/SKILL.md`). Every file it edits is backed up first to
`.git/logbook/backups`, written atomically (through symlinks, keeping line endings), and changed only between its own markers.
`--agent claude-code agents-md copilot gemini cursor` picks agents; otherwise it looks for `.claude`, `AGENTS.md`,
`.github/copilot-instructions.md`, `GEMINI.md` and `.cursor`. `logbook status --check` shows what is installed.

## What the agent does

- **Before answering** a "why" question, or searching the code for a cause, it looks up `logbook ask`. Hooks also put
  the matching notes in front of it (see below).
- **While working** it records what it learns, even with no commit: `echo '{...}' | logbook note --json` (summary, context, why,
  wrong, fix, decided, open, scale, paths). The skill shows the shape and a good example.
- **Before it finishes** a turn that read or searched three or more times and wrote no note, Claude Code is asked once to record
  one. `logbook config nudge context` makes that a reminder on the next prompt instead, `logbook config nudge off` turns it off.
  In a small test task this took unprompted note-writing from 1 of 4 runs (reminder only) to 4 of 4 (see `docs/DESIGN.md`).

## Daily use

    logbook note --json                       # the whole note as JSON on stdin (safest for agents)
    logbook note --kind finding --topic "late payments" --summary "revenue dip" --why "export stalled" --wrong "1 day under"
    logbook note --kind change --before-commit --summary "..." --why "..." --wrong "..." --fix "..."   # then commit as usual
    logbook note --commit <sha> --summary "..."   # a note about an earlier commit
    logbook publish <id>                      # preview + redaction, you confirm; evidence is opt-in
    logbook publish                           # lists your private notes that are not shared yet and asks which
    logbook publish --all                     # preview every one of them with redaction, confirm once
    logbook context                           # before a commit: does it need a note, and which of your findings it grew out of
    logbook backfill                          # recent commits with no note saying why, with diffs, for an agent to write
    logbook summarize                         # the notes under the repo or branch, for an agent to write a summary
    logbook sync                              # fetch teammates' entries, push yours
    logbook ask "refunds" | orders.py | <id> | main..HEAD   # exit 0 found, 3 ambiguous, 4 no match
    logbook log                               # the notes next to your commits, newest first (-v for their text)
    logbook status                            # what is recorded and waiting to be shared; --check, --stats

New teammate: clone, then `logbook setup`. A plain `git clone`/`git fetch` does not download logbook refs.
CI: `git fetch --depth=1 origin '+refs/logbook/log/*:refs/logbook-remote/origin/log/*'` (opt in; off by default).

## How an agent consults it first

Hooks (Claude Code is the only adapter shipped): `SessionStart`, `UserPromptSubmit` and `PreToolUse` (before Read, Edit and Write)
inject a digest of at most ~1,500 characters. A note is shown when the prompt or file names something a note was written about, or
when a prompt with no names clearly overlaps a note's words (at most two such notes). Only from people who have commits on this
history (or whom you ran `logbook trust` on), only entries that say *why* or *how wrong*, findings first, each labelled with
author, provenance, age, commits behind HEAD and "verify first". Each note is shown once per session. Agents without hooks get
the rules file, and `logbook snippet` prints the same text. Injection guarantees the notes are in context, not that the model
uses them.

## Safety defaults

- Entries from other writers are **untrusted data**: author comes from the ref path, never from the file; text is
  sanitised (links, code fences, instruction-like lines, angle brackets removed) before it reaches an agent, in `inject`
  and in CLI output.
- Every entry is recorded, searchable. Trust only decides what is *automatically injected into an
  agent's prompt*: your own entries, entries from anyone with a commit on this history (no setup), and writers you ran
  `logbook trust <user-id>` on. A writer with push access who never committed is searchable but not injected.
  Strict mode: `"inject_from": "self"` in `.logbook/policy.json`, or `trust_committers: false` in your config.
  Limit: the id in a ref path is self-asserted, so anyone who can push refs could write under a committer's id; only
  host-side ref protection prevents that.
- Publishing: allowlisted fields only, secrets/emails/connection strings masked, pasted table rows refused, exact-bytes preview
  with hash check, a local audit log. Redaction is a lint, not a guarantee. Published text can persist in forks and mirrors.
- `logbook purge <id> --push` rewrites your own ref without the entry and leaves an id-only tombstone. Rotate any leaked secret.
- Optional `.logbook/policy.json` (tracked): `publish`, `inject_from` (`self`|`trusted`), `attribution` (`none`|`pseudonym`|`named`
  ceiling), `max_entry_bytes`. The client only ever gets stricter from it. Default attribution is a pseudonymous id.

See `docs/DESIGN.md` for decisions, the failure-mode table, a small benchmark, and what is not built.
