# Changelog

## Unreleased

- **Fixed: the "record a note" prompt never came.** The hook decided Claude had already written a note when a command merely contained the word note, so Claude's own `logbook ask "... same note id"` switched the prompt off. Only the `note` subcommand counts now. Found by running a real Claude session on a real question, where it never wrote a note; our earlier 4-of-4 measurement used a toy transcript and missed it.
- **Fewer prompts.** `logbook setup` now adds allow rules for the commands that only read or write your private notes (`note`, `ask`, `context`, `cites`, `log`, `status`, `summarize`, `backfill`) to `.claude/settings.local.json`, so Claude Code stops asking before each one. Sharing, removing and changing settings (`publish`, `sync`, `purge`, `gc`, `trust`, `config`) still ask. `logbook uninstall` removes only those entries. The skill's note example is now a heredoc so one rule covers it.
- **A note in plain words.** `logbook note "late export dips revenue" shop/revenue.py` is a whole note: the words, then the files. A person's own note needs no why and no evidence and is shown to the agent as it is; the evidence rule is for notes an agent wrote.
- **Note quality gates.** `logbook note --check` looks up what a note names (the files it concerns, the names in backticks, the commit ids) in the repo and reports `grounding: files 2/2, names 3/4, ...`, and lists notes on the same files that say much the same. A finding that names no file that exists, no commit and no evidence is refused (`--allow-ungrounded` overrides). The result is saved and published with the note; an injected note that names something that is not there is labelled `unverified` and ranks lower, and auto mode does not share it on its own. Notes can now supersede your own earlier notes (`"supersedes": [ids]`, `--supersedes`). This checks that what a note names exists, not that what it says is true.
- **"agent-written" now means Claude wrote it.** Every note used to be labelled agent-written, including the ones a person typed. A note is now `agent-written` only when it is written from inside an agent's session (Claude Code puts its session id in the environment of the commands it runs) and `user-written` otherwise. `LOGBOOK_WRITER=agent` or `=user` says it outright, for another agent or for a person using an agent's shell. Notes written by earlier versions keep their claim but are shown as `origin unknown`, because there is no way to tell. The label is published with the note.
- `logbook cites --where N` prints, as JSON, every answer in a Claude Code chat that cites number N (the transcript row's id and the words around the citation), read from Claude Code's transcript. The band uses it for its peek, so clicking a citation works for every answer in the chat, on screen or not.
- Publish modes: `logbook config publish never|ask|claude|auto` (default `ask`). never: `publish` refuses. ask: you confirm a redacted preview each time, as before. claude: the agent may publish a note it judges worth sharing, without asking you. auto: every note is published to your local shelf as it is written, redacted the same way; a note the checks refuse stays private. Pushing is still `logbook sync` in every mode, and redaction is a lint that can miss secrets. A repo policy that turns publishing off wins over any mode. The agent's rules and skill say which mode means what, and `logbook cites --json` reports the mode for the band.
- **Security fix (affects 0.0.2 and 0.0.3).** A shared note's commit, tree, parent and merge-base ids came from the note and went into `git` arguments unchecked. An id such as `--output=<path>` made `git show` overwrite that file on the reader's machine, which `logbook cites`, the injected source lines and `ask` could trigger for a note from any writer you read. Those ids are now accepted only as hex when an entry is read, and the git helpers refuse anything else too. Upgrade, and treat shared refs from writers you do not trust with care until you have.
- Citations are written as a bare superscript number (¹ ² ³), and the band uses the same label. `commit_url` and `pr_url` in the config give links for hosts Logbook does not know; a header that names a pull request falls back to the commit when there is no pull request address.
- Changed back: `git push` no longer sends your notes. `logbook sync` is the one command that pushes them (it also fetches teammates' notes and merges your other machines). The pre-push hook only reminds you, now also of notes you published but have not pushed. In 0.0.3 the hook pushed notes too, and with it installed `logbook sync` could be rejected ("incorrect old value provided") because the same ref was pushed twice. If you installed 0.0.3, run `logbook setup --yes` to replace the old hook.
- Fixed: `logbook publish` with no ids printed a traceback when there was no answer to read (closed input). It now takes that as no answer.
- The compact label in `logbook cites` and the band is the note's own title, not the commit subject; the commit or pull request header moves to the expanded line.

## 0.0.3

- An optional Claude Code plugin in this repo (`.claude-plugin/`, `hooks/band/`): a Sources band above the prompt with Copy and expand/compact, showing the notes the latest answer cited and, for a teammate's shared notes, the link, author and date. Install with `/plugin install logbook --marketplace vssehdave/Logbook`.
- Citations. Notes put in front of an agent are numbered for the whole chat, and the agent cites them as superscripts (¹ ² ³). `logbook cites` maps a number back to the note, a link to the commit or pull request (GitHub, GitLab, Bitbucket, or a `commit_url` template in the config), the author and the date. Links and names are given only for notes a teammate shared; your own and private notes get none. A shared note with no commit reads "Note added by <name> on <date>".
- The repo is a tree you can walk: `repo` > `branch:<name>` > `commit:<sha>` > `note:<id>`. `logbook ask <address>` opens a node with its path from the root, its summary and what is below it; injected notes name their node. See `docs/SUMMARY-TREE.md`.
- A note written before its branch had a commit now follows a squash merge once the branch is gone (same files, first PR-numbered commit after the branch point); the rung says so.
- `wip`, `fixup!`, `squash!` and `amend!` commits are folded out of `logbook log` like chores.
- The skill says where a note belongs: long research on the branch, a short note on each commit.
- Seven commands to learn: `setup`, `note`, `publish`, `sync`, `ask`, `log`, `status`. `ask` takes a revision range, an id, a file or name, or free text. `log` shows the notes next to your commits in the terminal. `status --check` and `--stats` fold in `doctor` and `stats`. Every older name (`init`, `join`, `install`, `query`, `explain`, `path`, `doctor`, `queue`, `stats`, and the hook entry points) still runs, so existing installs keep working; they are just not listed in `--help`.
- Removed the browser viewer (`logbook serve`, `demo --serve`). It lives on the `viewer` branch.
- One shared shelf per person instead of one per clone. Two machines of the same person merge on `sync`. Old per-device refs are still read and are folded into the shelf on the next publish or sync (the old names are deleted on the remote after the push).
- `logbook publish` moves the note: the private copy is removed once the shared copy exists (`--keep` leaves it). It skips a note that is already shared, and one whose text a teammate already shared (`--force` overrides). With no ids it lists your unshared notes and asks which.
- The pre-push hook now pushes your published notes with the push (it never blocks, times out after 20 s, and only sends what you published). `logbook install` also adds the fetch setting so a plain `git pull` brings teammates' notes.
- Names are shown by default (`attribution: named`). A person can set `pseudonym`, and a repo's `.logbook/policy.json` can cap it.

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
