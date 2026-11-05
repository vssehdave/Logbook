# Logbook

Commit-anchored shared memory for AI-assisted repos. It records **why** code changed
(what was wrong, how wrong, the fix) next to the git history, and keeps findings that never became a commit, so a
teammate or an AI agent can pick up where the last person left off. It works for any repo and knows nothing about any
particular stack.

- Python 3.10+, **standard library only**, git 2.31+. Windows, macOS, Linux. No server to host, and no key: the optional observer uses your own `claude -p`.
  The agent writes the notes; the observer and `logbook log` ask a cheap model to condense them.
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

One command starts the repo, fetches teammates' notes when there is a remote, chains a git post-commit hook and a pre-push hook (it only reminds
you of unshared notes, never blocks a push and never sends notes: `logbook sync` does), and for each agent it finds writes that agent's hooks, an
always-on rules block and, for Claude Code, a skill (`.claude/skills/logbook/SKILL.md`). Every file it edits is backed up first to
`.git/logbook/backups`, written atomically (through symlinks, keeping line endings), and changed only between its own markers.
`--agent claude-code agents-md copilot gemini cursor` picks agents; otherwise it looks for `.claude`, `AGENTS.md`,
`.github/copilot-instructions.md`, `GEMINI.md` and `.cursor`. `logbook status --check` shows what is installed.

## The Bibliography band (Claude Code only, optional)

    /plugin install logbook --marketplace vssehdave/Logbook

A row above the prompt, always there: **bibliography**, then a dot shaded by the mode (light grey manual, pale yellow ask, darker yellow auto) and the mode's name, which does what **details** does, then how many sources this chat has cited (in grey), a finder on the right, and
**details** (it reads **compact** while the details are showing). Under it, the sources cited so far, as `¹ title` buttons that fit the width (`+N more` when they do
not). With details on, the mode selector (`manual  [ ask ]  auto`, each a button that changes the mode, the chosen one in light yellow) sits right after the underlined "bibliography" text (the dot and the count are hidden meanwhile), a rule closes the header, and a note a teammate shared also shows its commit or pull request header as a link (set `commit_url` and `pr_url` in
`.git/logbook/config.json` for a host Logbook does not know), who wrote it and when ("Note added by
<name> on <date>" when it has no commit). Your own and private notes stay one line. When there are more rows than the band may take, the
band scrolls (mouse wheel, or the keys while it is focused) and says how many are hidden.

Click `¹` and a peek appears under the header: the words around that citation in the closest answer that cites it, the latest. The finder
on the right shows the number and `x/y` (this is the xth of y answers that cite it, counted over the whole chat); up goes to
an earlier answer, down to a later one. Click the peek and the chat scrolls to that answer. The engine only lets a mod scroll the chat in
answer to your own click. The band finds the answers by asking `logbook cites --where N`, which reads Claude Code's transcript of the chat, so
it works for every answer and survives reloads; the jump uses the transcript row's id. Nothing can be typed into the finder. The band keeps the chat's sources until `/clear`, which starts the numbering again. Other agents get the same numbers in
the answer and `logbook cites` for the list. It needs the `logbook` command on your PATH. Checked with `claude plugin validate` and
`claude plugin test` and, for the first version, in a live session; scrolling the chat to a citation and the finder are new and
unproven at narrow widths.

## Who wrote a note

A note is labelled `agent-written` only when it is written from inside an agent's session (Claude Code is recognised by the session id in the
environment of the commands it runs), and `user-written` when a person writes it in their own terminal. For another agent, or a person using an
agent's shell, set `LOGBOOK_WRITER=agent` or `LOGBOOK_WRITER=user`. Notes from before this label was reliable show `origin unknown`.

## What the agent does

- **Before answering** a "why" question, or searching the code for a cause, it looks up `logbook ask`. Hooks also put
  the matching notes in front of it (see below).
- **While working** the observer records what it learns, per branch, in the background (next section). It writes a note itself only when you ask it to remember
  something, or for a root cause or decision that must be kept: `logbook note --fields <<'EOF' ... EOF` (summary, context, why, wrong, fix, decided, open, scale,
  paths). A note an agent writes is 3 to 9 lines and has an `evidence:` line (what it ran or read; naming a file is not enough); a one-line note is refused.
  The skill shows the shape and a good example. Nothing asks it to write a note for every task or every commit.
- **When the work is done** it saves a log (`logbook log`) in `auto` mode by itself, in `ask` mode after asking you (see Modes and savepoints).

## The observer (on by default, private)

Every tool use in a Claude Code session is queued by a hook, with no model call, in a **running log for the branch you are on** (`.git/logbook/running/`). A detached
process then reads the queue in batches and asks a cheap model (through your own `claude -p`, so no key is stored) what was learned, found, decided, built or fixed:
each answer is an observation with a type, a title, facts, a narrative, concepts and the files it read and changed. Routine work and anything already recorded is
skipped. A new branch starts from the main line's running log. Nothing here is shared, and `logbook config worker off` stops the collecting.

Cost is bounded: a daily call cap (`logbook config worker_calls`, default 120), a few calls per pass, and when the usage allowance runs out it waits an hour so it does
not compete with your own session. Its model call runs from an empty directory with settings, MCP servers and slash commands off, which keeps the fixed cost of a
call to a fraction of a cent. `logbook worker --status` shows what it has spent and what its last pass did; `logbook worker --drain` observes what is queued now.

## Modes and savepoints

`logbook log` is a **savepoint**. It first observes whatever tool uses are still queued, then summarizes the observations made on this branch since the last savepoint
(request, what was looked at, what was learned, what was done, next steps) and stores the result as a **private log** filed under the branch. The commit is optional: a
log carries one only when a commit was made since the last savepoint, so it can be saved before or after committing. The summary comes from the same cheap model as the
observations, or, with `--no-model` or no model available, is put together from the observations by code. The observations it covered move to
`.git/logbook/running/<branch>/archive/`; the ones a new branch inherited from the main line stay as context. The old view of notes next to commits is `logbook history`.

One setting, `logbook config publish`, decides how much happens by itself:

| mode | `logbook log` (savepoint) | `logbook publish` |
|---|---|---|
| `manual` | you run it | you run it |
| `ask` (default) | after a commit the agent asks you once, then runs it | the agent asks, shows the redacted preview, then runs it |
| `auto` | by itself, after a commit that follows 5 or more new observations, and when a session ends | when a branch looks merged, the agent is told at session start and runs `logbook publish --branch <name> --yes` |

**Publishing is by branch.** `logbook publish --branch <name>` moves every private log and note filed under that branch to the shared log (the usual redacted preview
and checks run first; what they refuse stays private). `logbook publish --merged` does that for every branch that looks merged into the main line. Git alone can see two
signs: a merge commit on the main line names the branch, or a commit one of the branch's own entries is anchored to is now in the main line's history. A squash merge
leaves neither, so in `ask` and `auto` mode the agent is told at session start which branches look merged, and, if it has the GitHub tools, can confirm a squashed pull
request there and run `logbook publish --branch` itself. Each record carries its own id and branch, so publishing at any moment is safe.

**Pulling.** `logbook setup` also adds git `post-merge` and `post-rewrite` hooks, so a `git pull` fetches the shared logs in the background (a pull-only sync: it never
pushes). `logbook tidy` does the same fetch first (`--no-sync` skips it). Nothing watches the remote between pulls.

The 0.0.4 names still work: `never` reads as `manual` and `claude` as `ask`. A repo policy that turns publishing off (`.logbook/policy.json`) still wins over every mode.

## What Claude may run without asking (Claude Code)

`logbook setup` adds one `PreToolUse` hook on Bash; it writes no allow rules. The hook answers for a command that is exactly one `logbook` command
line (plus a quoted heredoc for a note). A command with a second command, a pipe, a substitution or a redirect gets no answer from it, and Claude Code's
own prompt runs. `ask` lets that normal prompt run. The publish mode is the one in `logbook config publish`.

| command | decision |
|---|---|
| `note` | allow |
| `ask` | allow |
| `cites` | allow |
| `log` | allow |
| `status` | allow |
| `summarize` | allow |
| `tidy` | allow; `--apply` asks |
| `worker` | allow; `--drain` asks |
| `publish` | never: deny, manual: deny, ask: ask, auto: allow |
| `sync` | never: ask, manual: ask, ask: ask, auto: allow |
| `purge` | ask |
| `gc` | ask |
| `trust` | ask |
| `config` | ask |
| `setup` | ask |
| `uninstall` | ask |

Checked in a real `claude -p` session: a hook's `allow` runs a command that would otherwise be refused, `ask` and `deny` do not run it. Not checked: that
an interactive session skips the prompt on `allow`, and how a hook `allow` interacts with a `deny` rule of your own.

## Daily use

    logbook note --fields                     # the whole note as `key: value` lines on stdin: what an agent uses (no braces or quotes)
    logbook note --json                       # the same as a JSON object
    logbook note --kind finding --topic "late payments" --summary "revenue dip" --why "export stalled" --wrong "1 day under"
    logbook note --kind change --before-commit --summary "..." --why "..." --wrong "..." --fix "..."   # then commit as usual
    logbook note --commit <sha> --summary "..."   # a note about an earlier commit
    logbook publish <id>                      # preview + redaction, you confirm; evidence is opt-in
    logbook publish                           # lists your private notes that are not shared yet and asks which
    logbook publish --all                     # preview every one of them with redaction, confirm once
    logbook summarize                         # the notes under the repo or branch, for an agent to write a summary
    logbook sync                              # fetch teammates' entries, push yours
    logbook ask "refunds" | orders.py | <id> | main..HEAD   # exit 0 found, 3 ambiguous, 4 no match
    logbook ask repo | branch:<name> | commit:<sha> | note:<id>   # walk the tree from the top (docs/SUMMARY-TREE.md)
    logbook cites                             # the numbered sources behind an answer in this chat (links, names, dates)
    logbook log                               # save a log: summarize this branch's session since the last one (private until you publish)
    logbook history                           # the notes next to your commits, newest first (-v for their text)
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
