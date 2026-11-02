# Logbook

Commit-anchored shared memory for AI-assisted repos. It records **why** code and warehouse models changed
(what was wrong, how wrong, the fix) next to the git history, so a teammate or an AI agent can pick up where the
last person left off. Works for any repo; dbt-style repos get layer awareness (`stg_`, `int_`, `fct_`, `dim_`).

- Python 3.10+, **standard library only**, git 2.31+. Windows, macOS, Linux. No server to host, no model calls (`backend none`).
- Two logs: a **private** one under `.git/logbook/` (never tracked), and a **shared** one on git refs
  (`refs/logbook/log/<user>/<device>`, one writer per ref, so no merge conflicts). Sharing is opt-in per entry.
- A live local viewer (`logbook serve`) shows the shared tree with your private entries overlaid.

**Status: alpha (0.0.1).** The engine, git-ref storage, sharing and the viewer work and are tested on Linux, macOS and Windows.
Not built yet: nothing prompts an agent to write a note, so real reasons exist only when someone runs `logbook note`;
notes written on a branch before its first commit are not followed through a merge; there are no summaries above commits;
setup is three separate commands; Claude Code is the only host. Entries marked `inferred` are copied from the commit message
or a truncated transcript. They carry no reason and are never injected into an agent's prompt.

## Try it (no credentials, about 30 seconds)

    pip install getlogbook   # from a clone: pip install .   (or: PYTHONPATH=src python -m getlogbook ...)
                             # the command is `logbook`; the package name is getlogbook because `logbook` on PyPI is taken
    logbook demo           # Alice, Bob and a hostile Mallory on a scratch repo; every claim is checked
    logbook demo --serve   # same, then open the viewer on Bob's clone

## Daily use

    logbook init                              # once per clone (git config user.email must be set)
    logbook install-hook                      # git floor: copies each of your commits into an `inferred` entry (no reason)
    logbook install --agent claude-code --write   # merges hooks into .claude/settings.local.json (dry run without --write)
    logbook note --kind finding --topic "late payments" --summary "revenue dip" --why "export stalled" --wrong "1 day under"
    logbook note --kind change --before-commit --summary "..." --why "..." --wrong "..." --fix "..."   # then commit as usual
    logbook publish <id>                      # preview + redaction, you confirm; evidence is opt-in
    logbook sync                              # fetch teammates' entries, push yours
    logbook query "refunds" | explain fct_revenue | path <rev> <rev>   # exit 0 found, 3 ambiguous, 4 no match
    logbook serve --open
    logbook doctor                            # setup + what is NOT captured

New teammate: clone, then `logbook join`. A plain `git clone`/`git fetch` does not download logbook refs.
CI: `git fetch --depth=1 origin '+refs/logbook/log/*:refs/logbook-remote/origin/log/*'` (opt in; off by default).

## How an agent consults it first

Hooks (Claude Code is the only adapter shipped): `SessionStart` and `UserPromptSubmit` inject a digest of at most ~1,500
characters, only when the prompt names a known model or path, only from people who have commits on this history (or whom you
ran `logbook trust` on), only entries that say *why* or
*how wrong*, finding first, each labelled with author, provenance, age, commits behind HEAD and "verify first". Each note
is shown once per session. Agents without hooks: `logbook snippet` prints text for CLAUDE.md / AGENTS.md. Injection
guarantees the notes are in context, not that the model uses them.

## Safety defaults

- Entries from other writers are **untrusted data**: author comes from the ref path, never from the file; text is
  sanitised (links, code fences, instruction-like lines, angle brackets removed) before it reaches an agent, in `inject`
  and in CLI output; the viewer renders only with `textContent` under a strict CSP.
- Every entry is recorded, searchable and visible in the viewer. Trust only decides what is *automatically injected into an
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

See `docs/DESIGN.md` for decisions, the failure-mode table, and what is not built.
