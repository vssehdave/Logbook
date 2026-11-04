"""Which `logbook` commands Claude may run without asking, decided by a PreToolUse hook on Bash from the publish mode and the subcommand.

One table, no allow rules written into the person's settings. A command this module does not fully understand gets no opinion (Claude Code's own
prompt runs as usual): it must be one plain command line, optionally followed by a quoted heredoc that closes on the last line. Anything with a
shell operator, substitution, redirect or a second command in it is not ours to wave through.
"""
from __future__ import annotations

import json
import re
import shlex

# subcommand -> decision. "mode" means: follow the publish mode (see `decide`). Not listed: no opinion.
TABLE = {
    "note": "allow", "ask": "allow", "context": "allow", "cites": "allow", "log": "allow", "status": "allow", "summarize": "allow", "backfill": "allow",
    "publish": "mode", "sync": "mode",
    "purge": "ask", "gc": "ask", "trust": "ask", "config": "ask", "setup": "ask", "uninstall": "ask",
}
# publish: never denies, ask lets the normal prompt run, claude and auto allow. sync: allow only in auto mode, else ask.
MODE_RULES = {"publish": {"never": "deny", "ask": "ask", "claude": "allow", "auto": "allow"},
              "sync": {"never": "ask", "ask": "ask", "claude": "ask", "auto": "allow"}}
NAMES = ("logbook", "getlogbook")
_HEREDOC = re.compile(r"\s<<-?\s*'([A-Za-z_][A-Za-z0-9_]*)'\s*$")
_SHELL = re.compile(r"[;&|$`<>(){}\\\n]")  # shortcut: any of these anywhere in the command line, even inside quotes, means no opinion; upgrade if it bites


def subcommand(command):
    """The logbook subcommand of a Bash command that is exactly one logbook command line (plus an optional quoted heredoc), else ''."""
    lines = command.strip().split("\n")
    first = lines[0]
    m = _HEREDOC.search(first)
    if m:
        tag = m.group(1)
        if len(lines) < 2 or lines[-1].strip() != tag or sum(1 for ln in lines[1:] if ln.strip() == tag) != 1:  # it must close once, on the last line
            return ""
        first = first[:m.start()]
    elif len(lines) > 1:
        return ""
    if _SHELL.search(first):
        return ""
    try:
        args = shlex.split(first)
    except ValueError:
        return ""
    if len(args) < 2 or args[0].lower().removesuffix(".exe") not in NAMES or args[1].startswith("-"):
        return ""
    return args[1]


def decide(command, mode):
    """(decision, reason) for a command, or None for no opinion. decision is allow, ask or deny."""
    sub = subcommand(command)
    rule = TABLE.get(sub)
    if not rule:
        return None
    if rule == "mode":
        rule = MODE_RULES[sub].get(mode, "ask")
        return rule, f"logbook {sub} with publish mode {mode}"
    return rule, f"logbook {sub}: {'private and local' if rule == 'allow' else 'changes what is shared or kept, so it asks'}"


def hook_output(command, mode):
    """The PreToolUse hook's stdout for a Bash command, or '' for no opinion."""
    d = decide(command, mode)
    if not d:
        return ""
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": d[0], "permissionDecisionReason": d[1]}})


def readme_table():
    """The table as markdown, so the README can show exactly what the code does."""
    rows = ["| command | decision |", "|---|---|"]
    for sub, rule in TABLE.items():
        if rule == "mode":
            rule = ", ".join(f"{m}: {d}" for m, d in MODE_RULES[sub].items())
        rows.append(f"| `{sub}` | {rule} |")
    return "\n".join(rows)
