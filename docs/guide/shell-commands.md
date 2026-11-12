# Shell commands

Since 0.10.29 a `ShellCommandPolicy` decides what an agent's shell tool may run: allow,
ask, or deny, by rule. Until then nothing judged the command beyond `ToolArgSinkGuard`'s
metacharacter screen, and an allowlist of the first word lets `env rm -rf /` through,
since `env` is harmless on its own.

```python
from agent_airlock import Airlock
from agent_airlock.policy_presets import shell_command_defaults


@Airlock(policy=shell_command_defaults()["policy"])
def run_shell(command: str) -> str:
    ...
```

## The preset

`shell_command_defaults()`:

| | Commands |
| --- | --- |
| allow | `git status`, `git log`, `git diff`, `rg`, `ls`, `cat` |
| ask | `git push`, `git commit`, `sudo`, `doas` |
| deny | a recursive `rm`, a force push (`--force`, `-f`, a `+refspec`), `find -delete`, `rg --pre` |
| refused whatever the rules say | a shell or interpreter reading its program from a pipe (`curl ... \| sh`), and the rest of what the policy cannot follow (below) |

Anything else gets `default`, `ask` in the preset: the policy's approver decides, and with
no approver registered the call is refused. `rg --pre` is denied because it runs a command
on every file it searches.

## How a command is read

The command is split into words the way POSIX `sh` reads quoting, never by running a
shell: `echo 'a; rm -rf /'` is one command, and `ls; rm -rf /` is two. A line is split at
`;`, `&&`, `||`, `|`, `&` and newlines, a `#` comment is dropped, and redirections are not
words. Every command of the line is judged.

Wrappers are followed to the command they launch, and both are judged:

| Wrapper | What it launches |
| --- | --- |
| `env`, `nohup`, `timeout`, `nice`, `ionice`, `stdbuf`, `setsid`, `chroot`, `busybox`, `sudo`, `doas` | the command after their own options |
| `xargs` | its command (`echo` when it has none) |
| `find -exec`, `-execdir`, `-ok`, `-okdir` | each command up to its `;` or `+` |
| `sh -c`, `bash -c`, `zsh -c` and the other shells; `watch` | the line they run |
| `python -m mod` | `mod`, as a command |
| `git -c key=value` | for a key that names a command (`core.sshCommand`, `core.pager`, `credential.helper`, ...), that command |

`git`'s global options (`-C dir`, `--no-pager`) are skipped, so a rule for `git status`
matches `git -C repo status`. A program is matched by its name only when it is a bare name
or sits in a system directory (`/usr/bin/git`): `./git` is not `git`.

What the policy cannot follow is refused, whatever the rules say:

- command or process substitution (`$(...)`, backticks, `<(...)`, `>(...)`) where the
  shell performs it: unquoted, inside double quotes, in a line with a heredoc (`<<`), in
  the text a followed wrapper runs (`bash -c`, `sudo -s`, `watch`, `find -exec sh -c`,
  a `git -c` command key), and in the arguments of a program that runs them as shell
  text (`eval`, `trap`, `alias`, `su`, `runuser`, `sg`, `ssh`, `script`, `flock`, `tmux`,
  `screen`, `parallel`, or a shell named later in a command the policy does not follow,
  such as `docker exec c sh -c`), and in a comment. Single-quoted text is text, as it is
  to the shell, so `` grep '`' a.txt `` and `` sed -n '/`/p' a.txt `` are judged by the
  rules like any other command;
- inline code: `python -c`, `node -e`, `perl -e` and `-c`, `ruby -e`;
- a shell or interpreter with no program to read but stdin or a terminal: `sh` in a pipe,
  `bash -s`, `sudo -i`, `doas -s`, `chroot` with no command;
- an option a wrapper's parser does not know, since guessing could take the command for
  an option's value;
- setting a variable that changes which program runs or how it loads (`PATH`,
  `LD_PRELOAD`, `PYTHONPATH`, any `GIT_*`), as `NAME=value cmd` or through `env`;
- `git --config-env`, `--exec-path=`, an alias or `include.path` set with `-c`, and any
  `-c` key the policy does not know to be harmless.

A script file is different: `bash scripts/test.sh` is the shell running that file, and the
rules judge it as written.

## Rules

A rule is words, then options: `git push --force` matches a command whose program is
`git` and whose next word is `push`, with `--force` anywhere after. Each part is a
case-sensitive glob. A part starting with `-` or `+` may sit anywhere after the words, and
a rule cannot put a word after an option, so it cannot name an option's value.

- A `deny` rule matching any command of the line refuses it. That includes a wrapper, a
  command it launches, and a command an unknown wrapper puts later in the line, such as
  `strace rm -rf /`. A denial depends only on the command, so a retry, or an approver who
  would say yes, gets the same answer.
- An `ask` rule escalates to the policy's `approver` (rule `shell_command`). With none
  registered, the call is refused as `escalation_required`.
- Otherwise every innermost command must match an `allow` rule, or be named by an `ask`
  rule. Anything else gets `default`.

A line with a `$` expansion outside single quotes (`ls $HOME`) is allowed by no rule,
since the shell decides its words later: an `ask` rule naming it, or `default`, decides.

The refusal names the program, never the rule or the whole command: `policy_violation`
with `violation_type` `shell_command_denied`, or `shell_command_unanalyzable` saying what
could not be followed. The decision record's layer is `2.77:shell_command`.

## Settings

| Setting | Default | |
| --- | --- | --- |
| `allow`, `ask`, `deny` | `()` | rule strings |
| `default` | `"deny"` | the verdict for an innermost command no rule names |
| `command_args` | `("command", "cmd")` | the arguments holding the command: a string is a shell line, a list of strings one command's argv |
| `tools` | `()` | tool-name globs to apply it to; empty means every tool with one of `command_args` |

## With the argument screen

`ShellCommandPolicy` reads pipelines and lists. `ToolArgSinkGuard` (step 2.75) refuses
shell metacharacters in an argument outright. With both on, the screen runs first, so
`ls; git status` is refused as `tool_arg_sink` even though the policy would allow each
command.

## What it does not see

- A repository's own config: an alias, pager or hook defined in `.git/config` runs
  whatever it names. Only the command line is read.
- What a program does with its input. An `allow` rule for an interpreter
  (`python *`) admits any script it runs.
- A wrapper not in the table is judged as the command itself. Only `deny` and `ask` rules
  look past it.
