"""Coding-harness drivers.

Each harness is driven in its **non-interactive / print** mode with tool access enabled,
because a harness that cannot run a shell command cannot act on the injected line, and a
run with tools disabled would score a misleading 0% for every harness.

Invocations are built from each CLI's documented non-interactive flags. Availability is
probed rather than assumed, so a machine missing a harness reports it as *not run* instead
of silently shrinking the sample.
"""

from __future__ import annotations

import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

__all__ = [
    "HARNESSES",
    "SESSION_ENV_KEEP",
    "SESSION_ENV_REMOVE",
    "Harness",
    "available_harnesses",
    "harness_by_name",
    "harness_env",
    "removed_env_names",
]

#: Removed from every harness's environment; a trailing ``*`` is a prefix. A harness run
#: from inside a Claude Code session inherits that session's variables: an
#: ``ANTHROPIC_API_KEY`` would bill the run to API credit instead of the CLI's own login,
#: ``ANTHROPIC_BASE_URL`` would reroute it, and ``CLAUDECODE`` / ``CLAUDE_CODE_*`` would
#: tell the child it is nested inside another session.
SESSION_ENV_REMOVE: tuple[str, ...] = (
    "ANTHROPIC_*",
    "CLAUDECODE",
    "CLAUDE_CODE_*",
    "CLAUDE_EFFORT",
    "CLAUDE_PID",
    "ENABLE_TOOL_SEARCH",
    "ENABLE_LSP_TOOL",
    "MAX_THINKING_TOKENS",
)

#: Kept although a pattern above matches it: the CLI's own subscription login.
SESSION_ENV_KEEP: tuple[str, ...] = ("CLAUDE_CODE_OAUTH_TOKEN",)


@dataclass(frozen=True)
class Harness:
    """One coding harness under test."""

    name: str
    executable: str
    argv_template: tuple[str, ...]
    """``{prompt}`` is substituted with the task prompt."""
    version_argv: tuple[str, ...] = ()
    notes: str = ""
    env: dict[str, str] = field(default_factory=dict)
    """Set in the harness's environment after :attr:`env_remove` is applied."""
    model_argv: tuple[str, ...] = ()
    """Inserted before ``{prompt}`` when a model is pinned; ``{model}`` is substituted.

    A run on the CLI's configured default model is only comparable while that default holds.
    On 2026-10-03 this machine's codex default (``gpt-6.1-sol``) was refused for a ChatGPT
    account, every codex cell exited 1 before it started, and the run looked like 0/72
    complete. Pinning the model the previous run used makes a re-run like-for-like.
    """
    env_remove: tuple[str, ...] = SESSION_ENV_REMOVE
    """Variables removed from the inherited environment (``*`` suffix = prefix)."""
    auth_argv: tuple[str, ...] = ()
    """Prints the CLI's login state as JSON; empty when the harness has no such command."""
    expected_auth: str = ""
    """The auth method a paid run must use (``claude.ai`` for a subscription login).
    Any other recorded method skips the harness unless ``--allow-any-auth`` is passed."""
    stdout_json: bool = False
    """The CLI prints a JSON result whose model usage and cost are recorded per cell."""
    requires_model: bool = False
    """``--run`` refuses to start until this harness's model is pinned with ``--model``."""

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def argv(self, prompt: str, model: str = "") -> list[str]:
        if model and (not self.model_argv or "{prompt}" not in self.argv_template):
            raise ValueError(f"harness {self.name!r} has no model flag to pin {model!r} with")
        parts: list[str] = []
        for part in self.argv_template:
            if part == "{prompt}" and model:
                parts.extend(arg.replace("{model}", model) for arg in self.model_argv)
            parts.append(part.replace("{prompt}", prompt))
        return parts


#: The harnesses this repo can drive. Every one is a real CLI with a documented
#: non-interactive mode; none is a stand-in or a mock.
HARNESSES: tuple[Harness, ...] = (
    Harness(
        name="claude-code",
        executable="claude",
        # -p is print/non-interactive. The permission mode must allow tool use or the
        # harness structurally cannot act, which would score a false 0%. The JSON result
        # names the models that ran and the cost, recorded per cell.
        argv_template=(
            "claude",
            "-p",
            "{prompt}",
            "--permission-mode",
            "acceptEdits",
            "--output-format",
            "json",
        ),
        version_argv=("claude", "--version"),
        notes="Anthropic Claude Code CLI, print mode.",
        model_argv=("--model", "{model}"),
        auth_argv=("claude", "auth", "status", "--json"),
        expected_auth="claude.ai",
        stdout_json=True,
        # The 2026-10-03 run used the CLI's default and recorded neither its model nor
        # its auth, so it cannot be reproduced like-for-like. A paid run pins both.
        requires_model=True,
    ),
    Harness(
        name="cursor-agent",
        executable="cursor-agent",
        # --force allows commands unless explicitly denied; without it the agent cannot
        # run the planted script and the cell is unmeasurable.
        argv_template=(
            "cursor-agent",
            "-p",
            "{prompt}",
            "--output-format",
            "text",
            "--force",
        ),
        version_argv=("cursor-agent", "--version"),
        notes="Cursor Agent CLI, print mode with commands force-allowed.",
        model_argv=("--model", "{model}"),
    ),
    Harness(
        name="codex",
        executable="codex",
        # --skip-git-repo-check keeps the run working even if the fixture is not a git
        # repo; the fixture initialises one anyway, so this is belt-and-braces.
        #
        # --sandbox workspace-write is REQUIRED, not a tuning knob. `codex exec` defaults to
        # a read-only sandbox: verified empirically, a default-sandbox codex asked to change
        # `x = 1` to `x = 2` left the file untouched, while the same call with
        # workspace-write applied the edit. Without this flag codex cannot edit or run
        # anything, so every cell scores a structurally meaningless 0 — which is exactly what
        # the 2026-08-14 and 2026-08-15 runs recorded before this was found.
        argv_template=(
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--sandbox",
            "workspace-write",
            "{prompt}",
        ),
        version_argv=("codex", "--version"),
        notes="OpenAI Codex CLI, `codex exec` non-interactive, workspace-write sandbox.",
        model_argv=("-m", "{model}"),
    ),
)


def _removes(name: str, patterns: Sequence[str]) -> bool:
    if name in SESSION_ENV_KEEP:
        return False
    return any(
        name.startswith(pattern[:-1]) if pattern.endswith("*") else name == pattern
        for pattern in patterns
    )


def removed_env_names(harness: Harness, base: Mapping[str, str]) -> list[str]:
    """The names of the variables in ``base`` that :func:`harness_env` drops, sorted."""
    return sorted(name for name in base if _removes(name, harness.env_remove))


def harness_env(harness: Harness, base: Mapping[str, str]) -> dict[str, str]:
    """``base`` without the harness's :attr:`~Harness.env_remove` names, plus its ``env``."""
    env = {name: value for name, value in base.items() if not _removes(name, harness.env_remove)}
    env.update(harness.env)
    return env


def available_harnesses() -> tuple[Harness, ...]:
    return tuple(harness for harness in HARNESSES if harness.is_available())


def harness_by_name(name: str) -> Harness:
    for harness in HARNESSES:
        if harness.name == name:
            return harness
    known = ", ".join(harness.name for harness in HARNESSES)
    raise KeyError(f"unknown harness {name!r}; known: {known}")


def resolve(names: Sequence[str] | None) -> tuple[Harness, ...]:
    """Resolve ``names`` (or every available harness when ``None``)."""
    if not names:
        return available_harnesses()
    return tuple(harness_by_name(name) for name in names)
