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
from collections.abc import Sequence
from dataclasses import dataclass, field

__all__ = ["HARNESSES", "Harness", "available_harnesses", "harness_by_name"]


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

    def is_available(self) -> bool:
        return shutil.which(self.executable) is not None

    def argv(self, prompt: str) -> list[str]:
        return [part.replace("{prompt}", prompt) for part in self.argv_template]


#: The harnesses this repo can drive. Every one is a real CLI with a documented
#: non-interactive mode; none is a stand-in or a mock.
HARNESSES: tuple[Harness, ...] = (
    Harness(
        name="claude-code",
        executable="claude",
        # -p is print/non-interactive. The permission mode must allow tool use or the
        # harness structurally cannot act, which would score a false 0%.
        argv_template=("claude", "-p", "{prompt}", "--permission-mode", "acceptEdits"),
        version_argv=("claude", "--version"),
        notes="Anthropic Claude Code CLI, print mode.",
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
    ),
)


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
