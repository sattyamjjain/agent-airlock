"""Which of a module's tools a policy names, and which it admits only by default (V0.10.29).

A ``SecurityPolicy`` with an empty ``allowed_tools`` and ``default_deny=False`` admits every
tool it does not deny, so a tool added to a codebase is admitted without anyone deciding to
admit it. ``airlock policy coverage`` and :func:`agent_airlock.testing.assert_policy_covers`
put each ``@Airlock`` tool in one class and fail on that last one, the way a CI job fails
on a route nobody classified (OpenHands/OpenHands#17055).

The classes follow :meth:`SecurityPolicy.check`'s order, read from the policy's fields: a
denial first, then the allowlist, then escalation, which is checked last because only an
otherwise-allowable call can be escalated. Nothing is called on the policy, so no rate-limit
token is spent. Roles, time windows and rate limits still apply at call time; coverage is
about whether a rule names the tool at all.
"""

from __future__ import annotations

import enum
import importlib
import pkgutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import ModuleType
from typing import Any

from .capabilities import _airlock_wrappers_beneath, _is_airlock_wrapper
from .policy import SecurityPolicy

__all__ = [
    "CoverageClass",
    "CoverageReport",
    "ToolCoverage",
    "airlock_tools",
    "classify_tool",
    "coverage_report",
]


class CoverageClass(str, enum.Enum):
    """How a policy treats one tool name."""

    ALLOWED_BY_NAME = "allowed_by_name"
    ALLOWED_BY_PATTERN = "allowed_by_pattern"
    DENIED = "denied"
    ESCALATED = "escalated"
    ADMITTED_BY_DEFAULT = "admitted_by_default"


@dataclass(frozen=True)
class ToolCoverage:
    """One tool's class under a policy, and the rule that put it there."""

    tool: str
    coverage: CoverageClass
    rule: str

    @property
    def covered(self) -> bool:
        """Whether a rule of the policy names the tool."""
        return self.coverage is not CoverageClass.ADMITTED_BY_DEFAULT


@dataclass(frozen=True)
class CoverageReport:
    """Every tool's class under one policy."""

    tools: tuple[ToolCoverage, ...]

    @property
    def uncovered(self) -> tuple[str, ...]:
        """The tools admitted only because the allowlist is empty."""
        return tuple(entry.tool for entry in self.tools if not entry.covered)

    @property
    def covered(self) -> bool:
        return not self.uncovered

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": [
                {"tool": e.tool, "class": e.coverage.value, "rule": e.rule} for e in self.tools
            ],
            "uncovered": list(self.uncovered),
        }


def _most_specific(patterns: list[str]) -> str:
    """The pattern that names a tool most closely: no wildcard, then the longest."""
    return max(patterns, key=lambda p: (p.count("*") == 0, len(p.replace("*", ""))))


def _allowlist_class(policy: SecurityPolicy, tool: str) -> ToolCoverage | None:
    """The allowlist's verdict, or None when the allowlist does not apply (empty, no
    ``default_deny``)."""
    if not policy.allowed_tools and not policy.default_deny:
        return None
    if tool in policy.allowed_tools:
        return ToolCoverage(tool, CoverageClass.ALLOWED_BY_NAME, f"allowed_tools: {tool}")
    matching = [p for p in policy.allowed_tools if policy._matches_pattern(tool, p)]
    if matching:
        rule = f"allowed_tools: {_most_specific(matching)}"
        return ToolCoverage(tool, CoverageClass.ALLOWED_BY_PATTERN, rule)
    if policy.allowed_tools:
        return ToolCoverage(tool, CoverageClass.DENIED, "not on allowed_tools")
    return ToolCoverage(tool, CoverageClass.DENIED, "default_deny with an empty allowed_tools")


def classify_tool(policy: SecurityPolicy, tool: str) -> ToolCoverage:
    """Put ``tool`` in one :class:`CoverageClass` under ``policy``."""
    for pattern in policy.denied_tools:
        if policy._matches_pattern(tool, pattern):
            return ToolCoverage(tool, CoverageClass.DENIED, f"denied_tools: {pattern}")
    allowed = _allowlist_class(policy, tool)
    if allowed is not None and allowed.coverage is CoverageClass.DENIED:
        return allowed
    escalations = [p for p in policy.escalate_tools if policy._matches_pattern(tool, p)]
    if escalations:
        rule = max(escalations, key=len)  # the rule check_escalation picks
        return ToolCoverage(tool, CoverageClass.ESCALATED, f"escalate_tools: {rule}")
    if allowed is not None:
        return allowed
    return ToolCoverage(
        tool, CoverageClass.ADMITTED_BY_DEFAULT, "no rule names it; allowed_tools is empty"
    )


def coverage_report(policy: SecurityPolicy, tools: Iterable[str]) -> CoverageReport:
    """Classify every tool name in ``tools`` (sorted, each once)."""
    return CoverageReport(tuple(classify_tool(policy, tool) for tool in sorted(set(tools))))


def _tool_name(candidate: Any) -> str | None:
    """The name ``@Airlock`` checks a tool's calls by, when ``candidate`` is one."""
    if not callable(candidate):
        return None
    if _is_airlock_wrapper(candidate):
        return str(candidate.__name__)
    beneath = _airlock_wrappers_beneath(candidate)
    return str(beneath[0].__name__) if beneath else None


def _modules(root: ModuleType) -> Iterable[ModuleType]:
    """``root`` and, for a package, every module under it, imported."""
    yield root
    path = getattr(root, "__path__", None)
    if path is None:
        return
    for info in pkgutil.walk_packages(path, prefix=f"{root.__name__}."):
        yield importlib.import_module(info.name)


def airlock_tools(module: ModuleType | str) -> dict[str, Callable[..., Any]]:
    """Every ``@Airlock`` tool at module level in ``module`` and, for a package, under it.

    A tool is a module attribute that is an ``@Airlock`` wrapper or has one beneath it
    (``@requires`` above ``@Airlock`` included), keyed by the name its calls are checked
    by. A tool imported into several modules counts once.

    Raises:
        ImportError: ``module``, or a module under it, cannot be imported.
    """
    root = importlib.import_module(module) if isinstance(module, str) else module
    found: dict[str, Callable[..., Any]] = {}
    for loaded in _modules(root):
        for value in vars(loaded).values():
            name = _tool_name(value)
            if name is not None:
                found.setdefault(name, value)
    return found
