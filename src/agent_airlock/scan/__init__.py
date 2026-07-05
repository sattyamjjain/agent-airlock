"""Static contract / type-checker for MCP tool declarations.

``airlock scan-tools`` reads a set of MCP tool definitions and statically checks
each tool's declared contract against a least-privilege
:class:`~agent_airlock.policy.SecurityPolicy`. It is a *type-checker for AI tool
calls* — distinct from the runtime ``@Airlock`` decorator, and distinct from
content-signature tool-poisoning scanners (MCP-Scan, eSentire MCP-Scanner).

Public API:

* :func:`~agent_airlock.scan.contract.scan_tool` / :func:`scan_tools` — the checker.
* :func:`~agent_airlock.scan.loaders.load_tool_defs` — load tool defs from files/dirs.
* :func:`resolve_policy` — map a CLI policy name to a shipped ``SecurityPolicy``.
"""

from __future__ import annotations

from ..policy import (
    CAMOUFLAGE_RESISTANT_POLICY,
    PERMISSIVE_POLICY,
    READ_ONLY_POLICY,
    STRICT_POLICY,
    SecurityPolicy,
)
from .contract import (
    ContractViolation,
    Grade,
    ScanReport,
    ToolScanResult,
    infer_required_capability,
    scan_tool,
    scan_tools,
)
from .loaders import LoadedTools, load_tool_defs

__all__ = [
    "Grade",
    "ContractViolation",
    "ToolScanResult",
    "ScanReport",
    "scan_tool",
    "scan_tools",
    "infer_required_capability",
    "LoadedTools",
    "load_tool_defs",
    "resolve_policy",
    "POLICY_CHOICES",
]

# CLI policy name → shipped SecurityPolicy. No invented policies: each maps to a
# constant already exported from ``agent_airlock.policy``.
#   permissive       — allow all; only contract/type/trust checks bite.
#   read-only        — read_* allowed, write_*/delete_* denied (SCAN001).
#   strict           — STRICT capability caps: shell/delete denied, write not
#                      granted, DANGEROUS requires sandbox (SCAN006/SCAN007).
#   deny-by-default  — empty allowlist + default_deny: every tool must be opted
#                      in by name (maximal posture; everything fails SCAN001).
_POLICY_MAP: dict[str, SecurityPolicy] = {
    "permissive": PERMISSIVE_POLICY,
    "read-only": READ_ONLY_POLICY,
    "strict": STRICT_POLICY,
    "deny-by-default": CAMOUFLAGE_RESISTANT_POLICY,
}

POLICY_CHOICES: tuple[str, ...] = tuple(_POLICY_MAP)


def resolve_policy(name: str) -> SecurityPolicy:
    """Resolve a CLI policy name to a shipped :class:`SecurityPolicy`.

    Args:
        name: One of :data:`POLICY_CHOICES`.

    Raises:
        KeyError: If ``name`` is not a known policy choice.
    """
    key = name.strip().lower()
    if key not in _POLICY_MAP:
        raise KeyError(f"unknown policy '{name}'; choose from {', '.join(POLICY_CHOICES)}")
    return _POLICY_MAP[key]
