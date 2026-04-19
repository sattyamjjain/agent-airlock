"""MCP STDIO command sanitizer — Ox Security advisory mitigation (v0.5.1+).

Disclosed 2026-04-16 by Ox Security (10+ CVEs including CVE-2026-30616):
the STDIO transport in the official Anthropic MCP SDKs passes the client-
supplied argv of a STDIO server entry straight to ``subprocess.Popen``
without sanitisation. Adversary-controlled entries in ``mcp.json`` /
``claude_desktop_config.json`` / ``~/.cursor`` therefore achieve RCE
before the MCP handshake even begins.

Anthropic's position (per The Register, 2026-04-16) is that sanitising
inputs is the application author's responsibility. This module is that
sanitiser: a deny-by-default validator that runs immediately before the
subprocess spawns.

Usage — direct::

    from agent_airlock.mcp_spec.stdio_guard import (
        validate_stdio_command,
        StdioInjectionError,
    )
    from agent_airlock.policy_presets import stdio_guard_ox_defaults

    try:
        validate_stdio_command(["uvx", "mcp-foo"], stdio_guard_ox_defaults())
    except StdioInjectionError:
        # refuse to spawn
        ...

Usage — via ``MCPProxyGuard``::

    guard = MCPProxyGuard(MCPProxyConfig(
        stdio_guard=stdio_guard_ox_defaults(),
    ))
    guard.validate_stdio_spawn(["uvx", "mcp-foo"])

References
----------
- Ox advisory:   https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem
- The Register:  https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/
- CVE-2026-30616: https://nvd.nist.gov/vuln/detail/CVE-2026-30616
"""

from __future__ import annotations

import os
import unicodedata
from typing import Any

import structlog

from ..exceptions import AirlockError
from ..policy import StdioGuardConfig

logger = structlog.get_logger("agent-airlock.mcp_spec.stdio_guard")

# Unicode categories we reject outright in argv. RTL/LTR overrides are
# the canonical visual-spoofing vector in supply-chain attacks
# (Trojan Source, CVE-2021-42574 family).
_BANNED_UNICODE_CODEPOINTS: frozenset[str] = frozenset(
    {
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    }
)


class StdioInjectionError(AirlockError):
    """Raised when an argv fails the STDIO command sanitiser."""

    def __init__(
        self,
        message: str,
        *,
        offending_arg: str | None = None,
        rule: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.offending_arg = offending_arg
        self.rule = rule
        self.details = details or {}
        super().__init__(message)


def _contains_banned_unicode(arg: str) -> str | None:
    """Return the first banned codepoint found in ``arg``, else ``None``."""
    for ch in arg:
        if ch in _BANNED_UNICODE_CODEPOINTS:
            return ch
        # Category "Cf" = Format characters; RTL overrides are in there, but
        # so are benign soft-hyphens etc. We only block the overrides above.
        if unicodedata.category(ch) == "Cc" and ch not in ("\t",):
            return ch
    return None


def _basename(path: str) -> str:
    """Return the trailing component of ``path`` (cross-platform)."""
    return os.path.basename(path) or path


def validate_stdio_command(cmd: list[str], config: StdioGuardConfig) -> None:
    """Validate an MCP STDIO argv before it reaches ``subprocess.Popen``.

    Args:
        cmd: The argv list. Must be a non-empty list of strings (matches
            ``subprocess.Popen(args=[...], shell=False)`` semantics — we
            deliberately refuse any shell-invocation form).
        config: ``StdioGuardConfig`` — typically
            ``stdio_guard_ox_defaults()`` from ``policy_presets``.

    Raises:
        StdioInjectionError: On any rule failure. ``rule`` attribute
            names the specific check that fired.
    """
    if not cmd:
        raise StdioInjectionError(
            "empty argv",
            rule="empty_argv",
        )
    if not all(isinstance(a, str) for a in cmd):
        raise StdioInjectionError(
            "non-string argv element",
            rule="non_string_argv",
        )

    binary = cmd[0]

    # Binary allowlist: either basename match, OR absolute path starts with
    # an allowed prefix.
    if os.path.isabs(binary):
        if not any(binary.startswith(p) for p in config.allowed_binary_prefixes):
            raise StdioInjectionError(
                f"absolute binary path '{binary}' is not under any allowed prefix",
                offending_arg=binary,
                rule="absolute_path_not_allowed",
                details={"allowed_prefixes": list(config.allowed_binary_prefixes)},
            )
    else:
        if config.allowed_binaries and _basename(binary) not in config.allowed_binaries:
            raise StdioInjectionError(
                f"binary '{binary}' is not in the allowlist",
                offending_arg=binary,
                rule="binary_not_allowlisted",
                details={"allowed_binaries": sorted(config.allowed_binaries)},
            )

    # Per-arg checks.
    for i, arg in enumerate(cmd):
        # Metacharacter check.
        if not config.allow_shell_metachars:
            for meta in config.metachars:
                if meta in arg:
                    raise StdioInjectionError(
                        f"argv[{i}] contains shell metacharacter {meta!r}",
                        offending_arg=arg,
                        rule="shell_metachar",
                        details={"metachar": meta, "index": i},
                    )

        # Unicode visual-spoofing / control-character check.
        bad = _contains_banned_unicode(arg)
        if bad is not None:
            raise StdioInjectionError(
                f"argv[{i}] contains banned unicode codepoint U+{ord(bad):04X}",
                offending_arg=arg,
                rule="banned_unicode",
                details={"codepoint": f"U+{ord(bad):04X}", "index": i},
            )

        # Deny-pattern check.
        for pattern in config.deny_patterns:
            if pattern.search(arg):
                raise StdioInjectionError(
                    f"argv[{i}] matches deny pattern {pattern.pattern!r}",
                    offending_arg=arg,
                    rule="deny_pattern",
                    details={"pattern": pattern.pattern, "index": i},
                )

    logger.debug(
        "stdio_command_validated",
        binary=binary,
        argc=len(cmd),
    )
