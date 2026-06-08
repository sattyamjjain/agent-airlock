"""MCP server-config env-interpolation guard (v0.8.20+, CVE-2026-32625 anchor).

CVE-2026-32625 (LibreChat ≤ 0.8.3, CVSS 9.6, CWE-200, published
2026-06-02): the MCP server integration resolves ``${VAR}`` placeholders
in a **user-supplied** MCP server URL against the host process's
``process.env`` during schema validation. An authenticated user
configures an MCP server whose URL embeds references to server-side
secrets (``${JWT_SECRET}``, ``${CREDS_KEY}``, ``${MONGO_URI}``, ...);
the placeholders are expanded **server-side** and the resolved secret is
sent in the outbound connection to an attacker-controlled host — full
compromise of cryptographic material + DB credentials with no admin
privilege. Patched in 0.8.4-rc1.

The exploit class is **not** LibreChat-specific: any host that expands
shell-style env interpolation in a user-controlled MCP connection
template (URL, header value, or command/arg) before dialing out has the
same secret-exfiltration primitive. This guard is the reusable,
CVE-agnostic primitive.

What it inspects
----------------
Every string in the connection config — the URL, each header value, and
each command/arg element — for env-interpolation tokens:

- ``${VAR}`` / ``${VAR:-default}`` (POSIX brace form),
- bare ``$VAR`` (unescaped POSIX form),
- ``%VAR%`` (Windows ``cmd`` form).

Deny-by-default posture
-----------------------
Any interpolation token is denied **unless** the referenced variable is
on an operator-declared ``allowed_vars`` allowlist of explicitly
non-secret variables. An empty allowlist (the default) denies every
interpolation token — the safe default for the CVE class, where the
whole point is that the host must not expand *any* env var into a
user-controlled outbound template.

Why structural (no env expansion)
---------------------------------
The guard never reads ``os.environ`` and never expands anything — it
matches the interpolation *tokens* and refuses them. It therefore cannot
itself leak a secret, and it works identically regardless of which
variables happen to be set on the host.

Primary sources (retrieved 2026-06-08):
  https://github.com/danny-avila/LibreChat/security/advisories/GHSA-6vqg-rgpm-qvf9
  https://www.thehackerwire.com/librechat-critical-credential-disclosure-via-mcp-server-url/
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.env_interpolation_guard")


# ``${VAR}`` and ``${VAR:-default}`` / ``${VAR:?err}`` — capture the name.
_DOLLAR_BRACE_RE = re.compile(r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\b")
# Bare ``$VAR`` NOT part of a ``${...}`` and NOT escaped as ``\$`` or ``$$``.
_BARE_DOLLAR_RE = re.compile(r"(?<![\\$])\$([A-Za-z_][A-Za-z0-9_]*)\b")
# Windows ``%VAR%`` form.
_PERCENT_RE = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")

# Connection-config keys whose string values carry an outbound template.
_DEFAULT_SCANNED_KEYS: tuple[str, ...] = ("url", "uri", "endpoint", "headers", "args", "command")


class MCPEnvInterpolationVerdict(str, enum.Enum):
    """Stable reason codes for :class:`MCPEnvInterpolationDecision`."""

    ALLOW = "allow"
    DENY_DOLLAR_BRACE = "deny_dollar_brace"  # ${VAR}
    DENY_BARE_DOLLAR = "deny_bare_dollar"  # $VAR
    DENY_PERCENT = "deny_percent"  # %VAR%


@dataclass(frozen=True)
class MCPEnvInterpolationDecision:
    """Outcome of a single :meth:`MCPServerEnvInterpolationGuard.evaluate` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — every guard
    exposes ``allowed: bool`` so integrators can chain on one
    short-circuit predicate.

    Attributes:
        allowed: True iff no disallowed interpolation token was found.
        verdict: A stable :class:`MCPEnvInterpolationVerdict` value.
        detail: Free-form human-readable explanation.
        matched_field: The config field (e.g. ``"url"`` or
            ``"headers.Authorization"``) that tripped the guard, or
            ``None`` when allowed.
        matched_token: The literal interpolation token (e.g.
            ``"${JWT_SECRET}"``), or ``None`` when allowed.
        matched_var: The referenced variable name (e.g. ``"JWT_SECRET"``),
            or ``None`` when allowed.
        fix_hints: LLM-actionable remediation hints. Carries the advisory
            / CVE reference when the guard was constructed with one.
    """

    allowed: bool
    verdict: MCPEnvInterpolationVerdict
    detail: str
    matched_field: str | None = None
    matched_token: str | None = None
    matched_var: str | None = None
    fix_hints: list[str] = field(default_factory=list)


class MCPServerEnvInterpolationError(AirlockError):
    """Raised on a denied MCP server connection config (fail-closed).

    Carries the :class:`MCPEnvInterpolationDecision` and exposes
    ``fix_hints`` so an upstream airlock layer can route the refusal into
    self-healing retry semantics.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: LLM-actionable remediation hints.
    """

    def __init__(self, decision: MCPEnvInterpolationDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


class MCPServerEnvInterpolationGuard:
    """Deny-by-default gate on env-interpolation tokens in MCP server configs.

    Refuses any MCP server URL / header / command-arg template that
    contains a ``${VAR}`` / ``$VAR`` / ``%VAR%`` interpolation token,
    unless the referenced variable is on an operator-declared allowlist
    of explicitly non-secret variables. This blocks the CVE-2026-32625
    class, where a user-controlled connection template is expanded
    server-side and leaks a host secret into an outbound request.

    Args:
        allowed_vars: Variable names that MAY appear in an interpolation
            token (e.g. a non-secret ``REGION`` or ``API_VERSION``).
            Empty (default) denies every interpolation token.
        scanned_keys: Connection-config keys whose string values are
            scanned. Defaults to :data:`_DEFAULT_SCANNED_KEYS`.
        advisory: Optional advisory / CVE id (e.g. ``"CVE-2026-32625"``)
            surfaced in every deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.

    Raises:
        TypeError: ``allowed_vars`` is a bare ``str`` (a footgun that
            would be iterated character-by-character).
    """

    def __init__(
        self,
        *,
        allowed_vars: Iterable[str] | None = None,
        scanned_keys: tuple[str, ...] = _DEFAULT_SCANNED_KEYS,
        advisory: str | None = None,
        advisory_url: str | None = None,
    ) -> None:
        if isinstance(allowed_vars, str):
            raise TypeError(
                f"allowed_vars must be an iterable of str, not a bare str: {allowed_vars!r}"
            )
        self._allowed_vars: frozenset[str] = frozenset(allowed_vars or ())
        self._scanned_keys = scanned_keys
        self._advisory = advisory
        self._advisory_url = advisory_url

    def evaluate(self, config: Mapping[str, Any] | str | None) -> MCPEnvInterpolationDecision:
        """Decide whether a connection config carries a disallowed interpolation.

        Args:
            config: An MCP server URL string, or a connection-config
                mapping (``url`` / ``headers`` / ``args`` / ...).
                ``None`` = nothing to inspect = allow.

        Returns:
            :class:`MCPEnvInterpolationDecision`. ``allowed=False`` maps
            to a refusal at the registration / dial-out boundary.
        """
        if config is None:
            return self._allow()

        if isinstance(config, str):
            return self._scan_field("url", config)

        for key in self._scanned_keys:
            if key not in config:
                continue
            decision = self._scan_value(key, config[key])
            if not decision.allowed:
                return decision

        return self._allow()

    # -- internal helpers --------------------------------------------------

    def _scan_value(self, field_name: str, value: Any) -> MCPEnvInterpolationDecision:
        """Recursively scan a config value (str / list / dict) for tokens."""
        if isinstance(value, str):
            return self._scan_field(field_name, value)
        if isinstance(value, Mapping):
            for sub_key, sub_val in value.items():
                decision = self._scan_value(f"{field_name}.{sub_key}", sub_val)
                if not decision.allowed:
                    return decision
            return self._allow()
        if isinstance(value, (list, tuple)):
            for idx, item in enumerate(value):
                decision = self._scan_value(f"{field_name}[{idx}]", item)
                if not decision.allowed:
                    return decision
            return self._allow()
        return self._allow()

    def _scan_field(self, field_name: str, text: str) -> MCPEnvInterpolationDecision:
        """Scan a single string for the three interpolation forms."""
        for regex, verdict, render in (
            (_DOLLAR_BRACE_RE, MCPEnvInterpolationVerdict.DENY_DOLLAR_BRACE, "${{{}}}"),
            (_BARE_DOLLAR_RE, MCPEnvInterpolationVerdict.DENY_BARE_DOLLAR, "${}"),
            (_PERCENT_RE, MCPEnvInterpolationVerdict.DENY_PERCENT, "%{}%"),
        ):
            for match in regex.finditer(text):
                var = match.group(1)
                if var in self._allowed_vars:
                    continue
                token = render.format(var)
                return self._deny(verdict, field_name, token, var)
        return self._allow()

    def _allow(self) -> MCPEnvInterpolationDecision:
        return MCPEnvInterpolationDecision(
            allowed=True,
            verdict=MCPEnvInterpolationVerdict.ALLOW,
            detail="no disallowed env-interpolation token in connection config",
        )

    def _deny(
        self,
        verdict: MCPEnvInterpolationVerdict,
        field_name: str,
        token: str,
        var: str,
    ) -> MCPEnvInterpolationDecision:
        logger.warning(
            "mcp_env_interpolation_blocked",
            verdict=verdict.value,
            field=field_name,
            token=token,
            var=var,
            advisory=self._advisory,
        )
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints: list[str] = [
            f"{prefix}Connection config field {field_name!r} contains env-interpolation "
            f"token {token!r}, which would be expanded server-side and could leak the "
            f"value of {var!r} into the outbound request.",
            "Remove the interpolation token, or supply the resolved non-secret value "
            "literally. Never reference a server-side secret in a user-controlled "
            "MCP server URL/header.",
        ]
        if self._allowed_vars:
            hints.append(
                "Allowed (non-secret) variables for interpolation: "
                + ", ".join(sorted(self._allowed_vars))
            )
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return MCPEnvInterpolationDecision(
            allowed=False,
            verdict=verdict,
            detail=(
                f"env-interpolation token {token!r} in connection field "
                f"{field_name!r} references variable {var!r} not on the allowlist"
            ),
            matched_field=field_name,
            matched_token=token,
            matched_var=var,
            fix_hints=hints,
        )


__all__ = [
    "MCPEnvInterpolationDecision",
    "MCPEnvInterpolationVerdict",
    "MCPServerEnvInterpolationError",
    "MCPServerEnvInterpolationGuard",
]
