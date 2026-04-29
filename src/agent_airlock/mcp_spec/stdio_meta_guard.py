"""Composite ``StdioMetaGuard`` — bundled defense for the OX-disclosed STDIO RCE class (v0.5.9+).

OX Security's 2026-04-26 disclosure ("Mother of All AI Supply Chains")
confirmed the Anthropic MCP STDIO injection class is exploitable across
200K+ servers and that Anthropic has declined to patch ("expected
behavior"). The OSS runtime owns the mitigation path, so this module
composes every existing STDIO-adjacent guard already shipped by airlock
into a single named chain:

* :func:`agent_airlock.mcp_spec.stdio_guard.validate_stdio_command`
* :func:`agent_airlock.mcp_spec.argv_guard.enforce_argv_array`
* :func:`agent_airlock.mcp_spec.manifest_only_mode.launch_from_manifest`
  consistency check (manifest hash vs runtime argv)
* :func:`tools.scan_stdio_remote_input_flow` AST taint scanner result

The meta-guard does **not** re-implement any of those; it orchestrates
them, deduplicates findings by ``(guard_id, finding_id)`` so operators
do not see the same RCE flagged four times, and pins the variant set
in :data:`StdioMetaGuard.__variants__` so adding a new STDIO variant
guard is a one-line registration rather than a chain edit.

References
----------
* OX Security (2026-04-26):
  https://www.ox.security/blog/mother-of-all-ai-supply-chains-anthropic-mcp-stdio
* Original Ox advisory (2026-04-16, CVE-2026-30616 family):
  https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem
* Anthropic's "expected behavior" position (The Register, 2026-04-16):
  https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog

from ..exceptions import AirlockError
from ..policy import StdioGuardConfig
from .argv_guard import ArgvStringConcatenationError, enforce_argv_array
from .stdio_guard import StdioInjectionError, validate_stdio_command

logger = structlog.get_logger("agent-airlock.mcp_spec.stdio_meta_guard")

Verdict = Literal["allow", "warn", "block"]


@dataclass(frozen=True)
class Finding:
    """One guard-level finding emitted by :class:`StdioMetaGuard`."""

    guard_id: str
    finding_id: str
    rule: str
    severity: Literal["low", "medium", "high", "critical"]
    message: str
    offending_arg: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MetaVerdict:
    """Aggregated outcome of the composed STDIO chain."""

    verdict: Verdict
    findings: tuple[Finding, ...]
    duration_ms: float
    chain: tuple[str, ...]


class StdioMetaGuardError(AirlockError):
    """Raised by :meth:`StdioMetaGuard.evaluate_or_raise` on a block verdict."""

    def __init__(self, message: str, *, findings: tuple[Finding, ...]) -> None:
        self.findings = findings
        super().__init__(message)


# Variant registry — each entry is the conceptual STDIO-injection variant
# the meta-guard claims coverage of. Adding a new variant means adding a
# row here; the test suite asserts every variant has at least one guard
# step that responds to it. Keep the list ASCII-stable and ordered.
_DEFAULT_VARIANTS: tuple[str, ...] = (
    "argv_string_concat",  # client supplies a single shell-form string
    "argv_shell_metachar",  # ``;``, ``|``, backtick, ``$()`` smuggled in argv
    "argv_unicode_bidi",  # RLO/LRO visual-spoofing in argv
    "argv_absolute_path_smuggle",  # absolute binary outside allowed prefixes
    "argv_basename_not_allowlisted",  # plausible basename, not in allowlist
    "argv_env_path_traversal",  # ``../`` traversal in argv element
    "manifest_runtime_drift",  # runtime argv diverges from signed manifest
    "stdin_remote_input_taint",  # remote input reaches stdin sink (AST taint)
)


class StdioMetaGuard:
    """Composite guard chaining every airlock STDIO-defence in one call.

    The chain is intentionally short — four steps, deterministic order.
    Each step records findings; the final verdict is the *worst* verdict
    encountered (block > warn > allow).
    """

    __variants__: tuple[str, ...] = _DEFAULT_VARIANTS

    def __init__(
        self,
        *,
        stdio_config: StdioGuardConfig,
        manifest_check: ManifestRuntimeCheck | None = None,
        taint_check: TaintCheck | None = None,
    ) -> None:
        self.stdio_config = stdio_config
        self.manifest_check = manifest_check
        self.taint_check = taint_check

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose_chain(self) -> tuple[str, ...]:
        """Return the ordered list of guard step ids for this configuration."""
        chain: list[str] = [
            "argv_guard.enforce_argv_array",
            "stdio_meta_guard.path_traversal_check",
            "stdio_guard.validate_stdio_command",
        ]
        if self.manifest_check is not None:
            chain.append("manifest_only_mode.runtime_drift_check")
        if self.taint_check is not None:
            chain.append("scan_stdio_remote_input_flow.taint_check")
        return tuple(chain)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        server_spec: dict[str, Any],
        runtime_ctx: dict[str, Any] | None = None,
    ) -> MetaVerdict:
        """Run the composed chain and return an aggregated verdict.

        Args:
            server_spec: An MCP server spec dict with at minimum a
                ``"command"`` field (string or list-of-strings) and an
                optional ``"args"`` field. Extra keys are ignored.
            runtime_ctx: Optional context dict; ``"manifest"`` carries
                the signed manifest the runtime should match against.

        Returns:
            A :class:`MetaVerdict` whose ``verdict`` is the worst step
            verdict and whose ``findings`` are deduplicated by
            ``(guard_id, finding_id)``.
        """
        runtime_ctx = runtime_ctx or {}
        started = time.perf_counter()
        findings: list[Finding] = []

        cmd_obj = server_spec.get("command")
        cmd_args = server_spec.get("args") or []

        # Build the canonical argv list for downstream steps.
        if isinstance(cmd_obj, list):
            argv: list[str] = list(cmd_obj) + list(cmd_args)
        elif isinstance(cmd_obj, str):
            # Single-string ``command`` with no separate args is the
            # canonical shell-form smuggle when it contains spaces; only
            # a bare basename is acceptable.
            if " " in cmd_obj or any(c in cmd_obj for c in (";", "|", "&", "$", "`")):
                findings.append(
                    Finding(
                        guard_id="argv_guard",
                        finding_id="argv_string_concat",
                        rule="argv_string_concat",
                        severity="critical",
                        message=(
                            f"server_spec['command'] is a single string with shell "
                            f"metacharacters or whitespace: {cmd_obj!r}"
                        ),
                        offending_arg=cmd_obj,
                    )
                )
                return self._finalize(findings, started)
            argv = [cmd_obj] + list(cmd_args)
        else:
            argv = list(cmd_args)

        # Step 1: argv_guard — refuses any shell-form (string concatenation)
        # in any non-binary slot.
        try:
            enforce_argv_array(argv[1:] if argv else [], allow_spaces=False)
        except ArgvStringConcatenationError as exc:
            findings.append(
                Finding(
                    guard_id="argv_guard",
                    finding_id="argv_string_concat",
                    rule=getattr(exc, "rule", "argv_string_concat"),
                    severity="critical",
                    message=str(exc),
                    offending_arg=getattr(exc, "offending_arg", None),
                )
            )
            # Short-circuit: if the argv shape itself is wrong, downstream
            # steps cannot meaningfully run.
            return self._finalize(findings, started)

        # Step 1b: path-traversal scan. ``stdio_guard`` enforces metachar
        # / unicode / allowlist but does not catch ``../`` traversal in
        # an argv element on its own. Cover that variant here.
        for idx, value in enumerate(argv):
            if ".." in value and ("/" in value or "\\" in value):
                findings.append(
                    Finding(
                        guard_id="stdio_meta_guard",
                        finding_id="argv_env_path_traversal",
                        rule="path_traversal",
                        severity="critical",
                        message=f"argv[{idx}] contains '../' traversal: {value!r}",
                        offending_arg=value,
                        details={"index": idx},
                    )
                )

        # Step 2: stdio_guard — per-arg metachar / unicode / allowlist.
        try:
            validate_stdio_command(argv, self.stdio_config)
        except StdioInjectionError as exc:
            findings.append(
                Finding(
                    guard_id="stdio_guard",
                    finding_id=_finding_id_for_rule(exc.rule),
                    rule=exc.rule,
                    severity="critical",
                    message=str(exc),
                    offending_arg=exc.offending_arg,
                    details=dict(exc.details),
                )
            )

        # Step 3: manifest drift — runtime argv must match what the
        # signed manifest declared. Optional; only runs when configured.
        if self.manifest_check is not None:
            manifest = runtime_ctx.get("manifest")
            if manifest is not None:
                try:
                    self.manifest_check(argv, manifest)
                except AirlockError as exc:
                    findings.append(
                        Finding(
                            guard_id="manifest_only_mode",
                            finding_id="manifest_runtime_drift",
                            rule=getattr(exc, "rule", "manifest_runtime_drift"),
                            severity="critical",
                            message=str(exc),
                            details=getattr(exc, "details", {}) or {},
                        )
                    )

        # Step 4: AST taint check — does any remote-input source reach
        # stdin? Only runs when configured because it requires a
        # filesystem path and is moderately expensive.
        if self.taint_check is not None:
            for path in runtime_ctx.get("source_paths", ()):
                taint_findings = self.taint_check(path) or ()
                for tf in taint_findings:
                    findings.append(
                        Finding(
                            guard_id="scan_stdio_remote_input_flow",
                            finding_id="stdin_remote_input_taint",
                            rule=tf.get("rule", "remote_input_to_stdin"),
                            severity="high",
                            message=tf.get("message", "remote input reaches stdin"),
                            details={"path": str(path), **tf.get("details", {})},
                        )
                    )

        return self._finalize(findings, started)

    def evaluate_or_raise(
        self,
        server_spec: dict[str, Any],
        runtime_ctx: dict[str, Any] | None = None,
    ) -> MetaVerdict:
        """Like :meth:`evaluate`, but raises on a ``block`` verdict."""
        verdict = self.evaluate(server_spec, runtime_ctx)
        if verdict.verdict == "block":
            raise StdioMetaGuardError(
                "STDIO meta-guard refused server spec: "
                + "; ".join(f.message for f in verdict.findings),
                findings=verdict.findings,
            )
        return verdict

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _finalize(self, findings: list[Finding], started: float) -> MetaVerdict:
        deduped = _dedupe_findings(findings)
        verdict: Verdict = "block" if deduped else "allow"
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        logger.info(
            "stdio_meta_guard_evaluated",
            verdict=verdict,
            findings=len(deduped),
            duration_ms=round(elapsed_ms, 3),
            variants=self.__variants__,
        )
        return MetaVerdict(
            verdict=verdict,
            findings=tuple(deduped),
            duration_ms=elapsed_ms,
            chain=self.compose_chain(),
        )


# ---------------------------------------------------------------------------
# Helper protocols
# ---------------------------------------------------------------------------


class ManifestRuntimeCheck:
    """Callable protocol for the manifest-drift step.

    A callable that takes ``(argv: list[str], manifest: dict[str, Any])``
    and raises on drift. We accept any callable; ``manifest_only_mode``
    ships one shape, and tests can inject lambdas.
    """

    def __call__(self, argv: list[str], manifest: dict[str, Any]) -> None: ...


class TaintCheck:
    """Callable protocol for the AST-taint step.

    A callable that takes a source path and returns an iterable of
    finding dicts. ``tools/scan_stdio_remote_input_flow.py`` provides
    the concrete implementation.
    """

    def __call__(self, path: str) -> list[dict[str, Any]] | None: ...


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _finding_id_for_rule(rule: str) -> str:
    """Map a :class:`StdioInjectionError` rule to a meta-guard finding id."""
    mapping = {
        "shell_metachar": "argv_shell_metachar",
        "banned_unicode": "argv_unicode_bidi",
        "absolute_path_not_allowed": "argv_absolute_path_smuggle",
        "binary_not_allowlisted": "argv_basename_not_allowlisted",
        "path_traversal": "argv_env_path_traversal",
    }
    return mapping.get(rule, rule)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Drop subsequent findings sharing ``(guard_id, finding_id)``.

    First-emit wins; later dupes go to the debug log so operators are
    never spammed but the audit trail is still complete.
    """
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.guard_id, f.finding_id)
        if key in seen:
            logger.debug("stdio_meta_guard_dedup", guard=f.guard_id, finding=f.finding_id)
            continue
        seen.add(key)
        out.append(f)
    return out


__all__ = [
    "Finding",
    "ManifestRuntimeCheck",
    "MetaVerdict",
    "StdioMetaGuard",
    "StdioMetaGuardError",
    "TaintCheck",
    "Verdict",
]
