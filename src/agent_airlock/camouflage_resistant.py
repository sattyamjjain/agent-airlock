"""V0.8.6 camouflage-resistant preset composition.

Detector-independent defense against domain-camouflaged prompt injection.
Bundles the parts of the camouflage-resistant posture that span both
``SecurityPolicy`` and ``AirlockConfig`` so users can opt in with one call.

Threat model
============
arXiv:2605.22001 ("Blind Spots in the Guard: How Domain-Camouflaged
Injection Attacks Evade Detection in Multi-Agent LLM Systems", Pai, May
2026) shows that injection-detection rates collapse when payloads mimic
the target document's domain vocabulary and authority structures:

- Llama 3.1 8B: 93.8% → 9.7%
- Gemini 2.0 Flash: 100% → 55.6%
- Llama Guard 3 (production safety classifier): IDR = 0.000

Because detector content-signatures fail, this preset shifts the
defense to structural seams an attacker would need to ride regardless
of payload phrasing:

1. Tool allowlist deny-by-default (no glob shortcuts).
2. Ghost-argument BLOCK so a camouflaged directive cannot smuggle
   undeclared parameters past validation.
3. Hard output cap and PII/secret masking so a camouflaged directive
   embedded in tool output is truncated before re-entering the model
   context.
4. Per-call re-authorization once a tool's output has been observed
   (debate-amplification guard) — closes the multi-agent fan-out path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .policy import CAMOUFLAGE_RESISTANT_POLICY, SecurityPolicy
from .unknown_args import UnknownArgsMode

if TYPE_CHECKING:
    from .config import AirlockConfig


@dataclass
class CamouflageResistantBundle:
    """Composite handle returned by :func:`apply_camouflage_resistant`.

    Bundles the two seams the preset spans: ``config`` for
    ``AirlockConfig`` knobs (output cap, unknown-args BLOCK, masking)
    and ``policy`` for ``SecurityPolicy`` (allowlist, capabilities,
    debate-amplification guard).
    """

    config: AirlockConfig
    policy: SecurityPolicy


# Modest re-entry cap: large enough for typical tool output, small enough
# that a long injection prompt embedded in output gets truncated. Tunable
# per deployment via apply_camouflage_resistant(max_output_chars=...).
_DEFAULT_REENTRY_CAP_CHARS = 4000


def apply_camouflage_resistant(
    config: AirlockConfig | None = None,
    *,
    allowed_tools: list[str] | None = None,
    max_output_chars: int = _DEFAULT_REENTRY_CAP_CHARS,
) -> CamouflageResistantBundle:
    """Return a config+policy bundle pre-configured for camouflage resistance.

    Composes ``CAMOUFLAGE_RESISTANT_POLICY`` with the matching
    ``AirlockConfig`` knobs (``unknown_args=BLOCK``, sanitization on,
    output cap) so callers don't have to reassemble the bundle.

    Args:
        config: Starting config. If None, a fresh ``AirlockConfig`` is
            created. Existing fields are preserved unless they conflict
            with the camouflage-resistant posture, in which case the
            stricter setting wins.
        allowed_tools: Optional explicit tool allowlist. The preset's
            deny-by-default policy has an empty allowlist; pass the
            full list of tool names you want to permit. Glob patterns
            (e.g. ``read_*``) are accepted by ``SecurityPolicy`` but
            discouraged here — broad globs reopen the very attack
            surface the preset is meant to close.
        max_output_chars: Hard cap on tool output that re-enters the
            model context. Defaults to 4000 — small enough to truncate
            a long camouflaged directive embedded in output.

    Returns:
        ``CamouflageResistantBundle`` with the configured ``config``
        and matching ``policy``.

    Example:
        >>> from agent_airlock import Airlock, apply_camouflage_resistant
        >>> bundle = apply_camouflage_resistant(allowed_tools=["read_file"])
        >>> @Airlock(config=bundle.config, policy=bundle.policy)
        ... def read_file(path: str) -> str: ...
    """
    from .config import AirlockConfig

    if config is None:
        config = AirlockConfig()

    # The four config-level knobs the policy alone can't encode.
    config.unknown_args = UnknownArgsMode.BLOCK
    config.sanitize_output = True
    config.mask_pii = True
    config.mask_secrets = True
    if max_output_chars > 0 and (
        config.max_output_chars == 0 or max_output_chars < config.max_output_chars
    ):
        config.max_output_chars = max_output_chars

    policy = build_camouflage_resistant_policy(allowed_tools=allowed_tools)
    return CamouflageResistantBundle(config=config, policy=policy)


def build_camouflage_resistant_policy(
    allowed_tools: list[str] | None = None,
) -> SecurityPolicy:
    """Build a ``SecurityPolicy`` with the camouflage-resistant posture
    and a caller-supplied allowlist.

    The module-level ``CAMOUFLAGE_RESISTANT_POLICY`` has an empty
    ``allowed_tools`` deliberately — using it as-is blocks everything.
    Use this builder to add the specific tools your deployment needs
    without losing the rest of the posture.

    Args:
        allowed_tools: Explicit list of tool names (or glob patterns)
            to permit. ``None`` keeps the empty allowlist (deny-all).

    Returns:
        A new ``SecurityPolicy`` instance.
    """
    base = CAMOUFLAGE_RESISTANT_POLICY
    return SecurityPolicy(
        allowed_tools=list(allowed_tools) if allowed_tools else [],
        denied_tools=list(base.denied_tools),
        time_restrictions=dict(base.time_restrictions),
        rate_limits=dict(base.rate_limits),
        require_agent_id=base.require_agent_id,
        allowed_roles=list(base.allowed_roles),
        capability_policy=base.capability_policy,
        reauth_on_untrusted_reinvocation=base.reauth_on_untrusted_reinvocation,
        untrusted_reinvocation_threshold=base.untrusted_reinvocation_threshold,
        default_deny=base.default_deny,
    )


# Public re-export so callers can `from agent_airlock.camouflage_resistant
# import CAMOUFLAGE_RESISTANT_POLICY` without crossing modules.
__all__ = [
    "CAMOUFLAGE_RESISTANT_POLICY",
    "CamouflageResistantBundle",
    "apply_camouflage_resistant",
    "build_camouflage_resistant_policy",
]
