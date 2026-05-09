"""Managed Agents Outcomes-rubric guard (v0.7.4+, ADD-1 2026-05-09).

Anthropic's 2026-05-06 SF Code event shipped Managed Agents with a
structured **Outcomes** rubric (beta) — a rubric run produces a
verdict identifier that downstream tool calls should carry as a
provenance anchor. This module is the **runtime gate**: a managed-
agents-originated tool call whose provenance lacks the rubric ID,
or whose ID is outside the operator allowlist, is denied **before**
the side-effecting ``_run`` executes.

Why structurally pure (no SDK import)
-------------------------------------
The rubric ID is a string the SDK puts on a payload field. The guard
is a lookup against a frozenset[str]. There is no reason to take a
hard dep on ``claude-agent-sdk`` — that would force an install cost
on every operator who only wants the gate, not the SDK.

Companion preset
----------------
:func:`agent_airlock.policy_presets.managed_agents_outcomes_2026_05_06_defaults`
returns the recommended config dict. The guard accepts the same
inputs directly; the factory exists for parity with other dict-
returning presets (``mcp_elicitation_guard_2026_04``,
``mcp_config_path_traversal_cve_2026_31402``).

Honest scope
------------
- Anthropic's Managed Agents and Outcomes are **beta**. The rubric
  ID format and the field name carrying the anchor in tool-call
  payloads may shift between today (2026-05-06 anchor) and Q3 2026
  GA. Mitigation: the allowlist is a frozenset of strings (no regex
  pattern), and the field name is operator-overridable.
- **Dreaming** memory-curation payloads (the 2026-05-06 research
  preview) are out-of-scope for this guard — Sunday 2026-05-10
  weekly-review candidate for a separate preset.

Primary sources
---------------
- https://platform.claude.com/docs/en/managed-agents/dreams (2026-05-06)
- https://code.claude.com/docs/en/routines (2026-05-06)
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.integrations.managed_agents_outcomes_guard")


MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD = "managed_agents_outcomes_rubric_id"
"""Default provenance-payload field name carrying the rubric verdict ID.

Operators on a non-default Managed Agents harness can override this
via the :class:`ManagedAgentsOutcomesGuard` constructor.
"""


class OutcomesRubricVerdict(str, enum.Enum):
    """Stable reason codes for :class:`OutcomesRubricDecision`."""

    ALLOW = "allow"
    DENY_MISSING_PROVENANCE = "deny_missing_provenance"
    DENY_RUBRIC_ID_MISSING = "deny_rubric_id_missing"
    DENY_RUBRIC_ID_NOT_ALLOWED = "deny_rubric_id_not_allowed"


@dataclass(frozen=True)
class OutcomesRubricDecision:
    """Outcome of a single :meth:`ManagedAgentsOutcomesGuard.evaluate` call.

    Mirrors the field shape of
    :class:`agent_airlock.runtime.manifest_only_allowlist.AllowlistVerdict`
    — both expose ``allowed: bool`` so an integrator can chain guards
    on a single short-circuit predicate.

    Attributes:
        allowed: True iff the call may proceed.
        verdict: A stable :class:`OutcomesRubricVerdict` value.
        detail: Free-form human-readable explanation.
        rubric_id: The rubric ID extracted from the provenance, if any.
            ``None`` for missing provenance / missing key paths so
            callers can log without an unwrap.
    """

    allowed: bool
    verdict: OutcomesRubricVerdict
    detail: str
    rubric_id: str | None


class ManagedAgentsOutcomesGuard:
    """Fail-closed gate on the Managed Agents Outcomes rubric ID.

    Default: empty allowlist → deny-all. Operators must explicitly
    enrol every rubric ID they trust.

    Args:
        allowlist: Frozenset of rubric IDs the gate permits. Empty
            (default) denies every call. Each member must be a
            non-empty string.
        provenance_field: The dict key on the call's provenance
            payload that carries the rubric ID. Defaults to
            :data:`MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD`.
            Override per operator harness.

    Raises:
        TypeError: ``allowlist`` is not a frozenset, or any member
            is not a string.
    """

    def __init__(
        self,
        *,
        allowlist: frozenset[str] = frozenset(),
        provenance_field: str = MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD,
    ) -> None:
        if not isinstance(allowlist, frozenset):
            raise TypeError(f"allowlist must be a frozenset[str]; got {type(allowlist).__name__}")
        for member in allowlist:
            if not isinstance(member, str):
                raise TypeError(f"allowlist members must be str; got {type(member).__name__}")
        self._allowlist = allowlist
        self._provenance_field = provenance_field

    def evaluate(self, provenance: Mapping[str, Any] | None) -> OutcomesRubricDecision:
        """Decide whether a call's provenance carries an allowlisted rubric ID.

        Args:
            provenance: The call's provenance dict. ``None`` means the
                call had no provenance envelope at all (e.g. direct
                tool invocation outside any Managed Agents run) and
                is denied with :attr:`OutcomesRubricVerdict.DENY_MISSING_PROVENANCE`.

        Returns:
            :class:`OutcomesRubricDecision`. Callers map ``allowed=False``
            to a refusal at the Airlock decorator boundary.
        """
        if provenance is None:
            return OutcomesRubricDecision(
                allowed=False,
                verdict=OutcomesRubricVerdict.DENY_MISSING_PROVENANCE,
                detail="provenance envelope is None — no managed-agents rubric anchor",
                rubric_id=None,
            )

        raw = provenance.get(self._provenance_field)
        if not isinstance(raw, str) or not raw:
            return OutcomesRubricDecision(
                allowed=False,
                verdict=OutcomesRubricVerdict.DENY_RUBRIC_ID_MISSING,
                detail=(f"provenance lacks a non-empty string at key {self._provenance_field!r}"),
                rubric_id=None,
            )

        if raw not in self._allowlist:
            return OutcomesRubricDecision(
                allowed=False,
                verdict=OutcomesRubricVerdict.DENY_RUBRIC_ID_NOT_ALLOWED,
                detail=(
                    f"rubric_id {raw!r} not in operator allowlist (size={len(self._allowlist)})"
                ),
                rubric_id=raw,
            )

        logger.info(
            "managed_agents_outcomes_allow",
            rubric_id=raw,
            allowlist_size=len(self._allowlist),
        )
        return OutcomesRubricDecision(
            allowed=True,
            verdict=OutcomesRubricVerdict.ALLOW,
            detail="rubric_id matches operator allowlist",
            rubric_id=raw,
        )


__all__ = [
    "MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD",
    "ManagedAgentsOutcomesGuard",
    "OutcomesRubricDecision",
    "OutcomesRubricVerdict",
]
