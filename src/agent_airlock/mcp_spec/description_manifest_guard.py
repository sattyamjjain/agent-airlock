"""MCP description-vs-manifest consistency guard (v0.8.18+, DCIChecker anchor).

The DCIChecker paper (arXiv:2606.04769) measured **Description-Code
Inconsistency** across the public MCP ecosystem and found that
**9.93% of 19,200 tool description/implementation pairs across 2,214
MCP servers** were inconsistent — the natural-language description the
model consumes when it decides whether (and how) to call a tool does
**not** match the tool's actual registered contract. Two failure
directions dominate:

1. The description advertises an **argument the tool never declares** —
   a model that follows the description faithfully invents a ghost
   argument the implementation will never accept.
2. The description **understates a side effect** the tool actually has
   — the classic tool-poisoning shape, where a tool quietly does more
   (writes, deletes, sends network egress) than its advertised
   capability/security boundary admits.

Where this sits in the stack
----------------------------
agent-airlock already strips/blocks ghost arguments and runs Pydantic
strict type-validation at call time (``validator.py`` /
``unknown_args.py``). Those operate on the **observed call payload**.
This guard operates one layer earlier and on a different object: it
asserts the **declared contract itself is internally honest** — that
the description the model is given matches the registered manifest —
*before* a single call is admitted. It does **not** replace ghost-arg
stripping or type-validation; it composes above them.

Detected divergences
--------------------
- ``DESCRIBED_ARG_NOT_IN_MANIFEST`` — the description references /
  declares an argument absent from the manifest's declared args.
- ``UNDISCLOSED_SIDE_EFFECT`` — the manifest declares a side effect /
  capability the description does not disclose (under-disclosure; the
  tool-poisoning direction).
- ``OVERCLAIMED_CAPABILITY`` — the description advertises a capability
  absent from the manifest (the "declared capability absent from the
  manifest" mismatch).

Intentional non-divergence
--------------------------
A manifest arg that the description omits is **not** flagged: benign
under-documentation of an input is governed by the ghost-arg /
Pydantic layer at call time, not by this semantic guard. Flagging it
would penalise terse-but-honest descriptions. This is a deliberate
scope decision, stated so reviewers can trace it.

Drift modes
-----------
- ``strict`` (default): any divergence → deny (fail-closed,
  deny-by-default posture).
- ``warn``: divergence → allow, structured warning logged,
  divergences surfaced on the decision.
- ``shadow``: divergence → allow, divergences recorded with no log
  (calibrate the manifest registry against real descriptions before
  flipping to strict).

Inputs are caller-supplied dicts/dataclasses
--------------------------------------------
The core takes **no** new runtime dependency. Operators build a
:class:`ToolManifest` (the authoritative registered contract) and a
:class:`ToolDescription` (what the tool advertises) from whatever
source they own — the running server's ``tools/list`` response, a
checked-in manifest file, or a static catalogue — and hand them to the
guard. Pydantic-only core is preserved.

Primary source
--------------
https://arxiv.org/abs/2606.04769
"""

from __future__ import annotations

import enum
import functools
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.description_manifest_guard")


_VALID_DRIFT_MODES: frozenset[str] = frozenset({"strict", "warn", "shadow"})

F = TypeVar("F", bound=Callable[..., Any])


def _as_frozenset(value: Iterable[str] | None, *, label: str) -> frozenset[str]:
    """Normalise an iterable of strings to a frozenset, validating element types.

    Args:
        value: Iterable of strings, or ``None`` (→ empty set).
        label: Field name used in the raised error message.

    Returns:
        A ``frozenset[str]``.

    Raises:
        TypeError: ``value`` is a bare ``str`` (a common footgun that
            would otherwise be silently iterated character-by-character)
            or contains a non-string element.
    """
    if value is None:
        return frozenset()
    if isinstance(value, str):
        raise TypeError(f"{label} must be an iterable of str, not a bare str: {value!r}")
    out = frozenset(value)
    for item in out:
        if not isinstance(item, str):
            raise TypeError(f"{label} elements must be str; got {type(item).__name__}")
    return out


@dataclass(frozen=True)
class ToolManifest:
    """The authoritative, registered contract for a single tool.

    This is the ground truth: the arguments the tool actually accepts
    and the side effects / capabilities it actually has. Operators
    derive it from the server's registered tool spec, the
    implementation, or a reviewed catalogue — not from the
    model-facing description.

    Attributes:
        name: The tool name (the join key against a description).
        declared_args: The argument names the tool actually accepts.
        side_effects: Stable side-effect / capability tags the tool
            actually has (e.g. ``"filesystem_write"``, ``"network_egress"``,
            ``"data_delete"``). Free-form but should be a controlled
            vocabulary shared with descriptions.
    """

    name: str
    declared_args: Iterable[str] = field(default_factory=frozenset)
    side_effects: Iterable[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise TypeError("ToolManifest.name must be a non-empty str")
        object.__setattr__(
            self, "declared_args", _as_frozenset(self.declared_args, label="declared_args")
        )
        object.__setattr__(
            self, "side_effects", _as_frozenset(self.side_effects, label="side_effects")
        )


@dataclass(frozen=True)
class ToolDescription:
    """What a tool advertises to the model — its declared boundary.

    The description side of a DCIChecker pair. Built from the tool's
    model-facing description + declared input schema (the object the
    LLM consumes when deciding whether and how to call the tool).

    Attributes:
        name: The tool name (the join key against a manifest).
        described_args: Argument names the description references /
            declares as inputs the caller should supply.
        described_side_effects: Side-effect / capability tags the
            description discloses. Drawn from the same controlled
            vocabulary as :attr:`ToolManifest.side_effects`.
    """

    name: str
    described_args: Iterable[str] = field(default_factory=frozenset)
    described_side_effects: Iterable[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise TypeError("ToolDescription.name must be a non-empty str")
        object.__setattr__(
            self, "described_args", _as_frozenset(self.described_args, label="described_args")
        )
        object.__setattr__(
            self,
            "described_side_effects",
            _as_frozenset(self.described_side_effects, label="described_side_effects"),
        )


class DescriptionManifestVerdict(str, enum.Enum):
    """Stable reason codes for :class:`DescriptionManifestDecision`."""

    ALLOW = "allow"
    ALLOW_WARN = "allow_warn"
    ALLOW_SHADOW = "allow_shadow"
    DENY_INCONSISTENT = "deny_inconsistent"
    DENY_UNKNOWN_TOOL = "deny_unknown_tool"


class DescriptionManifestDivergenceKind(str, enum.Enum):
    """The inconsistency categories detected by the guard."""

    DESCRIBED_ARG_NOT_IN_MANIFEST = "described_arg_not_in_manifest"
    UNDISCLOSED_SIDE_EFFECT = "undisclosed_side_effect"
    OVERCLAIMED_CAPABILITY = "overclaimed_capability"


@dataclass(frozen=True)
class DescriptionManifestDivergence:
    """A single description-vs-manifest inconsistency finding.

    Attributes:
        kind: The category of inconsistency detected.
        item: The offending argument name (for
            ``DESCRIBED_ARG_NOT_IN_MANIFEST``) or side-effect tag (for
            ``UNDISCLOSED_SIDE_EFFECT`` / ``OVERCLAIMED_CAPABILITY``).
    """

    kind: DescriptionManifestDivergenceKind
    item: str


@dataclass(frozen=True)
class DescriptionManifestDecision:
    """Outcome of a single :meth:`DescriptionManifestGuard.evaluate` call.

    Mirrors the v0.7.x / v0.8.x decision family — every guard exposes
    ``allowed: bool`` so integrators can chain on one short-circuit
    predicate.

    Attributes:
        allowed: True iff the tool may be admitted. Divergence in
            ``warn`` / ``shadow`` mode still produces ``True``.
        verdict: Stable :class:`DescriptionManifestVerdict` value.
        detail: Free-form explanation suitable for logs.
        tool_name: Echo of the evaluated tool name.
        divergences: Every inconsistency finding. Empty when clean.
    """

    allowed: bool
    verdict: DescriptionManifestVerdict
    detail: str
    tool_name: str
    divergences: tuple[DescriptionManifestDivergence, ...]

    def fix_hints(self) -> list[str]:
        """Render LLM-actionable fix hints, one per divergence.

        Reuses the ``fix_hints`` concept from
        :class:`agent_airlock.self_heal.AirlockResponse` so a denied
        admission can flow into the same self-healing retry surface.
        """
        hints: list[str] = []
        for d in self.divergences:
            if d.kind is DescriptionManifestDivergenceKind.DESCRIBED_ARG_NOT_IN_MANIFEST:
                hints.append(
                    f"Description advertises argument {d.item!r} that the registered "
                    f"manifest does not declare; remove it from the description or "
                    f"declare it in the manifest."
                )
            elif d.kind is DescriptionManifestDivergenceKind.UNDISCLOSED_SIDE_EFFECT:
                hints.append(
                    f"Manifest declares side effect {d.item!r} that the description "
                    f"does not disclose; disclose it in the description (under-disclosed "
                    f"capability / tool-poisoning shape)."
                )
            else:  # OVERCLAIMED_CAPABILITY
                hints.append(
                    f"Description advertises capability {d.item!r} absent from the "
                    f"manifest; remove the claim or add the capability to the manifest."
                )
        return hints


class DescriptionManifestViolation(AirlockError):
    """Raised by a vaccinated tool when admission is denied (fail-closed).

    Carries the :class:`DescriptionManifestDecision` (with its
    divergences) and exposes ``fix_hints`` so an upstream airlock layer
    can route the refusal into self-healing retry semantics.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: LLM-actionable remediation hints (one per divergence).
    """

    def __init__(self, decision: DescriptionManifestDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints()
        super().__init__(decision.detail)


class DescriptionManifestGuard:
    """Asserts model-facing tool descriptions match the registered manifest.

    Construct once with the authoritative manifest registry, then call
    :meth:`evaluate` (or wrap tools with
    :func:`vaccinate_description_manifest`) to assert each description
    is internally consistent with its manifest before the tool is
    admitted.

    Args:
        manifests: Iterable of :class:`ToolManifest` — the ground-truth
            registered contracts, indexed internally by ``name``.
        drift_mode: One of ``"strict"`` (default) / ``"warn"`` /
            ``"shadow"``. Controls whether an inconsistency denies.

    Raises:
        TypeError: ``manifests`` contains a non-``ToolManifest``.
        ValueError: ``drift_mode`` is unknown, or two manifests share
            a ``name``.
    """

    def __init__(
        self,
        *,
        manifests: Iterable[ToolManifest],
        drift_mode: str = "strict",
    ) -> None:
        if drift_mode not in _VALID_DRIFT_MODES:
            raise ValueError(
                f"drift_mode must be one of {sorted(_VALID_DRIFT_MODES)!r}; got {drift_mode!r}"
            )
        index: dict[str, ToolManifest] = {}
        for m in manifests:
            if not isinstance(m, ToolManifest):
                raise TypeError(f"manifests must contain ToolManifest; got {type(m).__name__}")
            if m.name in index:
                raise ValueError(f"duplicate manifest for tool {m.name!r}")
            index[m.name] = m
        self._manifests = index
        self._drift_mode = drift_mode

    def evaluate(self, description: ToolDescription) -> DescriptionManifestDecision:
        """Compare a tool description against its registered manifest.

        Args:
            description: The model-facing declared contract to check.

        Returns:
            :class:`DescriptionManifestDecision`. ``allowed=False`` maps
            to a refusal at the Airlock decorator boundary.

        Raises:
            TypeError: ``description`` is not a :class:`ToolDescription`.
        """
        if not isinstance(description, ToolDescription):
            raise TypeError(
                f"description must be a ToolDescription; got {type(description).__name__}"
            )
        manifest = self._manifests.get(description.name)
        if manifest is None:
            return self._unknown_tool(description.name)

        divergences = self._compare(manifest=manifest, description=description)
        return self._wrap_verdict(tool_name=description.name, divergences=divergences)

    @staticmethod
    def _compare(
        *,
        manifest: ToolManifest,
        description: ToolDescription,
    ) -> tuple[DescriptionManifestDivergence, ...]:
        """Compute the divergence tuple for a description against its manifest.

        ``ToolManifest`` / ``ToolDescription`` normalise their fields to
        ``frozenset`` in ``__post_init__``; the locals below re-wrap them
        only so the static type is a concrete set (the declared field
        type is the broader ``Iterable[str]`` accepted at construction).
        """
        divergences: list[DescriptionManifestDivergence] = []

        declared_args = frozenset(manifest.declared_args)
        manifest_effects = frozenset(manifest.side_effects)
        described_args = frozenset(description.described_args)
        described_effects = frozenset(description.described_side_effects)

        # 1) Described arg the manifest never declares (case b — sorted
        #    for deterministic ordering in detail strings / tests).
        for arg in sorted(described_args - declared_args):
            divergences.append(
                DescriptionManifestDivergence(
                    kind=DescriptionManifestDivergenceKind.DESCRIBED_ARG_NOT_IN_MANIFEST,
                    item=arg,
                )
            )

        # 2) Manifest side effect the description does NOT disclose
        #    (case c — under-disclosure / tool-poisoning direction).
        for effect in sorted(manifest_effects - described_effects):
            divergences.append(
                DescriptionManifestDivergence(
                    kind=DescriptionManifestDivergenceKind.UNDISCLOSED_SIDE_EFFECT,
                    item=effect,
                )
            )

        # 3) Described capability absent from the manifest (over-claim).
        for effect in sorted(described_effects - manifest_effects):
            divergences.append(
                DescriptionManifestDivergence(
                    kind=DescriptionManifestDivergenceKind.OVERCLAIMED_CAPABILITY,
                    item=effect,
                )
            )

        return tuple(divergences)

    def _unknown_tool(self, tool_name: str) -> DescriptionManifestDecision:
        detail = f"no registered manifest for tool {tool_name!r}"
        if self._drift_mode == "strict":
            logger.warning("description_manifest_unknown_tool", tool_name=tool_name)
            return DescriptionManifestDecision(
                allowed=False,
                verdict=DescriptionManifestVerdict.DENY_UNKNOWN_TOOL,
                detail=detail,
                tool_name=tool_name,
                divergences=(),
            )
        verdict = (
            DescriptionManifestVerdict.ALLOW_WARN
            if self._drift_mode == "warn"
            else DescriptionManifestVerdict.ALLOW_SHADOW
        )
        if self._drift_mode == "warn":
            logger.warning("description_manifest_unknown_tool_warn", tool_name=tool_name)
        return DescriptionManifestDecision(
            allowed=True,
            verdict=verdict,
            detail=detail,
            tool_name=tool_name,
            divergences=(),
        )

    def _wrap_verdict(
        self,
        *,
        tool_name: str,
        divergences: tuple[DescriptionManifestDivergence, ...],
    ) -> DescriptionManifestDecision:
        if not divergences:
            return DescriptionManifestDecision(
                allowed=True,
                verdict=DescriptionManifestVerdict.ALLOW,
                detail="description is consistent with the registered manifest",
                tool_name=tool_name,
                divergences=(),
            )
        detail = (
            f"{len(divergences)} description/manifest inconsistency(ies) for "
            f"tool={tool_name!r}: " + ", ".join(f"{d.kind.value}:{d.item}" for d in divergences)
        )
        if self._drift_mode == "strict":
            logger.warning(
                "description_manifest_strict_deny",
                tool_name=tool_name,
                count=len(divergences),
            )
            return DescriptionManifestDecision(
                allowed=False,
                verdict=DescriptionManifestVerdict.DENY_INCONSISTENT,
                detail=detail,
                tool_name=tool_name,
                divergences=divergences,
            )
        if self._drift_mode == "warn":
            logger.warning(
                "description_manifest_warn_allow",
                tool_name=tool_name,
                count=len(divergences),
            )
            return DescriptionManifestDecision(
                allowed=True,
                verdict=DescriptionManifestVerdict.ALLOW_WARN,
                detail=detail,
                tool_name=tool_name,
                divergences=divergences,
            )
        # shadow
        return DescriptionManifestDecision(
            allowed=True,
            verdict=DescriptionManifestVerdict.ALLOW_SHADOW,
            detail=detail,
            tool_name=tool_name,
            divergences=divergences,
        )


def vaccinate_description_manifest(
    manifests: Iterable[ToolManifest],
    *,
    drift_mode: str = "strict",
) -> Callable[[ToolDescription], Callable[[F], F]]:
    """Return a decorator factory that admits a tool only if its description matches.

    Wires a :class:`DescriptionManifestGuard` to the manifest registry
    once, then returns a callable that takes the tool's
    :class:`ToolDescription` and decorates the tool function. The check
    runs at the **wrap seam**: on a deny decision the wrapped function
    raises :class:`DescriptionManifestViolation` **before** the
    underlying tool executes — every call, fail-closed.

    Example::

        manifests = [ToolManifest(name="read_file", declared_args={"path"})]
        vaccine = vaccinate_description_manifest(manifests, drift_mode="strict")

        @vaccine(ToolDescription(name="read_file", described_args={"path"}))
        def read_file(*, path: str) -> str:
            ...

    Args:
        manifests: The authoritative manifest registry.
        drift_mode: ``strict`` / ``warn`` / ``shadow``.

    Returns:
        ``(description) -> decorator`` factory.
    """
    guard = DescriptionManifestGuard(manifests=manifests, drift_mode=drift_mode)

    def make_decorator(description: ToolDescription) -> Callable[[F], F]:
        decision = guard.evaluate(description)

        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                if not decision.allowed:
                    raise DescriptionManifestViolation(decision)
                return fn(*args, **kwargs)

            return wrapped  # type: ignore[return-value]

        return decorator

    return make_decorator


__all__ = [
    "DescriptionManifestDecision",
    "DescriptionManifestDivergence",
    "DescriptionManifestDivergenceKind",
    "DescriptionManifestGuard",
    "DescriptionManifestVerdict",
    "DescriptionManifestViolation",
    "ToolDescription",
    "ToolManifest",
    "vaccinate_description_manifest",
]
