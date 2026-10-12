"""Mode C: call a guard's own entry point, then let a thin canary act iff admitted.

A standalone adapter constructs the guard, runs its ``evaluate`` / ``check`` /
``validate`` / ``enforce`` / ``inspect`` / ``check_url`` / ... entry on the
candidate, and reads a uniform ``denied`` from the heterogeneous decision family
(``.allowed`` booleans, ``.verdict`` str-enums, ConfigInspection's ``"block"``,
LANUnauthRCEGuard's ``.action``, or a raised ``AirlockError`` / ``ValueError``).

If — and only if — the guard admitted the candidate AND an **independent**
reference detector (stdlib ``ipaddress`` / ``os.path`` / a fresh regex, never the
guard's own code) confirms the candidate still carries the forbidden shape, the
thin canary records a sink hit. The oracle then classifies that as a bypass.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..oracle import CallSpec, Canary, Candidate, ForbiddenEffect, Intent, response_denied
from .base import extract_fix_hints, normalized_denial

# A guard refusal is one of these, not a harness error. ValueError covers the
# ``oauth`` / ``transport`` / spec-validator subclasses; AirlockError the rest.
RefusalTypes = tuple[type[BaseException], ...]


@dataclass
class StandaloneAdapter:
    """One mode-C guard target.

    Attributes:
        name: Adapter / target name.
        build_guard: Zero-arg factory returning the guard instance, or ``None``
            for a function-style guard.
        entry: ``(guard, call) -> decision``. Runs the guard's own entry point.
            Raises a guard refusal (caught) on a deny-by-raise guard.
        forbidden: The forbidden effect this guard prevents.
        blocked: ``(seed) -> CallSpec`` for a shape the guard's tests prove refused.
        benign: ``(seed) -> CallSpec`` for a shape the guard must admit.
        reference: ``(call) -> bool`` independent confirmation the call carries the
            forbidden shape. Defaults to "always" (so an admit of an attack probe
            is a sink hit); flagship adapters pass a real stdlib-backed detector.
        sink_probe: ``(call) -> list[str]`` the thin canary action when admitted.
            Defaults to a symbolic in-process marker.
        refusal_types: Exception types that mean "guard refused", not "harness
            error".
    """

    name: str
    build_guard: Callable[[], Any] | None
    entry: Callable[[Any, CallSpec], Any]
    forbidden: ForbiddenEffect
    blocked: Callable[[int], CallSpec]
    benign: Callable[[int], CallSpec]
    reference: Callable[[CallSpec], bool] = field(default=lambda _call: True)
    sink_probe: Callable[[CallSpec], list[str]] | None = None
    refusal_types: RefusalTypes = ()
    mode: str = "C"

    def __post_init__(self) -> None:
        # A guard refusal is always an AirlockError or a ValueError (the oauth /
        # transport / spec-validator subclasses); an adapter may add more (e.g.
        # MCPProxyGuard's ``MCPSecurityError``, which subclasses bare Exception).
        from agent_airlock.exceptions import AirlockError

        base: tuple[type[BaseException], ...] = (AirlockError, ValueError)
        self.refusal_types = tuple(dict.fromkeys((*self.refusal_types, *base)))

    def intent(self) -> ForbiddenEffect:
        return self.forbidden

    def build_canary(self) -> Any:  # pragma: no cover - trivial
        return None

    def known_blocked(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-blocked",
            call=self.blocked(seed),
            intent=Intent.ATTACK,
        )

    def benign_control(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-benign",
            call=self.benign(seed),
            intent=Intent.BENIGN,
        )

    def _default_sink(self, _call: CallSpec) -> list[str]:
        sentinel = self.forbidden.sentinel or "admitted"
        return [f"{self.forbidden.sink}:{sentinel}"]

    def run(self, candidate: Candidate) -> Canary:
        canary = Canary()
        guard = self.build_guard() if self.build_guard is not None else None
        try:
            decision = self.entry(guard, candidate.call)
        except self.refusal_types as exc:
            canary.response = normalized_denial(
                denied=True,
                verdict=type(exc).__name__,
                fix_hints=extract_fix_hints(exc),
                detail=str(exc),
            )
            return canary
        except Exception as exc:  # noqa: BLE001 - any other error is a harness error
            canary.raised = exc
            return canary

        canary.response = decision
        denied = response_denied(decision)
        if not denied and candidate.intent is Intent.ATTACK and self.reference(candidate.call):
            probe = self.sink_probe or self._default_sink
            canary.sink_hits.extend(probe(candidate.call))
        return canary
