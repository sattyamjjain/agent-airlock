"""The `sandbox=True` dispatch arm (v0.10.6).

Why this arm exists
-------------------
The headline block-rate in ``RESULTS.md`` was measured entirely on the **local** path. The
other arms in this package call the guards directly; nothing in the corpus ever went through
``@Airlock`` with ``sandbox=True``. That matters, because until v0.10.6 the sandbox dispatch
serialised the *undecorated* function into the micro-VM, so no ``Annotated`` validator ran on
that path at all: an operator who reached for ``sandbox=True`` on a dangerous tool, which is
exactly when a sandbox is reached for, got isolation and no argument contract. A number
measured only on the path that worked cannot detect that.

What this arm measures, and what it does not
--------------------------------------------
Two legs, reported separately because they are different claims:

* **Contract parity.** For each probe, does ``@Airlock(sandbox=True)`` reach the same verdict
  as ``@Airlock()``? This is the leg the fix changed. It runs on any machine, because the
  ``if self.sandbox:`` branch is taken whether or not a real backend is installed, and the
  parent-side validation now happens *before* ``_execute_in_sandbox`` is reached. With no
  backend that dispatch then fails, so a benign call comes back refused as ``sandbox_error``
  for an unrelated reason; :func:`_contract_refusal` separates the two so this arm never
  reports a backend failure as a contract block.
* **Backend execution.** Did a real isolation backend actually run the body? This needs E2B,
  the only backend ``@Airlock(sandbox=True)`` dispatches to, and is reported as **not-run**
  unless admitted calls actually returned from it, never folded into a pass rate.

Scope, stated rather than implied: the 210-item corpus carries no ``Annotated`` parameters,
so feeding it through a ``**kwargs`` tool would measure nothing and report a vacuous 100%.
The corpus items are therefore used for the leg the decorator genuinely decides (the
least-privilege **policy** leg), and the contract leg uses explicit probes, one per annotated
type. Items whose arguments are refused by the direct guard chain in the local arm are
counted as ``undeclared`` here rather than as passes: the decorator does not run those guards,
and saying so is worth more than a number that looks complete.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_airlock import (
    Airlock,
    HandleField,
    SafePath,
    SafeURL,
    SecurityPolicy,
    handle_run,
)

from .corpus import ToolCall, load_corpus

_PROBE_ISSUER = "blockrate.probe"
_PROBE_SCOPE = "workspace"


@dataclass(frozen=True)
class ContractProbe:
    """One annotated-contract case, run on both dispatch paths."""

    name: str
    annotated_type: str
    hostile: Any
    benign: Any


def _probes() -> tuple[ContractProbe, ...]:
    """One probe per annotated type the sandbox dispatch used to skip."""
    return (
        ContractProbe(
            "path traversal",
            "SafePath",
            Path("../../etc/passwd"),
            Path("/tmp/allowed.txt"),
        ),
        ContractProbe(
            "cloud metadata URL",
            "SafeURL",
            "http://169.254.169.254/latest/meta-data/",
            "https://api.example.com/v1/data",
        ),
        ContractProbe(
            "unissued capability handle",
            "HandleField",
            "ah_never-issued-anywhere",
            None,  # filled per-run: a handle must be minted inside the run
        ),
        ContractProbe("type coercion", "strict int", "7", 7),
    )


def _blocked(result: Any) -> bool:
    """A refusal is an AirlockResponse dict carrying a block_reason."""
    return isinstance(result, dict) and result.get("block_reason") is not None


def _contract_refusal(result: Any) -> bool:
    """True iff the *argument contract* refused this call, as opposed to the backend.

    This distinction is what lets the arm run on a machine with no isolation backend.
    With ``sandbox=True`` and no usable E2B backend, dispatch fails and every call, benign
    included, comes back refused as ``sandbox_error``. Counting that as a block would report
    a fake 100%.

    A contract refusal is distinguishable by its message: Pydantic refusals say
    ``"validation failed"`` and name the field, and a handle refusal carries its own
    ``BlockReason``. Both are produced *before* dispatch is attempted, which is the whole
    property this arm exists to measure.
    """
    if not _blocked(result):
        return False
    reason = str(result.get("block_reason", ""))
    if reason.startswith("handle_"):
        return True
    return "validation failed" in str(result.get("error", ""))


def _run_probe(probe: ContractProbe, *, sandbox: bool) -> tuple[bool, bool]:
    """Return ``(hostile_refused_by_contract, benign_passed_the_contract)``."""
    # Each stub's parameter is the thing under test: @Airlock checks it, and the body
    # never reads it. Hence the ARG001 pragmas, the same exemption tests/** has.
    if probe.annotated_type == "SafePath":

        @Airlock(sandbox=sandbox)
        def tool_path(target: SafePath) -> str:  # noqa: ARG001
            return "RAN"

        return (
            _contract_refusal(tool_path(target=probe.hostile)),
            not _contract_refusal(tool_path(target=probe.benign)),
        )

    if probe.annotated_type == "SafeURL":

        @Airlock(sandbox=sandbox)
        def tool_url(endpoint: SafeURL) -> str:  # noqa: ARG001
            return "RAN"

        return (
            _contract_refusal(tool_url(endpoint=probe.hostile)),
            not _contract_refusal(tool_url(endpoint=probe.benign)),
        )

    if probe.annotated_type == "HandleField":
        from agent_airlock import issue_handle

        @Airlock(sandbox=sandbox)
        def tool_handle(
            session: HandleField(issuer=_PROBE_ISSUER, scope=_PROBE_SCOPE),  # noqa: ARG001
        ) -> str:
            return "RAN"

        with handle_run("blockrate-probe"):
            hostile = _contract_refusal(tool_handle(session=probe.hostile))
            good = issue_handle(issuer=_PROBE_ISSUER, scope=_PROBE_SCOPE)
            benign = not _contract_refusal(tool_handle(session=good))
        return hostile, benign

    @Airlock(sandbox=sandbox)
    def tool_int(count: int) -> str:  # noqa: ARG001
        return "RAN"

    return (
        _contract_refusal(tool_int(count=probe.hostile)),
        not _contract_refusal(tool_int(count=probe.benign)),
    )


def _policy_refusal(result: Any) -> bool:
    """True iff the least-privilege *policy* refused this call, as opposed to the backend.

    With no isolation backend installed, a call the policy admits goes on to fail in
    dispatch on the sandbox path; that ``sandbox_error`` is not a policy verdict, so the
    policy leg compares this and not :func:`_blocked`.
    """
    return _blocked(result) and result.get("block_reason") == "policy_violation"


def _policy_tool(call: ToolCall, *, sandbox: bool) -> Any:
    """The decorator's least-privilege leg, exercised on one dispatch path.

    The policy decides on the tool's name, and ``@Airlock`` takes that name from the function
    it wraps, so the stub is renamed to the corpus item's tool before it is wrapped. Until
    0.10.23 it was not: every item reached the policy as ``invoke``, which no allow-list
    names, so both paths refused every item, the ones the allow-list admits included.
    """
    allow = [call.allowed_tool] if call.allowed_tool else []
    policy = SecurityPolicy(allowed_tools=allow, default_deny=True)

    # The stub never reads its argument; the policy decides on the name alone.
    def invoke(tool_name: str) -> str:  # noqa: ARG001
        return "RAN"

    invoke.__name__ = invoke.__qualname__ = call.tool_name
    return Airlock(sandbox=sandbox, policy=policy)(invoke)(tool_name=call.tool_name)


@dataclass
class SandboxArmReport:
    """Result of the sandbox-dispatch arm."""

    backend_name: str | None = None
    backend_available: bool = False
    backend_reason: str = ""
    # Admitted calls whose body returned from the backend. Availability is not execution:
    # the report says the backend ran only when this is above zero.
    backend_executions: int = 0

    policy_items: int = 0
    policy_agreements: int = 0
    # The agreements, split by verdict. Both must be non-zero for the parity to say anything:
    # until 0.10.23 every agreement was a refusal (see _policy_tool).
    policy_admitted: int = 0
    policy_refused: int = 0
    undeclared_items: int = 0

    probe_rows: list[dict[str, Any]] = field(default_factory=list)

    @property
    def probes_total(self) -> int:
        return len(self.probe_rows)

    @property
    def probes_blocked_on_sandbox(self) -> int:
        return sum(1 for r in self.probe_rows if r["sandbox_blocked"])

    @property
    def probes_in_parity(self) -> int:
        return sum(1 for r in self.probe_rows if r["parity"])

    @property
    def policy_parity_rate(self) -> float:
        return self.policy_agreements / self.policy_items if self.policy_items else 0.0

    @property
    def contract_block_rate(self) -> float:
        return self.probes_blocked_on_sandbox / self.probes_total if self.probes_total else 0.0

    @property
    def all_in_parity(self) -> bool:
        return (
            self.policy_agreements == self.policy_items
            and self.probes_in_parity == self.probes_total
        )


#: Appended to every not-run reason, because the reader's next question is "what about Docker".
_E2B_ONLY = "`@Airlock(sandbox=True)` dispatches only to E2B"


def _detect_backend() -> tuple[str | None, bool, str]:
    """Whether the one backend ``@Airlock(sandbox=True)`` dispatches to could run a body here.

    ``_execute_in_sandbox`` sends every call to E2B (``sandbox.execute_in_sandbox`` and its
    ``SandboxPool``); no Docker or Modal backend is on that path. So E2B is the only backend
    this arm reports, and only when dispatch's own preconditions hold: the SDK and cloudpickle
    import (``sandbox._missing_dependency``) and an API key is configured. Until 0.10.24 a
    Docker daemon that answered a ping counted as available, so the report could say a
    backend ran while every admitted call failed in dispatch, and a plain run pinged the
    local Docker daemon. Availability is still not execution: :func:`run_sandbox_arm` counts
    the calls that returned from the sandbox.
    """
    try:
        from agent_airlock import AirlockConfig
        from agent_airlock.sandbox import _missing_dependency
    except Exception as exc:  # pragma: no cover - import guard
        return None, False, f"agent_airlock.sandbox did not import ({type(exc).__name__})"

    missing = _missing_dependency()
    if missing is not None:
        return None, False, f"no E2B backend here ({missing.split('.')[0]}); {_E2B_ONLY}"
    if not AirlockConfig().e2b_api_key:
        return None, False, f"no E2B backend here (no E2B_API_KEY set); {_E2B_ONLY}"
    return "e2b", True, ""


def run_sandbox_arm() -> SandboxArmReport:
    """Run both legs and report them separately."""
    name, available, reason = _detect_backend()
    report = SandboxArmReport(backend_name=name, backend_available=available, backend_reason=reason)

    # Leg 1: the annotated contract, on both paths.
    for probe in _probes():
        local_hostile, local_benign = _run_probe(probe, sandbox=False)
        sandbox_hostile, sandbox_benign = _run_probe(probe, sandbox=True)
        report.probe_rows.append(
            {
                "name": probe.name,
                "type": probe.annotated_type,
                "local_blocked": local_hostile,
                "sandbox_blocked": sandbox_hostile,
                "benign_allowed_local": local_benign,
                "benign_allowed_sandbox": sandbox_benign,
                "parity": (local_hostile == sandbox_hostile) and (local_benign == sandbox_benign),
            }
        )

    # Leg 2: the policy leg over the real corpus, on both paths.
    for call in load_corpus():
        if call.allowed_tool is None:
            # No least-privilege allowlist to decide with, and no Annotated parameter
            # either: the decorator has nothing to enforce here. Counted, not claimed.
            report.undeclared_items += 1
            continue
        report.policy_items += 1
        local = _policy_refusal(_policy_tool(call, sandbox=False))
        # A policy denial is raised before dispatch, so it never reaches
        # _execute_in_sandbox; an admitted call that then fails there for want of a
        # backend is not a denial (_policy_refusal).
        sandboxed_result = _policy_tool(call, sandbox=True)
        sandboxed = _policy_refusal(sandboxed_result)
        if available and sandboxed_result == "RAN":
            # The body returned from the sandbox, so the backend executed it. Only counted
            # when the backend was detected: with agent_airlock.sandbox unimportable and
            # sandbox_required=False, the decorator runs the body in-process instead.
            report.backend_executions += 1
        if local == sandboxed:
            report.policy_agreements += 1
            if local:
                report.policy_refused += 1
            else:
                report.policy_admitted += 1

    return report
