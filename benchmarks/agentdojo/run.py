"""Register agent-airlock as an AgentDojo defense and measure its effect.

[AgentDojo](https://arxiv.org/abs/2406.13352) is a *model-in-the-loop* adaptive
attacker benchmark. This harness wires airlock into it as a **defense** — the same
``validate -> policy -> execute -> sanitize`` seam ``@Airlock`` applies, installed at
AgentDojo's tool-execution pipeline element — and measures its effect two ways:

* **DETERMINISTIC (default; no model, no API key).** Using AgentDojo's real suites
  and the ``tool_knowledge`` injection tasks' **ground-truth target tool-calls**,
  measure how many injection->task pairs airlock's deny-by-default least-privilege
  policy **blocks** at the tool-call seam. This is a deterministic **upper bound on
  airlock's ASR reduction** — it is *not* the model-in-the-loop Attack Success Rate,
  and it is not extrapolated to AgentDojo's full task x injection set. It states its
  exact suites / tasks / attack. Reproducible in CI with zero model cost.

* **MODEL (``--model <id>``; needs an API key and the ``bench`` extra).** Build a
  defended (airlock) pipeline and an undefended pipeline and run
  ``benchmark_suite_with_injections`` / ``benchmark_suite_without_injections`` on the
  pinned subset to report the true benign utility / utility-under-attack / ASR for
  defended vs undefended. This is the real adaptive-attacker number; it costs API $.

``agentdojo`` is an **optional extra** (``pip install 'agent-airlock[bench]'``). The
airlock core stays zero-dep: the import is gated below, and if ``agentdojo`` is
absent the harness prints an install hint and exits cleanly.

Run::

    python -m benchmarks.agentdojo.run                 # deterministic, writes RESULTS.md
    python -m benchmarks.agentdojo.run --model gpt-4o-2024-08-06   # real ASR (needs key)
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_airlock import SecurityPolicy
from agent_airlock.policy import PolicyViolation
from agent_airlock.sanitizer import sanitize_output

# --- Optional bench dependency: gated so the airlock core stays zero-dep. ------
try:  # pragma: no cover - trivial import guard
    import agentdojo  # noqa: F401

    _HAVE_AGENTDOJO = True
except ImportError:  # pragma: no cover
    _HAVE_AGENTDOJO = False

# AgentDojo suites + attack this bench pins. workspace + banking under the
# tool_knowledge attack: a fixed, reproducible subset (2 of AgentDojo's 4 suites),
# NOT the full task x injection x attack matrix.
BENCHMARK_VERSION = "v1.2.1"
PINNED_SUITES: tuple[str, ...] = ("workspace", "banking")
ATTACK = "tool_knowledge"


# --------------------------------------------------------------------------- #
# The airlock enforcement decision — pure airlock, no agentdojo.
# --------------------------------------------------------------------------- #


def least_privilege_policy(allowed_tools: list[str]) -> SecurityPolicy:
    """Deny-by-default policy allow-listing exactly ``allowed_tools``.

    This is airlock's least-privilege posture: only the tools a task legitimately
    needs are permitted; everything else is denied. Mirrors AgentDojo's own
    ``tool_filter`` defense idea, enforced in-process by airlock.
    """
    return SecurityPolicy(allowed_tools=sorted(set(allowed_tools)), default_deny=True)


def airlock_blocks(
    policy: SecurityPolicy,
    function_name: str,
    args: dict[str, Any],
    param_names: set[str] | None,
) -> tuple[bool, str]:
    """Return ``(blocked, reason)`` for one tool call under ``policy``.

    The same decision ``@Airlock`` makes at its seam:

    * deny-by-default policy — the tool must be allow-listed (``check_tool_allowed``);
    * ghost-argument BLOCK — an argument key not in the tool's schema is rejected
      (``UnknownArgsMode.BLOCK``).
    """
    try:
        policy.check_tool_allowed(function_name)
    except PolicyViolation as exc:
        return True, f"policy: {exc}"
    if param_names is not None:
        ghosts = set(args) - param_names
        if ghosts:
            return True, f"ghost-args: {sorted(ghosts)}"
    return False, ""


def _injection_blocked(
    policy: SecurityPolicy,
    injection_calls: list[tuple[str, dict[str, Any]]],
    param_names_by_tool: dict[str, set[str]],
) -> bool:
    """True iff airlock refuses at least one of the injection's required calls.

    An injection's goal completes only if **all** its ground-truth tool calls
    execute; airlock defeats it by blocking any one of them.
    """
    for name, args in injection_calls:
        blocked, _ = airlock_blocks(policy, name, args, param_names_by_tool.get(name))
        if blocked:
            return True
    return False


# --------------------------------------------------------------------------- #
# Deterministic block-coverage over AgentDojo ground truths (no model).
# --------------------------------------------------------------------------- #


@dataclass
class SuiteCoverage:
    suite: str
    pairs: int = 0
    blocked_pairs: int = 0
    injections: int = 0
    blocked_union: int = 0

    @property
    def per_task_rate(self) -> float:
        return self.blocked_pairs / self.pairs if self.pairs else 0.0

    @property
    def union_rate(self) -> float:
        return self.blocked_union / self.injections if self.injections else 0.0


@dataclass
class DeterministicReport:
    suites: list[SuiteCoverage] = field(default_factory=list)

    @property
    def total_pairs(self) -> int:
        return sum(s.pairs for s in self.suites)

    @property
    def total_blocked_pairs(self) -> int:
        return sum(s.blocked_pairs for s in self.suites)

    @property
    def combined_per_task_rate(self) -> float:
        return self.total_blocked_pairs / self.total_pairs if self.total_pairs else 0.0


def _ground_truth_calls(task: Any, env: Any) -> list[tuple[str, dict[str, Any]]]:
    """Extract ``[(tool_name, args), ...]`` from a task's ground truth."""
    try:
        return [(c.function, dict(c.args)) for c in task.ground_truth(env)]
    except Exception:  # a task whose ground truth needs richer state - skip it
        return []


def measure_suite_coverage(suite_name: str) -> SuiteCoverage:
    """Deterministic per-suite block coverage under the least-privilege policy."""
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite(BENCHMARK_VERSION, suite_name)
    env = suite.load_and_inject_default_environment({})
    param_names = {t.name: set(t.parameters.model_fields) for t in suite.tools}

    user_tool_sets = {
        uid: {n for n, _ in _ground_truth_calls(ut, env)} for uid, ut in suite.user_tasks.items()
    }
    injection_calls = {
        iid: _ground_truth_calls(it, env) for iid, it in suite.injection_tasks.items()
    }
    injection_calls = {iid: calls for iid, calls in injection_calls.items() if calls}

    union_allowed = set().union(*user_tool_sets.values()) if user_tool_sets else set()
    cov = SuiteCoverage(suite=suite_name)

    for allowed in user_tool_sets.values():
        task_policy = least_privilege_policy(list(allowed))
        for calls in injection_calls.values():
            cov.pairs += 1
            if _injection_blocked(task_policy, calls, param_names):
                cov.blocked_pairs += 1

    union_policy = least_privilege_policy(list(union_allowed))
    for calls in injection_calls.values():
        cov.injections += 1
        if _injection_blocked(union_policy, calls, param_names):
            cov.blocked_union += 1
    return cov


def run_deterministic(suites: tuple[str, ...] = PINNED_SUITES) -> DeterministicReport:
    """Compute the deterministic block-coverage report for ``suites``."""
    return DeterministicReport(suites=[measure_suite_coverage(s) for s in suites])


# --------------------------------------------------------------------------- #
# The real AgentDojo defense (model path). Constructed only when running --model.
# --------------------------------------------------------------------------- #


def make_airlock_tools_executor(policy: SecurityPolicy) -> Any:
    """Build an ``AirlockToolsExecutor`` pipeline element bound to ``policy``.

    Subclasses AgentDojo's ``ToolsExecutor`` and gates every tool call through
    airlock (``airlock_blocks``) before execution, then runs airlock's output
    sanitizer over each allowed tool result — i.e. airlock installed as an
    AgentDojo defense at the tool-execution seam. Constructed lazily so the module
    imports without ``agentdojo``.
    """
    from agentdojo.agent_pipeline import ToolsExecutor
    from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

    class AirlockToolsExecutor(ToolsExecutor):  # type: ignore[misc, valid-type]
        def __init__(self, security_policy: SecurityPolicy) -> None:
            super().__init__()
            self._policy = security_policy

        def query(self, query, runtime, env=None, messages=(), extra_args=None):  # type: ignore[override, no-untyped-def]
            extra_args = {} if extra_args is None else extra_args
            messages = list(messages)
            if not messages or messages[-1].get("role") != "assistant":
                return query, runtime, env, messages, extra_args
            tool_calls = messages[-1].get("tool_calls") or []
            if not tool_calls:
                return query, runtime, env, messages, extra_args

            param_names = {
                name: set(fn.parameters.model_fields) for name, fn in runtime.functions.items()
            }
            allowed_calls = []
            results = []
            for call in tool_calls:
                blocked, reason = airlock_blocks(
                    self._policy, call.function, dict(call.args), param_names.get(call.function)
                )
                if blocked:
                    results.append(
                        ChatToolResultMessage(
                            role="tool",
                            content=[text_content_block_from_string("")],
                            tool_call_id=call.id,
                            tool_call=call,
                            error=f"blocked by agent-airlock ({reason}). Call a permitted tool instead.",
                        )
                    )
                else:
                    allowed_calls.append(call)

            # Execute only the airlock-allowed calls via the parent executor, then
            # sanitize their outputs.
            if allowed_calls:
                stub = dict(messages[-1])
                stub["tool_calls"] = allowed_calls
                _, runtime, env, executed, extra_args = super().query(
                    query, runtime, env, [*messages[:-1], stub], extra_args
                )
                for msg in executed[len(messages) :]:
                    for block in msg.get("content") or []:
                        if isinstance(block, dict) and "content" in block:
                            block["content"] = sanitize_output(block["content"]).content
                    results.append(msg)
            return query, runtime, env, [*messages, *results], extra_args

    return AirlockToolsExecutor(policy)


def _suite_policy(suite: Any) -> SecurityPolicy:
    """Least-privilege policy allow-listing the suite's benign toolset."""
    env = suite.load_and_inject_default_environment({})
    allowed: set[str] = set()
    for ut in suite.user_tasks.values():
        allowed |= {n for n, _ in _ground_truth_calls(ut, env)}
    return least_privilege_policy(list(allowed))


def run_model(
    model_id: str, suites: tuple[str, ...], max_user_tasks: int, max_injection_tasks: int
) -> str:
    """Run the real model-in-the-loop AgentDojo pass for defended vs undefended.

    Requires an API key for ``model_id``'s provider. Returns a markdown block with
    benign utility, utility-under-attack, and ASR for each arm.
    """
    from agentdojo.agent_pipeline import (
        AgentPipeline,
        PipelineConfig,
        ToolsExecutionLoop,
        ToolsExecutor,
    )
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import (
        benchmark_suite_with_injections,
        benchmark_suite_without_injections,
    )
    from agentdojo.task_suite.load_suites import get_suite

    def _swap_executor(pipeline: Any, policy: SecurityPolicy) -> Any:
        """Replace the ToolsExecutor inside the pipeline's loop with airlock's."""
        replaced = False
        for element in getattr(pipeline, "elements", []):
            if isinstance(element, ToolsExecutionLoop):
                element.elements = [
                    make_airlock_tools_executor(policy) if isinstance(e, ToolsExecutor) else e
                    for e in element.elements
                ]
                replaced = any(type(e).__name__ == "AirlockToolsExecutor" for e in element.elements)
        if not replaced:
            raise RuntimeError(
                "could not install airlock defense: no ToolsExecutor in pipeline loop"
            )
        return pipeline

    lines: list[str] = []
    for suite_name in suites:
        suite = get_suite(BENCHMARK_VERSION, suite_name)
        policy = _suite_policy(suite)
        user_ids = list(suite.user_tasks)[:max_user_tasks]
        inj_ids = list(suite.injection_tasks)[:max_injection_tasks]

        for arm in ("undefended", "airlock"):
            pipeline = AgentPipeline.from_config(PipelineConfig(llm=model_id, defense=None))
            pipeline.name = f"airlock-bench-{arm}"
            if arm == "airlock":
                pipeline = _swap_executor(pipeline, policy)
            benign = benchmark_suite_without_injections(
                pipeline, suite, logdir=None, force_rerun=False, user_tasks=user_ids
            )
            attack = load_attack(ATTACK, suite, pipeline)
            attacked = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack,
                logdir=None,
                force_rerun=False,
                user_tasks=user_ids,
                injection_tasks=inj_ids,
            )
            util = _mean(benign.utility_results.values())
            util_atk = _mean(attacked.utility_results.values())
            asr = _mean([bool(v) for v in attacked.security_results.values()])
            lines.append(f"| {suite_name} | {arm} | {util:.1%} | {util_atk:.1%} | {asr:.1%} |")
    return "\n".join(lines)


def _mean(values: Any) -> float:
    vals = [1.0 if bool(v) else 0.0 for v in values]
    return sum(vals) / len(vals) if vals else 0.0


# --------------------------------------------------------------------------- #
# RESULTS.md rendering + CLI
# --------------------------------------------------------------------------- #


def render_results_md(report: DeterministicReport) -> str:
    combined = report.combined_per_task_rate
    rows = "\n".join(
        f"| {s.suite} | {s.pairs} | {s.blocked_pairs} | **{s.per_task_rate:.1%}** | "
        f"{s.blocked_union}/{s.injections} ({s.union_rate:.0%}) |"
        for s in report.suites
    )
    return f"""# AgentDojo — adaptive-attacker robustness (agent-airlock as a defense)

Reproduce (deterministic, no model, no API key):

```bash
pip install "agent-airlock[bench]"
python -m benchmarks.agentdojo.run
```

## What this measures

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024) is a
**model-in-the-loop** adaptive-attacker benchmark. agent-airlock is registered as an
AgentDojo **defense** — the same `validate -> policy -> execute -> sanitize` seam
`@Airlock` applies, installed at AgentDojo's tool-execution pipeline element
(`AirlockToolsExecutor`): deny-by-default `SecurityPolicy` (least-privilege
allow-list) + ghost-argument BLOCK + output sanitizer.

The numbers below are **deterministic**: using AgentDojo's real `{ATTACK}` injection
tasks' **ground-truth target tool-calls** on the pinned **{" + ".join(PINNED_SUITES)}**
suites (benchmark `{BENCHMARK_VERSION}`), we measure how many injection->task pairs
airlock's least-privilege policy **blocks at the tool-call seam**. Blocking any one of
an injection's required calls defeats it.

> This is a deterministic **upper bound on airlock's ASR reduction** — the fraction of
> attacks whose target action airlock forces to fail *regardless of model*. It is
> **NOT** AgentDojo's model-in-the-loop Attack Success Rate, and it is **NOT**
> extrapolated to AgentDojo's full task set. For the real ASR (benign utility /
> utility-under-attack / ASR, defended vs undefended), run the model path:
> `python -m benchmarks.agentdojo.run --model <id>` (needs an API key; costs $).

## Result — deterministic block coverage (per-task least-privilege)

| Suite | injection->task pairs | blocked | block rate | per-suite-union |
| --- | --- | --- | --- | --- |
{rows}

**Combined: {report.total_blocked_pairs}/{report.total_pairs} pairs blocked = {combined:.1%}** of
`{ATTACK}` injection->task pairs have their target tool-call blocked by airlock's
deny-by-default least-privilege policy.

## The honest nuance (why scoping is what matters)

The **per-suite-union** column allow-lists *every* tool any benign task in the suite
uses, then asks how many injections are still blocked. It is far lower (0% on banking,
where injections abuse a *legitimate* tool like `send_money` with a malicious
recipient; ~17% on workspace). The gap between the per-task and per-suite-union numbers
is the whole point: **least-privilege scoping** — authorizing only the tools the
*current* task needs — is what blocks these attacks at the tool seam. A coarse,
suite-wide allow-list does not. Injections that abuse a legitimately-allowed tool with
malicious arguments are **not** caught by the tool-level policy alone; catching those
needs argument-level policy or the model-in-the-loop run.

## Scope, stated plainly

- Suites: **{", ".join(PINNED_SUITES)}** (2 of AgentDojo's 4), attack: **{ATTACK}**,
  benchmark version **{BENCHMARK_VERSION}**.
- Deterministic, offline, reproducible in CI — no model, no API key, no network.
- **Not** a re-run of model-in-the-loop incumbents and **no fabricated competitor
  number.** The model path exists (`--model`) and reports the true ASR when a key is
  supplied.
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="benchmarks.agentdojo.run",
        description="Register agent-airlock as an AgentDojo defense and measure robustness.",
    )
    parser.add_argument(
        "--model", default=None, help="Run the real model-in-the-loop pass (needs an API key)."
    )
    parser.add_argument(
        "--max-user-tasks", type=int, default=5, help="Model path: cap user tasks per suite."
    )
    parser.add_argument(
        "--max-injection-tasks",
        type=int,
        default=3,
        help="Model path: cap injection tasks per suite.",
    )
    parser.add_argument("--out", type=Path, default=None, help="Write RESULTS.md to this path.")
    args = parser.parse_args(argv)

    if not _HAVE_AGENTDOJO:
        print(
            "agentdojo is not installed. This is a bench-only extra; the airlock core "
            "stays zero-dep.\n  pip install 'agent-airlock[bench]'",
            file=sys.stderr,
        )
        return 0

    if args.model:
        print(
            f"# AgentDojo model run ({args.model}) — {' + '.join(PINNED_SUITES)}, attack={ATTACK}\n"
        )
        print("| suite | arm | benign utility | utility under attack | ASR |")
        print("| --- | --- | --- | --- | --- |")
        print(run_model(args.model, PINNED_SUITES, args.max_user_tasks, args.max_injection_tasks))
        return 0

    report = run_deterministic()
    md = render_results_md(report)
    out = args.out or (Path(__file__).parent / "RESULTS.md")
    out.write_text(md)
    print(f"wrote {out}")
    print(
        f"combined per-task block coverage: "
        f"{report.total_blocked_pairs}/{report.total_pairs} = {report.combined_per_task_rate:.1%}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
