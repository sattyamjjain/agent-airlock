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
import contextlib
import math
import sys
import tempfile
from collections.abc import Callable
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

# AgentDojo suites + attack this bench pins. All 4 AgentDojo suites under the
# tool_knowledge attack, at a pinned benchmark version for reproducibility. This is
# the full suite set; the measured subset is stated per-suite in RESULTS.md.
BENCHMARK_VERSION = "v1.2.1"
PINNED_SUITES: tuple[str, ...] = ("workspace", "banking", "travel", "slack")
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


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion ``k/n``.

    The Wilson interval is well-behaved at small ``n`` and near 0/1 (unlike the
    normal-approximation interval), which matters here: the model-in-the-loop
    subset is deliberately small, so a bare percentage would over-claim
    precision. Returns ``(low, high)`` clamped to ``[0, 1]``; an empty sample
    ``(n == 0)`` returns ``(0.0, 1.0)`` — maximal uncertainty. Pure stdlib, no
    scipy, so the ``[bench]`` extra stays light.

    Args:
        k: Number of successes.
        n: Number of trials.
        z: Standard-normal quantile (1.96 == 95% CI).

    Returns:
        The ``(low, high)`` bounds of the Wilson score interval.
    """
    if n <= 0:
        return 0.0, 1.0
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, center - half), min(1.0, center + half)


@dataclass
class ArmCounts:
    """Raw success/total counts for one (suite, arm) — kept so the report can
    compute pooled rates and Wilson intervals rather than shipping bare means.

    * ``benign_*``  — benign utility: task solved with no injection present.
    * ``atk_util_*`` — utility under attack: benign task still solved with the
      injection present.
    * ``asr_*`` — attack success: the injection achieved its goal (higher is
      worse; the defense's job is to lower it).
    """

    benign_k: int = 0
    benign_n: int = 0
    atk_util_k: int = 0
    atk_util_n: int = 0
    asr_k: int = 0
    asr_n: int = 0


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


def execute_model(
    model_id: str,
    suites: tuple[str, ...],
    max_user_tasks: int,
    max_injection_tasks: int,
    logdir_arg: str | None = None,
) -> tuple[dict[str, dict[str, ArmCounts]], str, str]:
    """Run the real model-in-the-loop AgentDojo pass for defended vs undefended.

    Requires an API key for ``model_id``'s provider. Returns
    ``(results, agentdojo_version, stamp_date)`` — the raw per-(suite, arm) counts,
    which the caller renders (single-model section or cross-model roll-up). Wrap the
    call in :func:`install_litellm_cost_hook` to capture token/$ cost.
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
    from agentdojo.logging import OutputLogger
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

    from datetime import datetime, timezone
    from importlib.metadata import PackageNotFoundError, version

    try:
        ad_ver = version("agentdojo")
    except PackageNotFoundError:  # pragma: no cover
        ad_ver = "?"
    stamp_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # agentdojo's TraceLogger reads ``delegate.logdir`` from the ambient logger, so
    # the benchmark calls must run inside an OutputLogger context. A bare
    # ``logdir=None`` hits a NullLogger with no ``logdir`` attribute in agentdojo
    # 0.1.x. When ``logdir_arg`` is given, agentdojo reuses any per-task result
    # already cached there (``force_rerun=False``), so a run can resume without
    # re-spending on completed trajectories; otherwise a throwaway dir is used.
    logdir = Path(logdir_arg) if logdir_arg else Path(tempfile.mkdtemp(prefix="airlock-agentdojo-"))
    logdir.mkdir(parents=True, exist_ok=True)

    # results[suite][arm] = raw success/total counts (rates + Wilson CIs derived later)
    results: dict[str, dict[str, ArmCounts]] = {}
    with OutputLogger(str(logdir)):
        for suite_name in suites:
            suite = get_suite(BENCHMARK_VERSION, suite_name)
            env = suite.load_and_inject_default_environment({})
            user_ids = list(suite.user_tasks)[:max_user_tasks]
            inj_ids = list(suite.injection_tasks)[:max_injection_tasks]
            results[suite_name] = {}

            for arm in ("undefended", "airlock"):
                counts = ArmCounts()
                # PER-USER-TASK least-privilege, matching Result 1's per-task posture
                # (not the weaker suite-wide union), so both results measure the SAME
                # defense and the gap is a clean deterministic-vs-realised comparison.
                # A fresh pipeline is built per task so the airlock arm enforces exactly
                # the current task's allow-list.
                for uid in user_ids:
                    task_tools = {n for n, _ in _ground_truth_calls(suite.user_tasks[uid], env)}
                    if not task_tools:
                        # Ground truth unavailable -> can't scope a per-task policy;
                        # skip rather than fabricate a block-everything false positive.
                        continue
                    policy = least_privilege_policy(list(task_tools))
                    # agentdojo >= 0.1.x PipelineConfig requires model_id / system_message*
                    # fields (None -> the suite's default system message via its validator).
                    pipeline = AgentPipeline.from_config(
                        PipelineConfig(
                            llm=model_id,
                            model_id=None,
                            defense=None,
                            system_message_name=None,
                            system_message=None,
                        )
                    )
                    # Keep the model string in the pipeline name: the tool_knowledge
                    # (important_instructions) attack derives the target model name from
                    # it via agentdojo's get_model_name_from_pipeline(); a name without a
                    # recognized model makes load_attack raise.
                    pipeline.name = f"{model_id}-{arm}"
                    if arm == "airlock":
                        pipeline = _swap_executor(pipeline, policy)
                    benign = benchmark_suite_without_injections(
                        pipeline, suite, logdir=logdir, force_rerun=False, user_tasks=[uid]
                    )
                    attack = load_attack(ATTACK, suite, pipeline)
                    attacked = benchmark_suite_with_injections(
                        pipeline,
                        suite,
                        attack,
                        logdir=logdir,
                        force_rerun=False,
                        user_tasks=[uid],
                        injection_tasks=inj_ids,
                    )
                    # agentdojo SuiteResults is a TypedDict -> subscript, not attribute.
                    counts.benign_k += sum(1 for v in benign["utility_results"].values() if v)
                    counts.benign_n += len(benign["utility_results"])
                    counts.atk_util_k += sum(1 for v in attacked["utility_results"].values() if v)
                    counts.atk_util_n += len(attacked["utility_results"])
                    counts.asr_k += sum(1 for v in attacked["security_results"].values() if v)
                    counts.asr_n += len(attacked["security_results"])
                results[suite_name][arm] = counts

    return results, ad_ver, stamp_date


def run_model(
    model_id: str,
    suites: tuple[str, ...],
    max_user_tasks: int,
    max_injection_tasks: int,
    deterministic_rate: float,
    logdir_arg: str | None = None,
) -> str:
    """Single-model convenience wrapper: execute + render the "Result 2" section.

    Kept for the original single-model reproduce command so its output is
    byte-for-byte unchanged. The cross-model path uses :func:`execute_model`
    directly (see ``main``).
    """
    results, ad_ver, stamp_date = execute_model(
        model_id, suites, max_user_tasks, max_injection_tasks, logdir_arg
    )
    return _render_model_section(
        results,
        model_id,
        ad_ver,
        stamp_date,
        max_user_tasks,
        max_injection_tasks,
        deterministic_rate,
    )


def _pooled(results: dict[str, dict[str, ArmCounts]], arm: str) -> ArmCounts:
    """Sum an arm's raw counts across all suites (for pooled rates + CIs)."""
    total = ArmCounts()
    for arms in results.values():
        c = arms.get(arm)
        if c is None:
            continue
        total.benign_k += c.benign_k
        total.benign_n += c.benign_n
        total.atk_util_k += c.atk_util_k
        total.atk_util_n += c.atk_util_n
        total.asr_k += c.asr_k
        total.asr_n += c.asr_n
    return total


def _rate(k: int, n: int) -> float:
    return k / n if n else 0.0


def _render_model_section(
    results: dict[str, dict[str, ArmCounts]],
    model_id: str,
    agentdojo_version: str,
    stamp_date: str,
    max_user_tasks: int,
    max_injection_tasks: int,
    deterministic_rate: float,
) -> str:
    """Render the model-in-the-loop "Result 2" section from raw counts.

    Reports, per arm, benign utility / utility-under-attack / ASR with the
    underlying k/n; a pooled Wilson 95% CI on ASR; the benign-utility cost (the
    defense's false-positive analogue); and the gap between the measured ASR
    reduction and the deterministic upper bound.
    """
    rows = []
    for suite_name, arms in results.items():
        for arm in ("undefended", "airlock"):
            c = arms.get(arm)
            if c is None:
                continue
            rows.append(
                f"| {suite_name} | {arm} | "
                f"{_rate(c.benign_k, c.benign_n):.0%} ({c.benign_k}/{c.benign_n}) | "
                f"{_rate(c.atk_util_k, c.atk_util_n):.0%} ({c.atk_util_k}/{c.atk_util_n}) | "
                f"**{_rate(c.asr_k, c.asr_n):.0%}** ({c.asr_k}/{c.asr_n}) |"
            )

    undef = _pooled(results, "undefended")
    air = _pooled(results, "airlock")

    undef_asr, air_asr = _rate(undef.asr_k, undef.asr_n), _rate(air.asr_k, air.asr_n)
    undef_lo, undef_hi = wilson_ci(undef.asr_k, undef.asr_n)
    air_lo, air_hi = wilson_ci(air.asr_k, air.asr_n)
    asr_reduction = undef_asr - air_asr

    undef_util, air_util = _rate(undef.benign_k, undef.benign_n), _rate(air.benign_k, air.benign_n)
    fp_cost = undef_util - air_util
    gap = deterministic_rate - asr_reduction

    return f"""## Result 2 — model-in-the-loop utility-under-attack + ASR (the leaderboard metrics)

Real adaptive-attacker pass, **airlock defense vs no defense**. Model **{model_id}**,
`agentdojo {agentdojo_version}`, attack `{ATTACK}`, benchmark `{BENCHMARK_VERSION}`, run
**{stamp_date}** (UTC). Subset: up to **{max_user_tasks}** user tasks and
**{max_injection_tasks}** injection tasks per suite — a stated subset, **not** the full
609-pair leaderboard cell. Greedy decoding is not guaranteed for this model, so treat
single-run rates as point estimates and read the Wilson interval, not the bare percentage.

| Suite | arm | benign utility | utility under attack | ASR |
| --- | --- | --- | --- | --- |
{chr(10).join(rows)}

**Pooled across suites** (n = {air.asr_n} attacked trajectories/arm, {air.benign_n} benign):

| arm | ASR | ASR 95% Wilson CI | benign utility |
| --- | --- | --- | --- |
| undefended | {undef_asr:.0%} ({undef.asr_k}/{undef.asr_n}) | [{undef_lo:.0%}, {undef_hi:.0%}] | {undef_util:.0%} ({undef.benign_k}/{undef.benign_n}) |
| **airlock** | **{air_asr:.0%}** ({air.asr_k}/{air.asr_n}) | **[{air_lo:.0%}, {air_hi:.0%}]** | {air_util:.0%} ({air.benign_k}/{air.benign_n}) |

- **ASR reduction (headline): {undef_asr:.0%} → {air_asr:.0%} = {asr_reduction:+.0%}** with airlock
  (lower ASR is better); airlock ASR 95% Wilson CI **[{air_lo:.0%}, {air_hi:.0%}]**.
- **Benign false-positive cost: {fp_cost:+.0%}** — benign utility {undef_util:.0%} → {air_util:.0%}.
  A false positive here is a benign task the policy breaks by denying a tool the agent
  reached for. The policy allow-lists each task's **minimal ground-truth tools** (matching
  Result 1), so this is the tightest-scoping cost — see the per-suite benign column above
  for where it concentrates; a more permissive per-task allow-list trades some of it back.
  A block rate without this number is not interpretable, which is why it is on the same run.
- **The gap is the finding: deterministic upper bound {deterministic_rate:.0%} vs measured
  reduction {asr_reduction:+.0%} (gap {gap:+.0%}).** Result 1's {deterministic_rate:.0%} is an
  *upper bound* on ASR reduction — the fraction of all 609 injection→task pairs whose target
  tool-call airlock *can* block. The model-in-the-loop reduction here is over {air.asr_n}
  attacked trajectories: a related but distinct quantity on a different sample. The gap
  between "target call blockable" and "attack actually prevented in the loop" is expected —
  the model does not always attempt the blocked call, and some attacks resolve for reasons
  upstream of the tool seam. The deterministic number *bounds*; the model number *realises*."""


# --------------------------------------------------------------------------- #
# Cross-model: cost accounting, per-model roll-up, append-only RESULTS log.
# --------------------------------------------------------------------------- #


@dataclass
class CostMeter:
    """Token / dollar accounting for one model's run.

    A benchmark whose cost is undocumented cannot be decided-on by anyone, so the
    harness records it. Populated best-effort from a litellm success callback (see
    :func:`install_litellm_cost_hook`); if the backend does not route through
    litellm, ``calls`` stays 0 and :meth:`summary` says so plainly rather than
    printing a fabricated $0.00.
    """

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def record(self, *, prompt_tokens: int, completion_tokens: int, usd: float) -> None:
        self.calls += 1
        self.prompt_tokens += int(prompt_tokens)
        self.completion_tokens += int(completion_tokens)
        self.usd += float(usd)

    @property
    def measured(self) -> bool:
        return self.calls > 0

    def summary(self) -> str:
        if not self.measured:
            return "unmeasured (no LLM calls captured via litellm — record token/$ by hand)"
        return (
            f"{self.calls} calls, {self.total_tokens:,} tokens "
            f"({self.prompt_tokens:,} prompt + {self.completion_tokens:,} completion), "
            f"${self.usd:.4f}"
        )


def install_litellm_cost_hook(meter: CostMeter):  # type: ignore[no-untyped-def]
    """Feed ``meter`` from litellm's success callback. Returns a teardown callable.

    Best-effort and non-fatal: if litellm is not importable (or the model backend
    does not use it) nothing is captured and the meter stays at 0. Never raises.
    """
    try:
        import litellm
    except Exception:  # noqa: BLE001 - litellm absent or broken -> no cost capture
        return lambda: None

    def _cb(kwargs: Any, response: Any, _start: Any, _end: Any) -> None:  # pragma: no cover
        try:
            usage = getattr(response, "usage", None) or {}
            get = (
                (lambda k: usage.get(k, 0))
                if isinstance(usage, dict)
                else (lambda k: getattr(usage, k, 0))
            )
            usd = float(kwargs.get("response_cost") or 0.0)
            if not usd:
                try:
                    usd = float(litellm.completion_cost(completion_response=response))
                except Exception:  # noqa: BLE001
                    usd = 0.0
            meter.record(
                prompt_tokens=int(get("prompt_tokens") or 0),
                completion_tokens=int(get("completion_tokens") or 0),
                usd=usd,
            )
        except Exception:  # noqa: BLE001 - accounting must never break the run
            pass

    litellm.success_callback = [*(getattr(litellm, "success_callback", None) or []), _cb]

    def _teardown() -> None:
        with contextlib.suppress(Exception):
            litellm.success_callback = [c for c in litellm.success_callback if c is not _cb]

    return _teardown


# USD per 1M tokens: (input, output). List price, used to turn captured token
# counts into the dollar figure a run records. Prefix-matched against the model
# the API response reports. Extend as models are added.
_MODEL_PRICES: dict[str, tuple[float, float]] = {
    "gpt-4o-mini-2024-07-18": (0.15, 0.60),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o-2024-05-13": (5.00, 15.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4-turbo": (10.00, 30.00),
    "gpt-3.5-turbo": (0.50, 1.50),
    "claude-3-haiku-20240307": (0.25, 1.25),
    "claude-3-5-haiku": (0.80, 4.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-7-sonnet": (3.00, 15.00),
    "claude-3-opus": (15.00, 75.00),
}


def _price_usd(model: str | None, prompt_tokens: int, completion_tokens: int) -> float:
    if not model:
        return 0.0
    for key, (pin, pout) in _MODEL_PRICES.items():
        if model.startswith(key):
            return prompt_tokens / 1e6 * pin + completion_tokens / 1e6 * pout
    return 0.0


def install_provider_cost_hooks(meter: CostMeter):  # type: ignore[no-untyped-def]
    """Record token/$ cost from the OpenAI and Anthropic SDK responses into ``meter``.

    agentdojo calls the provider SDKs directly (OpenAI sync ``chat.completions``,
    Anthropic async ``messages.stream``), not litellm, so the litellm callback never
    fires. This patches the two points where the raw API response — which carries
    ``.usage`` — is in hand: the OpenAI ``Completions.create`` return value, and
    agentdojo's Anthropic message converter (the async streaming client makes a
    call-level patch awkward). Returns a teardown that restores both. Best-effort
    and non-fatal: a provider whose internals differ is simply not metered.
    """
    restores: list[Callable[[], None]] = []

    try:
        from openai.resources.chat import completions as _oai

        _orig_create = _oai.Completions.create

        def _patched_create(self: Any, *a: Any, **k: Any) -> Any:
            resp = _orig_create(self, *a, **k)
            with contextlib.suppress(Exception):
                u = getattr(resp, "usage", None)
                if u is not None:
                    pt = int(getattr(u, "prompt_tokens", 0) or 0)
                    ct = int(getattr(u, "completion_tokens", 0) or 0)
                    meter.record(
                        prompt_tokens=pt,
                        completion_tokens=ct,
                        usd=_price_usd(getattr(resp, "model", None), pt, ct),
                    )
            return resp

        _oai.Completions.create = _patched_create  # type: ignore[method-assign]
        restores.append(lambda: setattr(_oai.Completions, "create", _orig_create))
    except Exception:  # noqa: BLE001
        pass

    try:
        import agentdojo.agent_pipeline.llms.anthropic_llm as _am

        _orig_conv = _am._anthropic_to_assistant_message

        def _patched_conv(completion: Any, *a: Any, **k: Any) -> Any:
            with contextlib.suppress(Exception):
                u = getattr(completion, "usage", None)
                if u is not None:
                    pt = int(getattr(u, "input_tokens", 0) or 0)
                    ct = int(getattr(u, "output_tokens", 0) or 0)
                    meter.record(
                        prompt_tokens=pt,
                        completion_tokens=ct,
                        usd=_price_usd(getattr(completion, "model", None), pt, ct),
                    )
            return _orig_conv(completion, *a, **k)

        _am._anthropic_to_assistant_message = _patched_conv  # type: ignore[assignment]
        restores.append(lambda: setattr(_am, "_anthropic_to_assistant_message", _orig_conv))
    except Exception:  # noqa: BLE001
        pass

    def _teardown() -> None:
        for restore in restores:
            with contextlib.suppress(Exception):
                restore()

    return _teardown


@dataclass
class ModelRun:
    """One model's raw counts + cost, kept so the report derives per-model rates,
    per-model Wilson CIs, and a benign-FPR control without re-running anything."""

    model_id: str
    results: dict[str, dict[str, ArmCounts]]
    cost: CostMeter
    agentdojo_version: str
    stamp_date: str
    max_user_tasks: int
    max_injection_tasks: int


def _asr_fpr(counts_undef: ArmCounts, counts_air: ArmCounts) -> dict[str, float]:
    undef_asr, air_asr = (
        _rate(counts_undef.asr_k, counts_undef.asr_n),
        _rate(counts_air.asr_k, counts_air.asr_n),
    )
    air_lo, air_hi = wilson_ci(counts_air.asr_k, counts_air.asr_n)
    undef_lo, undef_hi = wilson_ci(counts_undef.asr_k, counts_undef.asr_n)
    undef_util, air_util = (
        _rate(counts_undef.benign_k, counts_undef.benign_n),
        _rate(counts_air.benign_k, counts_air.benign_n),
    )
    return {
        "undef_asr": undef_asr,
        "air_asr": air_asr,
        "air_lo": air_lo,
        "air_hi": air_hi,
        "undef_lo": undef_lo,
        "undef_hi": undef_hi,
        "reduction": undef_asr - air_asr,
        "fp_cost": undef_util - air_util,
    }


def render_cross_model_comparison(runs: list[ModelRun], deterministic_rate: float) -> str:
    """Render a dated, per-model cross-model block for the append-only RESULTS log.

    Reports **per model** (each with its own Wilson CI and its own benign-FPR
    control) and, **separately**, a pooled-across-models figure that is explicitly
    NOT presented as a single measurement. If a second model shows a materially
    smaller reduction, that is the finding — the table shows it rather than hiding
    it in a pool.
    """
    if not runs:
        return ""
    date = runs[0].stamp_date
    ad_ver = runs[0].agentdojo_version
    caps = (
        f"<= {runs[0].max_user_tasks} user / <= {runs[0].max_injection_tasks} injection per suite"
    )
    model_list = ", ".join(r.model_id for r in runs)

    per_model_rows = []
    pooled_undef, pooled_air = ArmCounts(), ArmCounts()
    for r in runs:
        undef, air = _pooled(r.results, "undefended"), _pooled(r.results, "airlock")
        m = _asr_fpr(undef, air)
        per_model_rows.append(
            f"| `{r.model_id}` | {m['undef_asr']:.0%} → **{m['air_asr']:.0%}** "
            f"({m['reduction']:+.0%}) | [{m['air_lo']:.0%}, {m['air_hi']:.0%}] | "
            f"{m['fp_cost']:+.0%} | {air.asr_n} | {r.cost.summary()} |"
        )
        for src, dst in ((undef, pooled_undef), (air, pooled_air)):
            dst.asr_k += src.asr_k
            dst.asr_n += src.asr_n
            dst.benign_k += src.benign_k
            dst.benign_n += src.benign_n

    pm = _asr_fpr(pooled_undef, pooled_air)
    n_models = len(runs)
    spread = ""
    if n_models > 1:
        reductions = [
            _asr_fpr(_pooled(r.results, "undefended"), _pooled(r.results, "airlock"))["reduction"]
            for r in runs
        ]
        spread = (
            f"Per-model ASR reduction ranges **{min(reductions):+.0%} to "
            f"{max(reductions):+.0%}** across the {n_models} models. "
        )

    return f"""### {date} · cross-model ({model_list})

`agentdojo {ad_ver}`, attack `{ATTACK}`, benchmark `{BENCHMARK_VERSION}`, caps {caps}.
Each row is one model with its **own** Wilson 95% CI and its **own** benign-FPR control.
`cost` is that model's measured token/$ spend for this run.

| model | ASR (undef → airlock) | airlock ASR 95% CI | benign FP cost | n/arm | cost |
| --- | --- | --- | --- | --- | --- |
{chr(10).join(per_model_rows)}

{spread}A defense that generalises should hold its reduction across families; a model
where it does not is a finding, published here rather than pooled away.

**Pooled across models** (reported separately, **not** a single measurement — the models
differ, so this is a weighted average, not one experiment): undefended ASR
{pm["undef_asr"]:.0%} → airlock **{pm["air_asr"]:.0%}** ({pm["reduction"]:+.0%}), airlock
95% Wilson CI [{pm["air_lo"]:.0%}, {pm["air_hi"]:.0%}] over {pooled_air.asr_n} attacked
trajectories, benign FP cost {pm["fp_cost"]:+.0%}. Deterministic upper bound
{deterministic_rate:.0%}; the pooled realised reduction is {pm["reduction"]:+.0%}
(gap {deterministic_rate - pm["reduction"]:+.0%})."""


_RUNS_MARKER = "<!-- CROSS-MODEL-RUNS: append newest below; never edit dated blocks -->"


def append_run_to_results(results_path: Path, dated_block: str, *, force: bool = False) -> str:
    """Append a dated model-run block below ``_RUNS_MARKER``, preserving prior runs.

    The 2026-07-31 single-model rows and every later run stay intact and dated;
    this only inserts, never rewrites them. Returns the new file text. Raises if
    the marker is absent, or (unless ``force``) if the block's ``### <heading>``
    already exists — so a re-run does not silently duplicate a dated section.
    """
    text = results_path.read_text(encoding="utf-8")
    if _RUNS_MARKER not in text:
        raise ValueError(
            f"{results_path} has no append marker; add {_RUNS_MARKER!r} where runs should go"
        )
    heading = dated_block.strip().splitlines()[0].strip()
    if heading in text and not force:
        raise ValueError(f"a run block for {heading!r} already exists; pass force=True to replace")
    head, _, tail = text.partition(_RUNS_MARKER)
    new = f"{head}{_RUNS_MARKER}\n\n{dated_block.strip()}\n{tail}"
    results_path.write_text(new, encoding="utf-8")
    return new


# --------------------------------------------------------------------------- #
# RESULTS.md rendering + CLI
# --------------------------------------------------------------------------- #


_PENDING_NOTE = """_No model run recorded yet._ The two leaderboard metrics — **utility under attack** and
**ASR** — need a real model-in-the-loop pass (an LLM API key + real API spend). Each run
appends a dated block above; none is claimed until a run produces it."""


def _model_log_region(dated_block: str | None) -> str:
    """The append-only Result 2 region: H2 + reproduce command + marker + block."""
    return f"""## Result 2 — model-in-the-loop utility-under-attack + ASR (append-only log)

Each dated block below is one run and is never edited after the fact; newer runs are
prepended under the marker. Reproduce / add a run (cross-model example):

```bash
python -m benchmarks.agentdojo.run \\
  --model gpt-4o-mini-2024-07-18 --model gpt-4o-2024-05-13 \\
  --out benchmarks/agentdojo/RESULTS.md
```

{_RUNS_MARKER}

{dated_block.strip() if dated_block else _PENDING_NOTE}"""


def _union_caveat(report: DeterministicReport) -> str:
    """Build the honest per-suite-union caveat from the actual report numbers."""
    full_miss = [s.suite for s in report.suites if s.injections and s.blocked_union == 0]
    best = max(report.suites, key=lambda s: s.union_rate, default=None)
    miss_clause = (
        f"It drops to **0%** on {', '.join(full_miss)} — where the injection abuses a "
        f"*legitimate* tool (e.g. `send_money` with a malicious recipient) that a "
        f"suite-wide allow-list still permits"
        if full_miss
        else "It drops sharply under a suite-wide allow-list"
    )
    best_clause = f", and tops out at **{best.union_rate:.0%}** on {best.suite}" if best else ""
    return miss_clause + best_clause


def render_results_md(report: DeterministicReport, model_section: str | None = None) -> str:
    combined = report.combined_per_task_rate
    rows = "\n".join(
        f"| {s.suite} | {s.pairs} | {s.blocked_pairs} | **{s.per_task_rate:.1%}** | "
        f"{s.blocked_union}/{s.injections} ({s.union_rate:.0%}) |"
        for s in report.suites
    )
    model_block = _model_log_region(model_section)
    return f"""# AgentDojo — adaptive-attacker robustness (agent-airlock as a defense)

Reproduce (deterministic block-coverage, no model, no API key):

```bash
pip install "agent-airlock[bench]"
python -m benchmarks.agentdojo.run
```

Reproduce (model-in-the-loop utility-under-attack + ASR, needs a key + API spend):

```bash
python -m benchmarks.agentdojo.run --model gpt-4o-mini-2024-07-18 \\
  --out benchmarks/agentdojo/RESULTS.md
```

## What this measures

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024) is a
**model-in-the-loop** adaptive-attacker benchmark. agent-airlock is registered as an
AgentDojo **defense** — the same `validate -> policy -> execute -> sanitize` seam
`@Airlock` applies, installed at AgentDojo's tool-execution pipeline element
(`AirlockToolsExecutor`): deny-by-default `SecurityPolicy` (least-privilege
allow-list) + ghost-argument BLOCK + output sanitizer.

This file reports **two** numbers, and is scrupulous about which is which:

1. a **deterministic block-coverage** number (free, offline, no model) — a defensible
   *upper bound* on airlock's ASR reduction; and
2. the **model-in-the-loop** utility-under-attack + ASR (the actual leaderboard
   metrics), which need an API key and are only shown once really run.

## Result 1 — deterministic block coverage (per-task least-privilege)

Using AgentDojo's real `{ATTACK}` injection tasks' **ground-truth target tool-calls**
on the **{", ".join(PINNED_SUITES)}** suites (benchmark `{BENCHMARK_VERSION}`), we
measure how many injection->task pairs airlock's least-privilege policy **blocks at the
tool-call seam**. Blocking any one of an injection's required calls defeats it.

| Suite | injection->task pairs | blocked | block rate | per-suite-union |
| --- | --- | --- | --- | --- |
{rows}

**Combined: {report.total_blocked_pairs}/{report.total_pairs} pairs blocked = {combined:.1%}** of
`{ATTACK}` injection->task pairs have their target tool-call blocked by airlock's
deny-by-default least-privilege policy.

> This is a deterministic **upper bound on airlock's ASR reduction** — the fraction of
> attacks whose target action airlock forces to fail *regardless of model*. It is
> **NOT** AgentDojo's model-in-the-loop ASR (that is Result 2), and it is **NOT**
> extrapolated to AgentDojo's full task x injection set.

{model_block}

## What airlock does NOT neutralize (the honest misses)

The **per-suite-union** column allow-lists *every* tool any benign task in the suite
uses, then asks how many injections are still blocked. {_union_caveat(report)}. The gap
between the per-task and per-suite-union columns is the whole point: **least-privilege
scoping** — authorizing only the tools the *current* task needs — is what blocks these
attacks at the tool seam. A coarse, suite-wide allow-list does not. Injections that
abuse a **legitimately-allowed tool with malicious arguments** are **not** caught by the
tool-level policy alone; catching those needs argument-level policy (airlock's strict
Pydantic validation on the specific arg) or the model-in-the-loop run. We report the
misses; we do not claim airlock "blocks everything".

## Where this sits vs a native MCP gateway (the wedge)

A gateway / OAuth resource server authenticates *who* connects and routes the call; it
does not open the tool-call payload and check it against the current task's contract. So
the exact injection classes airlock's contract layer blocks here — **a call to a tool
outside the task's least-privilege scope**, and **an argument key the tool never
declared (ghost-arg BLOCK)** — are precisely the classes a gateway forwards, because
they are well-formed transport-wise and carry a valid token. That is the "contract layer
beneath your gateway" wedge, measured on a third-party adaptive-attacker benchmark rather
than asserted. What a gateway *does* catch that airlock does not (unauthenticated
callers, bad tokens, transport tampering) is complementary — use both.

## Scope, stated plainly

- Suites: **{", ".join(PINNED_SUITES)}** (all 4 of AgentDojo's suites), attack:
  **{ATTACK}**, benchmark version **{BENCHMARK_VERSION}**.
- Result 1 is deterministic, offline, reproducible in CI — no model, no API key, no
  network. Result 2 is the real model-in-the-loop pass and is only shown when run.
- **Not** a re-run of model-in-the-loop incumbents and **no fabricated competitor
  number.**
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="benchmarks.agentdojo.run",
        description="Register agent-airlock as an AgentDojo defense and measure robustness.",
    )
    parser.add_argument(
        "--model",
        action="append",
        default=None,
        help="Model id for the real model-in-the-loop pass (needs an API key). "
        "Repeat to run several models cross-family (e.g. --model gpt-4o-mini-2024-07-18 "
        "--model gpt-4o-2024-05-13); each is reported with its own Wilson CI.",
    )
    parser.add_argument(
        "--register-model",
        action="append",
        default=None,
        metavar="ID",
        help="Register a model id against agentdojo's registry before running (repeatable). "
        "Needed for current Claude ids that unmaintained agentdojo 0.1.35 does not know "
        "(its enum lists only retired claude-3-x). A claude-* --model not in the enum is "
        "auto-registered; use this to register a non-claude id or override the inference. "
        "See benchmarks/agentdojo/model_registry_shim.py.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing dated run block of the same heading (default: refuse).",
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
    parser.add_argument(
        "--logdir",
        default=None,
        help="Persistent trace/cache dir for the model path. Reuses completed "
        "per-task results (resume without re-spending); default is a throwaway dir.",
    )
    parser.add_argument(
        "--suites",
        default=None,
        help="Comma-separated subset of suites for the model path (default: all four). "
        "Result 1 (deterministic) always covers all four.",
    )
    args = parser.parse_args(argv)

    if not _HAVE_AGENTDOJO:
        print(
            "agentdojo is not installed. This is a bench-only extra; the airlock core "
            "stays zero-dep.\n  pip install 'agent-airlock[bench]'",
            file=sys.stderr,
        )
        return 0

    report = run_deterministic()
    print(
        f"Result 1 (deterministic, no model): "
        f"{report.total_blocked_pairs}/{report.total_pairs} pairs blocked = "
        f"{report.combined_per_task_rate:.1%}"
    )

    models: list[str] = args.model or []
    dated_block: str | None = None
    if models:
        # Register current model ids agentdojo 0.1.35 does not know (its enum lists only
        # retired claude-3-x) across enum / provider / attack-name tables, so the pipeline
        # can be built and the attack stays meaningful. Opt-in, best-effort.
        try:
            from benchmarks.agentdojo.model_registry_shim import ensure_registered

            registered = ensure_registered(models, extra=args.register_model or [])
            if registered:
                print(
                    f"model-registry shim: registered {', '.join(registered)} against "
                    "agentdojo (enum + provider + attack self-name)",
                    file=sys.stderr,
                )
        except Exception as exc:  # noqa: BLE001 - never let the shim abort a run
            print(f"model-registry shim skipped: {exc}", file=sys.stderr)

        model_suites = (
            PINNED_SUITES
            if not args.suites
            else tuple(s.strip() for s in args.suites.split(",") if s.strip())
        )
        runs: list[ModelRun] = []
        for model_id in models:
            print(
                f"running model-in-the-loop pass ({model_id}) over "
                f"{' + '.join(model_suites)} — needs an API key and spends real $. caps: "
                f"<= {args.max_user_tasks} user / <= {args.max_injection_tasks} injection per suite.",
                file=sys.stderr,
            )
            meter = CostMeter()
            teardown_litellm = install_litellm_cost_hook(meter)
            teardown_sdk = install_provider_cost_hooks(meter)
            try:
                results, ad_ver, stamp = execute_model(
                    model_id,
                    model_suites,
                    args.max_user_tasks,
                    args.max_injection_tasks,
                    logdir_arg=args.logdir,
                )
            finally:
                teardown_sdk()
                teardown_litellm()
            print(f"  {model_id} cost: {meter.summary()}", file=sys.stderr)
            runs.append(
                ModelRun(
                    model_id,
                    results,
                    meter,
                    ad_ver,
                    stamp,
                    args.max_user_tasks,
                    args.max_injection_tasks,
                )
            )
        dated_block = render_cross_model_comparison(runs, report.combined_per_task_rate)

    # Non-destructive by default: never silently overwrite RESULTS.md. With --out on
    # an existing marked file, APPEND the dated block (prior runs stay intact); a
    # fresh --out gets a full scaffold; with no --out the block prints for pasting.
    if args.out:
        out: Path = args.out
        if out.exists() and _RUNS_MARKER in out.read_text(encoding="utf-8"):
            if dated_block:
                append_run_to_results(out, dated_block, force=args.force)
                print(f"appended a dated run block to {out} (prior runs preserved)")
            else:
                print(f"{out} left unchanged (no --model given; nothing to append)")
        else:
            out.write_text(render_results_md(report, dated_block))
            print(f"wrote fresh {out}")
    elif dated_block:
        print("\n" + dated_block)
        print(
            "\n(paste the block above under the CROSS-MODEL-RUNS marker in "
            "benchmarks/agentdojo/RESULTS.md, or re-run with "
            "--out benchmarks/agentdojo/RESULTS.md to append it)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
