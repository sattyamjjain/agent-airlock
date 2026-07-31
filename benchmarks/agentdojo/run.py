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
import math
import sys
import tempfile
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


def run_model(
    model_id: str,
    suites: tuple[str, ...],
    max_user_tasks: int,
    max_injection_tasks: int,
    deterministic_rate: float,
    logdir_arg: str | None = None,
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
# RESULTS.md rendering + CLI
# --------------------------------------------------------------------------- #


_MODEL_SECTION_PLACEHOLDER = """## Result 2 — model-in-the-loop utility-under-attack + ASR (the leaderboard metrics)

_Not yet run in this checkout._ The two metrics the AgentDojo leaderboard reports —
**utility under attack** (benign task still succeeds with the injection present) and
**ASR** (attack success rate) — require a real model-in-the-loop pass, which needs an
LLM API key and real API spend. To populate this section, run:

```bash
python -m benchmarks.agentdojo.run --model gpt-4o-mini-2024-07-18 \\
  --out benchmarks/agentdojo/RESULTS.md
```

with `OPENAI_API_KEY` set. That regenerates this file with a `baseline vs airlock`
table (benign utility / utility-under-attack / ASR / the utility cost of the defense)
for every pinned suite. No number is claimed here until that run produces it."""


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
    model_block = model_section or _MODEL_SECTION_PLACEHOLDER
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
    model_section: str | None = None
    if args.model:
        model_suites = (
            PINNED_SUITES
            if not args.suites
            else tuple(s.strip() for s in args.suites.split(",") if s.strip())
        )
        print(
            f"running model-in-the-loop pass ({args.model}) over "
            f"{' + '.join(model_suites)} — this needs an API key and spends real $. "
            f"caps: <= {args.max_user_tasks} user / <= {args.max_injection_tasks} injection tasks per suite.",
            file=sys.stderr,
        )
        model_section = run_model(
            args.model,
            model_suites,
            args.max_user_tasks,
            args.max_injection_tasks,
            report.combined_per_task_rate,
            logdir_arg=args.logdir,
        )

    md = render_results_md(report, model_section)
    out = args.out or (Path(__file__).parent / "RESULTS.md")
    out.write_text(md)
    print(f"wrote {out}")
    print(
        f"combined per-task block coverage: "
        f"{report.total_blocked_pairs}/{report.total_pairs} = {report.combined_per_task_rate:.1%}"
    )
    if model_section is not None:
        print("model-in-the-loop Result 2 section populated in RESULTS.md.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
