"""Register agent-airlock as an AgentDojo defense and measure its effect.

[AgentDojo](https://arxiv.org/abs/2406.13352) is a *model-in-the-loop* indirect
prompt-injection benchmark. The attack this harness runs is AgentDojo's fixed-template
``tool_knowledge`` attack (a ``FixedJailbreakAttack``: one template, filled with the
injection goal and its target tool sequence), not an adaptive attacker that searches
against the defense. The harness wires airlock into AgentDojo as a **defense** — the same
``validate -> policy -> execute -> sanitize`` seam ``@Airlock`` applies, installed at
AgentDojo's tool-execution pipeline element — and measures its effect two ways:

* **DETERMINISTIC (default; no model, no API key).** Using AgentDojo's real suites and the
  ``tool_knowledge`` injection tasks' **ground-truth target tool-calls**, measure how many
  injection->task pairs airlock's deny-by-default least-privilege policy **blocks** at the
  tool-call seam. Some injections' ground truth lists no tool call (at v1.2.1: workspace
  ``injection_task_6``-``13``, whose exfiltration goals are scored on the environment, and
  travel ``injection_task_6``, which asks only for text), so the bound has no target call to
  check on their pairs; the census reports them beside the blocked count, so the bound is
  never read as covering every attacked pair. This is a deterministic **upper bound on
  airlock's ASR reduction** over the pairs that do have a target — not the
  model-in-the-loop Attack Success Rate. Reproducible in CI with zero model cost.

* **MODEL (``--model <id> --run``; the ``bench`` extra and an API key).** Build a defended
  (airlock) pipeline and an undefended pipeline and run the pinned subset to report the
  true benign utility / utility-under-attack / ASR for defended vs undefended, under the
  same fixed-template attack. Without ``--run`` a ``--model`` invocation is a dry run: it
  prints the plan (episodes, pairs per arm, estimated cost) and sends nothing. A paid run
  needs ``--budget-usd`` and a new, empty ``--logdir``. Claude 5.x ids go through
  ``claude_patch.py``, because unpatched agentdojo 0.1.35 cannot call them.

``agentdojo`` is an **optional extra** (``pip install 'agent-airlock[bench]'``). The
airlock core stays zero-dep: the import is gated below, and if ``agentdojo`` is absent the
harness prints an install hint and exits cleanly.

Run::

    python -m benchmarks.agentdojo.run                 # deterministic, free
    python -m benchmarks.agentdojo.run --model claude-haiku-5-5         # dry run: plan + cost
    ANTHROPIC_API_KEY=... python -m benchmarks.agentdojo.run --model claude-haiku-5-5 \\
        --run --budget-usd 10 --logdir ~/.cache/agent-airlock-bench/runs/agentdojo/h55
"""

from __future__ import annotations

import argparse
import contextlib
import json
import math
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import NormalDist
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

REPO_ROOT = Path(__file__).resolve().parents[2]

# AgentDojo suites + attack this bench pins. All 4 AgentDojo suites under the
# tool_knowledge attack, at a pinned benchmark version for reproducibility. This is
# the full suite set; the measured subset is stated per-suite in RESULTS.md.
BENCHMARK_VERSION = "v1.2.1"
PINNED_SUITES: tuple[str, ...] = ("workspace", "banking", "travel", "slack")
ATTACK = "tool_knowledge"

# The v1.2.1 census, recomputed by measure_suite_coverage() and pinned by
# tests/test_agentdojo_coverage_census.py. Used where a renderer has no report in hand.
V121_ALL_PAIRS = 949
"""Every user task x injection task pair the four v1.2.1 suites define."""
V121_TARGET_PAIRS = 609
"""Pairs whose injection's ground truth names a tool call; for the other 340 it names none."""

DEFAULT_MAX_USER_TASKS = 14
"""14 user x 3 injection tasks x 4 suites = 168 pairs per arm, over the 163 the power
calculation asks for (``power_sample_size(0.45, 0.30)``); 13 gave 156, short of it."""
DEFAULT_MAX_INJECTION_TASKS = 3
LEGACY_MAX_USER_TASKS = 5
"""The 2026-07-31 and 2026-08-08 passes ran 5 user tasks per suite (60 pairs per arm)."""

# Dry-run cost model. Trajectory shape measured on earlier AgentDojo runs: 4.36-6.78 LLM
# calls per episode, ~1.8K input tokens per call (the 2026-08-08 gpt-4o pass averaged
# 904,170 / 523 = 1,729), and Claude's 5.x tokenizer counts ~1.3x OpenAI's tokens for the
# same text. Output per call (visible + thinking) uses the shared infra's 300 / 1,300
# assumptions (benchmarks._claude.batch.plan_cost). Pilots replace all of it with measured
# usage; until then it only sizes the reservation.
CALLS_PER_EPISODE: tuple[float, float] = (4.36, 6.78)
INPUT_TOKENS_PER_CALL = 1_800
CLAUDE_TOKENIZER_FACTOR = 1.3
OUTPUT_TOKENS_PER_CALL: tuple[int, int] = (300, 1_300)
RESERVE_MARGIN = 1.5
"""A paid pass reserves its high estimate x this margin (capped at the budget left) and
stops if spend reaches the reservation; the finished trajectories stay resumable."""

MANIFEST_NAME = "airlock_run.json"
CALLS_LOG_NAME = "claude_calls.jsonl"
_MANIFEST_KEYS = (
    "model",
    "effort",
    "max_tokens",
    "thinking",
    "attack",
    "benchmark_version",
    "suites",
    "max_user_tasks",
    "max_injection_tasks",
    "defense",
    "agentdojo_version",
)
"""The settings that define what a pass measures; ``--resume`` requires all to match."""
_DEFENSE = "per-task least-privilege allow-list + ghost-argument BLOCK + output sanitizer"


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


def _injection_block_reason(
    policy: SecurityPolicy,
    injection_calls: list[tuple[str, dict[str, Any]]],
    param_names_by_tool: dict[str, set[str]],
) -> str | None:
    """The reason airlock refuses the first of an injection's required calls, or ``None``."""
    for name, args in injection_calls:
        blocked, reason = airlock_blocks(policy, name, args, param_names_by_tool.get(name))
        if blocked:
            return reason
    return None


def _injection_blocked(
    policy: SecurityPolicy,
    injection_calls: list[tuple[str, dict[str, Any]]],
    param_names_by_tool: dict[str, set[str]],
) -> bool:
    """True iff airlock refuses at least one of the injection's required calls.

    An injection's goal completes only if **all** its ground-truth tool calls
    execute; airlock defeats it by blocking any one of them.
    """
    return _injection_block_reason(policy, injection_calls, param_names_by_tool) is not None


# --------------------------------------------------------------------------- #
# Deterministic block-coverage over AgentDojo ground truths (no model).
# --------------------------------------------------------------------------- #


def _task_sort_key(task_id: str) -> tuple[str, int]:
    """``injection_task_10`` sorts after ``injection_task_6``."""
    match = re.match(r"^(.*?)(\d+)$", task_id)
    if match is None:
        return task_id, -1
    return match.group(1), int(match.group(2))


@dataclass
class SuiteCoverage:
    """Deterministic coverage for one suite.

    ``pairs`` / ``injections`` count only injections that name a tool call (the policy's
    reach); ``all_pairs`` counts every user x injection pair the suite defines, so the
    difference is the pairs no tool-call policy can check.
    """

    suite: str
    pairs: int = 0
    blocked_pairs: int = 0
    injections: int = 0
    blocked_union: int = 0
    all_pairs: int = 0
    untargeted_injections: list[str] = field(default_factory=list)
    """Injection tasks whose ground truth names no tool call."""
    unreadable_injections: list[str] = field(default_factory=list)
    """Injection tasks whose ground truth raised (counted with the untargeted pairs)."""
    ghost_arg_blocks: int = 0
    """Blocked pairs whose refusing check was a ghost-argument BLOCK, not the allow-list."""

    @property
    def per_task_rate(self) -> float:
        return self.blocked_pairs / self.pairs if self.pairs else 0.0

    @property
    def union_rate(self) -> float:
        return self.blocked_union / self.injections if self.injections else 0.0

    @property
    def untargeted_pairs(self) -> int:
        return self.all_pairs - self.pairs


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

    @property
    def total_all_pairs(self) -> int:
        return sum(s.all_pairs for s in self.suites)

    @property
    def total_untargeted_pairs(self) -> int:
        return sum(s.untargeted_pairs for s in self.suites)

    @property
    def total_ghost_arg_blocks(self) -> int:
        return sum(s.ghost_arg_blocks for s in self.suites)


def _ground_truth_calls(task: Any, env: Any) -> list[tuple[str, dict[str, Any]]]:
    """Extract ``[(tool_name, args), ...]`` from a task's ground truth."""
    try:
        return [(c.function, dict(c.args)) for c in task.ground_truth(env)]
    except Exception:  # a task whose ground truth needs richer state - skip it
        return []


def _classify_ground_truth(task: Any, env: Any) -> tuple[str, list[tuple[str, dict[str, Any]]]]:
    """``("calls", [...])``, ``("empty", [])`` (names no tool call) or ``("raised", [])``."""
    try:
        calls = [(c.function, dict(c.args)) for c in task.ground_truth(env)]
    except Exception:  # noqa: BLE001 - reported as unreadable, never silently dropped
        return "raised", []
    return ("calls" if calls else "empty"), calls


def measure_suite_coverage(suite_name: str) -> SuiteCoverage:
    """Deterministic per-suite block coverage under the least-privilege policy.

    Also enumerates every injection task, so the pairs whose injection names no tool call
    are counted (``all_pairs`` / ``untargeted_injections``) rather than silently dropped.
    """
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite(BENCHMARK_VERSION, suite_name)
    env = suite.load_and_inject_default_environment({})
    param_names = {t.name: set(t.parameters.model_fields) for t in suite.tools}

    user_tool_sets = {
        uid: {n for n, _ in _ground_truth_calls(ut, env)} for uid, ut in suite.user_tasks.items()
    }
    classified = {iid: _classify_ground_truth(it, env) for iid, it in suite.injection_tasks.items()}
    injection_calls = {iid: calls for iid, (kind, calls) in classified.items() if kind == "calls"}

    union_allowed = set().union(*user_tool_sets.values()) if user_tool_sets else set()
    cov = SuiteCoverage(
        suite=suite_name,
        all_pairs=len(user_tool_sets) * len(classified),
        untargeted_injections=sorted(
            (iid for iid, (kind, _) in classified.items() if kind == "empty"), key=_task_sort_key
        ),
        unreadable_injections=sorted(
            (iid for iid, (kind, _) in classified.items() if kind == "raised"), key=_task_sort_key
        ),
    )

    for allowed in user_tool_sets.values():
        task_policy = least_privilege_policy(list(allowed))
        for calls in injection_calls.values():
            cov.pairs += 1
            reason = _injection_block_reason(task_policy, calls, param_names)
            if reason is not None:
                cov.blocked_pairs += 1
                if reason.startswith("ghost-args"):
                    cov.ghost_arg_blocks += 1

    union_policy = least_privilege_policy(list(union_allowed))
    for calls in injection_calls.values():
        cov.injections += 1
        if _injection_blocked(union_policy, calls, param_names):
            cov.blocked_union += 1
    return cov


def run_deterministic(suites: tuple[str, ...] = PINNED_SUITES) -> DeterministicReport:
    """Compute the deterministic block-coverage report for ``suites``."""
    return DeterministicReport(suites=[measure_suite_coverage(s) for s in suites])


def compact_task_ids(task_ids: list[str]) -> str:
    """``[injection_task_6, ..., injection_task_13]`` -> ``injection_task_6-13``."""
    keyed = sorted({_task_sort_key(t) for t in task_ids}, key=lambda k: (k[0], k[1]))
    parts: list[str] = []
    i = 0
    while i < len(keyed):
        prefix, start = keyed[i]
        if start < 0:  # no numeric suffix: the id as it is
            parts.append(prefix)
            i += 1
            continue
        end = start
        while i + 1 < len(keyed) and keyed[i + 1][0] == prefix and keyed[i + 1][1] == end + 1:
            i += 1
            end = keyed[i][1]
        parts.append(f"{prefix}{start}" if start == end else f"{prefix}{start}-{end}")
        i += 1
    return ", ".join(parts)


def render_coverage_census(report: DeterministicReport) -> str:
    """The blocked count beside the full pair census, as one line of text.

    ``524/609`` is never shown without ``out of 949 attacked pairs``: the bound covers only
    the pairs whose injection names a tool call.
    """
    untargeted = "; ".join(
        f"{s.suite} {compact_task_ids(s.untargeted_injections + s.unreadable_injections)}"
        for s in report.suites
        if s.untargeted_injections or s.unreadable_injections
    )
    detail = f" ({untargeted})" if untargeted else ""
    return (
        f"{report.total_blocked_pairs}/{report.total_pairs} pairs blocked = "
        f"{report.combined_per_task_rate:.1%}, out of {report.total_all_pairs} attacked pairs; "
        f"{report.total_untargeted_pairs} pairs have no tool-call target the policy can "
        f"check{detail}"
    )


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


@dataclass
class TaskSelection:
    """The tasks a model pass runs in one suite (identical in both arms)."""

    suite: str
    user_ids: list[str]
    injection_ids: list[str]
    untargeted: list[str] = field(default_factory=list)
    """Selected injection tasks whose ground truth names no tool call (Result 1 cannot score
    them; one that asks only for text, like travel ``injection_task_6``, no tool-call policy
    can block)."""
    skipped_user_ids: list[str] = field(default_factory=list)
    """User tasks dropped because their ground truth names no tool (no policy to scope)."""

    @property
    def pairs(self) -> int:
        return len(self.user_ids) * len(self.injection_ids)

    @property
    def targeted_pairs(self) -> int:
        return len(self.user_ids) * (len(self.injection_ids) - len(self.untargeted))


def _select_tasks(
    suite: Any, env: Any, max_user_tasks: int, max_injection_tasks: int
) -> tuple[TaskSelection, dict[str, set[str]]]:
    """The first ``max_*`` tasks in agentdojo's own order, plus each user task's tools."""
    user_ids = list(suite.user_tasks)[:max_user_tasks]
    inj_ids = list(suite.injection_tasks)[:max_injection_tasks]
    task_tools = {
        uid: {n for n, _ in _ground_truth_calls(suite.user_tasks[uid], env)} for uid in user_ids
    }
    selection = TaskSelection(
        suite=suite.name,
        user_ids=[uid for uid in user_ids if task_tools[uid]],
        injection_ids=inj_ids,
        untargeted=[
            iid
            for iid in inj_ids
            if not _ground_truth_calls(suite.get_injection_task_by_id(iid), env)
        ],
        skipped_user_ids=[uid for uid in user_ids if not task_tools[uid]],
    )
    return selection, task_tools


def select_tasks(
    suites: tuple[str, ...], max_user_tasks: int, max_injection_tasks: int
) -> list[TaskSelection]:
    """What a model pass with these caps runs, suite by suite (needs ``agentdojo``)."""
    from agentdojo.task_suite.load_suites import get_suite

    out = []
    for suite_name in suites:
        suite = get_suite(BENCHMARK_VERSION, suite_name)
        env = suite.load_and_inject_default_environment({})
        out.append(_select_tasks(suite, env, max_user_tasks, max_injection_tasks)[0])
    return out


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
    call in :func:`install_provider_cost_hooks` (or, for Claude 5.x, ``claude_patch``)
    to capture token/$ cost.

    Episodes run user task by user task with both arms interleaved, so a pass stopped
    early (budget cap, API error) leaves the arms balanced to within one user task, and
    the arms' identical opening requests share the prompt cache. Each user task's
    injections run through ``run_task_with_injection_tasks`` directly:
    ``benchmark_suite_with_injections`` would first run every selected injection task as
    a benign user task, an unscored sanity check that costs real episodes.
    """
    from agentdojo.agent_pipeline import (
        AgentPipeline,
        PipelineConfig,
        ToolsExecutionLoop,
        ToolsExecutor,
    )
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import (
        benchmark_suite_without_injections,
        run_task_with_injection_tasks,
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

    from importlib.metadata import PackageNotFoundError, version

    try:
        ad_ver = version("agentdojo")
    except PackageNotFoundError:  # pragma: no cover
        ad_ver = "?"
    stamp_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # agentdojo's TraceLogger reads ``delegate.logdir`` from the ambient logger, so
    # the benchmark calls must run inside an OutputLogger context. A bare
    # ``logdir=None`` hits a NullLogger with no ``logdir`` attribute in agentdojo
    # 0.1.x. agentdojo reuses any per-task result already cached in ``logdir``
    # (``force_rerun=False``) and its cache key ignores the policy and the LLM settings,
    # so a paid run (``main``) only ever passes a new, empty directory or a ``--resume``
    # whose recorded settings match; otherwise a throwaway dir is used.
    logdir = Path(logdir_arg) if logdir_arg else Path(tempfile.mkdtemp(prefix="airlock-agentdojo-"))
    logdir.mkdir(parents=True, exist_ok=True)

    arms = ("undefended", "airlock")
    # results[suite][arm] = raw success/total counts (rates + Wilson CIs derived later)
    results: dict[str, dict[str, ArmCounts]] = {}
    with OutputLogger(str(logdir)):
        for suite_name in suites:
            suite = get_suite(BENCHMARK_VERSION, suite_name)
            env = suite.load_and_inject_default_environment({})
            selection, task_tools = _select_tasks(suite, env, max_user_tasks, max_injection_tasks)
            counts = {arm: ArmCounts() for arm in arms}
            results[suite_name] = counts

            # PER-USER-TASK least-privilege, matching Result 1's per-task posture
            # (not the weaker suite-wide union), so both results measure the SAME
            # defense and the gap is a clean deterministic-vs-realised comparison.
            # A fresh pipeline is built per task so the airlock arm enforces exactly
            # the current task's allow-list. User tasks whose ground truth names no
            # tool were dropped by _select_tasks rather than given a block-everything
            # policy that would fabricate false positives.
            for uid in selection.user_ids:
                policy = least_privilege_policy(list(task_tools[uid]))
                for arm in arms:
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
                        pipeline,
                        suite,
                        logdir=logdir,
                        force_rerun=False,
                        user_tasks=[uid],
                        benchmark_version=BENCHMARK_VERSION,
                    )
                    attack = load_attack(ATTACK, suite, pipeline)
                    atk_utility, atk_security = run_task_with_injection_tasks(
                        suite,
                        pipeline,
                        suite.get_user_task_by_id(uid),
                        attack,
                        logdir,
                        False,
                        selection.injection_ids,
                        BENCHMARK_VERSION,
                    )
                    # agentdojo SuiteResults is a TypedDict -> subscript, not attribute.
                    c = counts[arm]
                    c.benign_k += sum(1 for v in benign["utility_results"].values() if v)
                    c.benign_n += len(benign["utility_results"])
                    c.atk_util_k += sum(1 for v in atk_utility.values() if v)
                    c.atk_util_n += len(atk_utility)
                    c.asr_k += sum(1 for v in atk_security.values() if v)
                    c.asr_n += len(atk_security)

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

    Kept for the original single-model reproduce command. The cross-model path uses
    :func:`execute_model` directly (see ``main``).
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
    *,
    target_pairs: int = V121_TARGET_PAIRS,
    all_pairs: int = V121_ALL_PAIRS,
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

Real model-in-the-loop pass under AgentDojo's fixed-template `{ATTACK}` attack (the same
template every episode, not an adaptive attacker), **airlock defense vs no defense**. Model
**{model_id}**, `agentdojo {agentdojo_version}`, benchmark `{BENCHMARK_VERSION}`, run
**{stamp_date}** (UTC). Subset: up to **{max_user_tasks}** user tasks and
**{max_injection_tasks}** injection tasks per suite — a stated subset, **not** the full
cell ({all_pairs} attacked pairs, of which {target_pairs} have a tool-call target). Greedy
decoding is not guaranteed for this model, so treat single-run rates as point estimates and
read the Wilson interval, not the bare percentage.

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
  *upper bound* on ASR reduction — the fraction of the {target_pairs} injection→task pairs with
  a tool-call target (of {all_pairs}) whose target call airlock *can* block. The
  model-in-the-loop reduction here is over {air.asr_n}
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
    harness records it. Fed by the provider SDK hooks (:func:`install_provider_cost_hooks`),
    by ``claude_patch`` for Claude 5.x (its USD is the shared ledger's exact-id price,
    cache reads and writes included), or by a litellm callback. If nothing is captured,
    :meth:`summary` says so plainly rather than printing a fabricated $0.00, and a call
    with no list price makes the dollar figure read "unmeasured", never $0.0000.
    """

    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd: float = 0.0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    unpriced_calls: int = 0
    unpriced_models: set[str] = field(default_factory=set)

    @property
    def total_tokens(self) -> int:
        return (
            self.prompt_tokens
            + self.completion_tokens
            + self.cache_read_tokens
            + self.cache_write_tokens
        )

    def record(
        self,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        usd: float | None,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
        model: str | None = None,
    ) -> None:
        """Add one call. ``usd=None`` means the model has no list price (not free)."""
        self.calls += 1
        self.prompt_tokens += int(prompt_tokens)
        self.completion_tokens += int(completion_tokens)
        self.cache_read_tokens += int(cache_read_tokens)
        self.cache_write_tokens += int(cache_write_tokens)
        if usd is None:
            self.unpriced_calls += 1
            self.unpriced_models.add(model or "unknown model")
        else:
            self.usd += float(usd)

    @property
    def measured(self) -> bool:
        return self.calls > 0

    def summary(self) -> str:
        if not self.measured:
            return "unmeasured (no LLM calls captured — record token/$ by hand)"
        if self.cache_read_tokens or self.cache_write_tokens:
            breakdown = (
                f"{self.prompt_tokens:,} uncached input + {self.cache_read_tokens:,} cache read "
                f"+ {self.cache_write_tokens:,} cache write + {self.completion_tokens:,} output"
            )
        else:
            breakdown = f"{self.prompt_tokens:,} prompt + {self.completion_tokens:,} completion"
        if self.unpriced_calls:
            dollars = (
                f"$ unmeasured ({self.unpriced_calls} of {self.calls} calls have no list price: "
                f"{', '.join(sorted(self.unpriced_models))})"
            )
        else:
            dollars = f"${self.usd:.4f}"
        return f"{self.calls} calls, {self.total_tokens:,} tokens ({breakdown}), {dollars}"


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
            usd: float | None = float(kwargs.get("response_cost") or 0.0) or None
            if usd is None:
                try:
                    usd = float(litellm.completion_cost(completion_response=response)) or None
                except Exception:  # noqa: BLE001
                    usd = None
            meter.record(
                prompt_tokens=int(get("prompt_tokens") or 0),
                completion_tokens=int(get("completion_tokens") or 0),
                usd=usd,
                model=getattr(response, "model", None),
            )
        except Exception:  # noqa: BLE001 - accounting must never break the run
            pass

    litellm.success_callback = [*(getattr(litellm, "success_callback", None) or []), _cb]

    def _teardown() -> None:
        with contextlib.suppress(Exception):
            litellm.success_callback = [c for c in litellm.success_callback if c is not _cb]

    return _teardown


# USD per 1M tokens: (input, output). List price, used to turn captured token
# counts into the dollar figure a run records. Matched against the model the API
# response reports: an exact id wins, then the LONGEST matching prefix, so a dated
# snapshot (claude-haiku-4-5-20251001) finds its family and claude-opus-5-5 can never
# fall through to claude-opus-5's rate. An id that matches nothing is unpriced (None),
# never $0. Extend as models are added.
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
    # The Claude 5.5 / 5.1 line the credit-funded runs use, exact ids, from the dated
    # snapshot src/agent_airlock/data/anthropic_pricing_2026_10.json (read from
    # https://platform.claude.com/docs/en/about-claude/pricing on 2026-10-10). Until
    # 0.10.25 claude-opus-5-5 prefix-matched claude-opus-5 ($5/$25; real $4/$20) and
    # claude-haiku-5-5 matched nothing and recorded $0. A Claude 5.x pass is billed from
    # the shared ledger (benchmarks._claude.pricing: cache multipliers included); this
    # table prices the meters of the other paths.
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-fable-5-1": (10.00, 50.00),
    # Read from the same page on 2026-09-12 (base input/output per million; caching, Batch
    # and data-residency multipliers are not modelled here).
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-opus-4-6": (5.00, 25.00),
    "claude-opus-4-5": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
    # Together (open models) list price — the 3rd family for the widened run. Cost is
    # captured by the OpenAI-client SDK hook (Together is OpenAI-compatible).
    "mistralai/Mixtral-8x7B-Instruct-v0.1": (0.60, 0.60),
    "meta-llama/Llama-3-70b-chat-hf": (0.88, 0.88),
    # A Together model outside the two above is unpriced: a paid run refuses it until it
    # is priced here.
}


def _model_rates(model: str | None) -> tuple[float, float] | None:
    """``(input, output)`` USD per million for ``model``, or ``None`` if unpriced."""
    if not model:
        return None
    if model in _MODEL_PRICES:
        return _MODEL_PRICES[model]
    for key in sorted(_MODEL_PRICES, key=len, reverse=True):
        if model.startswith(key):
            return _MODEL_PRICES[key]
    return None


def _price_usd(model: str | None, prompt_tokens: int, completion_tokens: int) -> float | None:
    """List-price USD for one call, or ``None`` when the model is unpriced (never ``0``)."""
    rates = _model_rates(model)
    if rates is None:
        return None
    pin, pout = rates
    return prompt_tokens / 1e6 * pin + completion_tokens / 1e6 * pout


def power_sample_size(
    p1: float,
    p2: float,
    *,
    alpha: float = 0.05,
    power: float = 0.80,
) -> int:
    """Per-arm pair count for a two-proportion z-test (two-sided), rounded up.

    This is how the widened AgentDojo sample size is chosen from a power calculation rather
    than from convenience (see RESULTS.md "Widening plan"). It returns the number of
    injection->task pairs **per arm** needed to detect a change in attack-success-rate from
    ``p1`` (undefended) to ``p2`` (airlock) at significance ``alpha`` and ``power``, using the
    standard normal approximation::

        n = ( z_{1-alpha/2}·sqrt(2·pbar·(1-pbar))
              + z_{1-beta}·sqrt(p1·(1-p1) + p2·(1-p2)) )^2 / (p1 - p2)^2 ,   pbar = (p1+p2)/2

    Args:
        p1: undefended ASR (0 < p1 < 1).
        p2: airlock ASR (0 < p2 < 1), p2 != p1.
        alpha: two-sided significance (default 0.05).
        power: desired power 1-beta (default 0.80).

    Returns:
        The per-arm pair count (``math.ceil``).

    Raises:
        ValueError: if ``p1``/``p2`` are outside (0, 1) or equal.
    """
    if not (0.0 < p1 < 1.0) or not (0.0 < p2 < 1.0) or p1 == p2:
        raise ValueError("p1 and p2 must be distinct proportions in the open interval (0, 1)")
    normal = NormalDist()
    z_alpha = normal.inv_cdf(1.0 - alpha / 2.0)
    z_beta = normal.inv_cdf(power)
    pbar = (p1 + p2) / 2.0
    pooled = z_alpha * math.sqrt(2.0 * pbar * (1.0 - pbar))
    unpooled = z_beta * math.sqrt(p1 * (1.0 - p1) + p2 * (1.0 - p2))
    return math.ceil((pooled + unpooled) ** 2 / (p1 - p2) ** 2)


def install_provider_cost_hooks(meter: CostMeter, *, anthropic: bool = True):  # type: ignore[no-untyped-def]
    """Record token/$ cost from the OpenAI and Anthropic SDK responses into ``meter``.

    agentdojo calls the provider SDKs directly (OpenAI sync ``chat.completions``,
    Anthropic async ``messages.stream``), not litellm, so the litellm callback never
    fires. This patches the two points where the raw API response — which carries
    ``.usage`` — is in hand: the OpenAI ``Completions.create`` return value, and
    agentdojo's Anthropic message converter (the async streaming client makes a
    call-level patch awkward). Pass ``anthropic=False`` when ``claude_patch`` meters the
    Anthropic calls itself, so nothing is counted twice. Returns a teardown that restores
    what it patched. Best-effort and non-fatal: a provider whose internals differ is
    simply not metered.
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
                    details = getattr(u, "prompt_tokens_details", None)
                    cached = int(getattr(details, "cached_tokens", 0) or 0)
                    meter.record(
                        prompt_tokens=pt - cached,
                        completion_tokens=ct,
                        cache_read_tokens=cached,
                        # Cached tokens priced at the full input rate: an over-estimate.
                        usd=_price_usd(getattr(resp, "model", None), pt, ct),
                        model=getattr(resp, "model", None),
                    )
            return resp

        _oai.Completions.create = _patched_create  # type: ignore[method-assign]
        restores.append(lambda: setattr(_oai.Completions, "create", _orig_create))
    except Exception:  # noqa: BLE001
        pass

    if anthropic:
        try:
            import agentdojo.agent_pipeline.llms.anthropic_llm as _am

            _orig_conv = _am._anthropic_to_assistant_message

            def _patched_conv(completion: Any, *a: Any, **k: Any) -> Any:
                with contextlib.suppress(Exception):
                    u = getattr(completion, "usage", None)
                    if u is not None:
                        pt = int(getattr(u, "input_tokens", 0) or 0)
                        ct = int(getattr(u, "output_tokens", 0) or 0)
                        cr = int(getattr(u, "cache_read_input_tokens", 0) or 0)
                        cw = int(getattr(u, "cache_creation_input_tokens", 0) or 0)
                        model = getattr(completion, "model", None)
                        # Cache reads at 0.1x and writes at 1.25x of base input, the
                        # default multipliers for the pre-5.5 models this path serves.
                        base = _price_usd(model, pt, ct)
                        rates = _model_rates(model)
                        usd = (
                            None
                            if base is None or rates is None
                            else base + (cr * 0.1 + cw * 1.25) * rates[0] / 1e6
                        )
                        meter.record(
                            prompt_tokens=pt,
                            completion_tokens=ct,
                            cache_read_tokens=cr,
                            cache_write_tokens=cw,
                            usd=usd,
                            model=model,
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
    settings: dict[str, Any] = field(default_factory=dict)
    """Request settings the pass pinned (effort, thinking, max_tokens, ...)."""
    call_outcomes: dict[str, int] = field(default_factory=dict)
    """Per-call outcome counts from ``claude_patch`` (``ok``, ``refusal``, ``max_tokens``)."""
    selection: list[TaskSelection] = field(default_factory=list)


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


def _render_selection(selection: list[TaskSelection]) -> str:
    """``workspace `0, 1, 2`; travel `6*, 0, 1` ...`` with ``*`` marking no-target injections."""
    parts = []
    for sel in selection:
        ids = ", ".join(
            iid.removeprefix("injection_task_") + ("*" if iid in sel.untargeted else "")
            for iid in sel.injection_ids
        )
        parts.append(f"{sel.suite} `{ids}` ({len(sel.user_ids)} user tasks)")
    return "; ".join(parts)


def _render_call_table(runs: list[ModelRun]) -> str:
    """Request settings and per-call outcomes, for the runs that recorded them."""
    rows = []
    for r in runs:
        if not r.settings and not r.call_outcomes:
            continue
        outcomes = r.call_outcomes
        calls = sum(outcomes.values())
        failed = ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items()) if k not in {"ok"} and v)
        rows.append(
            f"| `{r.model_id}` | {r.settings.get('effort', '—')} | "
            f"{r.settings.get('thinking', '—')} | {r.settings.get('max_tokens', '—')} | "
            f"{calls} | {failed or 'none'} | {r.cost.cache_read_tokens:,} |"
        )
    if not rows:
        return ""
    return (
        "\n\nRequest settings and per-call outcomes (no temperature, no fallbacks; a "
        "refusal or `max_tokens` stop ends its episode as a failed step):\n\n"
        "| model | effort | thinking | max_tokens | API calls | non-ok calls | "
        "cache-read tokens |\n| --- | --- | --- | --- | --- | --- | --- |\n" + "\n".join(rows)
    )


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
    selection = (
        f"\nInjection tasks per suite: {_render_selection(runs[0].selection)}; `*` marks an "
        "injection whose ground truth names no tool call (one that asks only for text is out "
        "of any tool-call policy's reach)."
        if runs[0].selection
        else ""
    )

    return f"""### {date} · cross-model ({model_list})

`agentdojo {ad_ver}`, attack `{ATTACK}` (AgentDojo's fixed template, not an adaptive
attacker), benchmark `{BENCHMARK_VERSION}`, caps {caps}.{selection}
Each row is one model with its **own** Wilson 95% CI and its **own** benign-FPR control.
`cost` is that model's measured token/$ spend for this run.

| model | ASR (undef → airlock) | airlock ASR 95% CI | benign FP cost | n/arm | cost |
| --- | --- | --- | --- | --- | --- |
{chr(10).join(per_model_rows)}{_render_call_table(runs)}

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
        raise ValueError(
            f"a run block for {heading!r} already exists; pass force=True to append another "
            "block under the same heading (dated blocks are never edited)"
        )
    head, _, tail = text.partition(_RUNS_MARKER)
    new = f"{head}{_RUNS_MARKER}\n\n{dated_block.strip()}\n{tail}"
    results_path.write_text(new, encoding="utf-8")
    return new


# --------------------------------------------------------------------------- #
# Paid-pass planning, gating and execution
# --------------------------------------------------------------------------- #


def _is_claude5(model_id: str) -> bool:
    from benchmarks.agentdojo.claude_patch import is_claude5_model

    return is_claude5_model(model_id)


@dataclass
class PassPlan:
    """What a ``--model`` pass would run and roughly cost, before anything is sent."""

    model_id: str
    selections: list[TaskSelection]
    max_user_tasks: int
    max_injection_tasks: int
    effort: str | None = None
    max_tokens: int | None = None

    @property
    def claude5(self) -> bool:
        return _is_claude5(self.model_id)

    @property
    def suites(self) -> tuple[str, ...]:
        return tuple(s.suite for s in self.selections)

    @property
    def benign_per_arm(self) -> int:
        return sum(len(s.user_ids) for s in self.selections)

    @property
    def pairs_per_arm(self) -> int:
        return sum(s.pairs for s in self.selections)

    @property
    def targeted_pairs_per_arm(self) -> int:
        return sum(s.targeted_pairs for s in self.selections)

    @property
    def episodes(self) -> int:
        return 2 * (self.benign_per_arm + self.pairs_per_arm)

    @property
    def calls(self) -> tuple[float, float]:
        return self.episodes * CALLS_PER_EPISODE[0], self.episodes * CALLS_PER_EPISODE[1]

    @property
    def input_tokens_per_call(self) -> float:
        factor = CLAUDE_TOKENIZER_FACTOR if self.model_id.startswith("claude-") else 1.0
        return INPUT_TOKENS_PER_CALL * factor

    def cost_usd(self) -> tuple[float, float] | None:
        """``(low, high)`` USD estimate, or ``None`` when the model has no list price.

        The high end prices every input token as a 5-minute cache write (1.25x) for a
        Claude 5.x model, the most top-level caching can add; caching usually cuts input.
        """
        tokens_in = self.input_tokens_per_call
        lo_out, hi_out = OUTPUT_TOKENS_PER_CALL
        if self.claude5:
            from benchmarks._claude.pricing import UnpricedModelError, rates_for

            try:
                rates = rates_for(self.model_id)
            except UnpricedModelError:
                return None
            per_lo = (tokens_in * rates.input + lo_out * rates.output) / 1e6
            per_hi = (tokens_in * rates.cache_write_5m + hi_out * rates.output) / 1e6
        else:
            legacy = _model_rates(self.model_id)
            if legacy is None:
                return None
            per_lo = (tokens_in * legacy[0] + lo_out * legacy[1]) / 1e6
            per_hi = (tokens_in * legacy[0] + hi_out * legacy[1]) / 1e6
        calls_lo, calls_hi = self.calls
        return calls_lo * per_lo, calls_hi * per_hi

    def logdir_name(self) -> str:
        return f"{self.model_id.replace('/', '_')}__{self.effort or 'default'}"


def plan_model_pass(
    model_id: str,
    suites: tuple[str, ...],
    max_user_tasks: int,
    max_injection_tasks: int,
    *,
    effort: str | None = None,
    max_tokens: int | None = None,
) -> PassPlan:
    """Enumerate the episodes a pass would run (needs ``agentdojo``; sends nothing)."""
    return PassPlan(
        model_id=model_id,
        selections=select_tasks(suites, max_user_tasks, max_injection_tasks),
        max_user_tasks=max_user_tasks,
        max_injection_tasks=max_injection_tasks,
        effort=effort,
        max_tokens=max_tokens,
    )


def render_pass_plan(plan: PassPlan, *, logdir: Path | None = None) -> str:
    """The dry-run printout for one model."""
    calls_lo, calls_hi = plan.calls
    lines = [f"model-in-the-loop plan: {plan.model_id}"]
    if plan.claude5:
        effort = plan.effort or "NOT PINNED (pass --effort)"
        lines.append(
            f"  request: via claude_patch; effort {effort}, thinking adaptive (display "
            f"omitted), max_tokens {plan.max_tokens}, top-level cache_control ephemeral, no "
            "temperature, no fallbacks"
        )
    lines += [
        f"  suites: {', '.join(plan.suites)}; caps <= {plan.max_user_tasks} user / "
        f"<= {plan.max_injection_tasks} injection tasks per suite; attack {ATTACK} "
        f"(fixed template), benchmark {BENCHMARK_VERSION}",
        f"  per arm: {plan.pairs_per_arm} attacked pairs ({plan.targeted_pairs_per_arm} with "
        f"a tool-call target) + {plan.benign_per_arm} benign runs; "
        f"{plan.episodes} episodes over both arms",
        f"  injection tasks: {_render_selection(plan.selections)} (* ground truth names no "
        "tool call)",
        f"  estimated LLM calls: {calls_lo:,.0f}-{calls_hi:,.0f} "
        f"({CALLS_PER_EPISODE[0]}-{CALLS_PER_EPISODE[1]} per episode)",
    ]
    skipped = [
        f"{s.suite}: {', '.join(s.skipped_user_ids)}" for s in plan.selections if s.skipped_user_ids
    ]
    if skipped:
        lines.append(f"  user tasks skipped (ground truth names no tool): {'; '.join(skipped)}")
    cost = plan.cost_usd()
    if cost is None:
        lines.append(
            f"  estimated cost: unmeasured — {plan.model_id} has no list price; a paid run "
            "refuses it until it is priced"
        )
    else:
        lo, hi = cost
        lines.append(
            f"  estimated cost: ${lo:,.2f}-${hi:,.2f} ({plan.input_tokens_per_call:,.0f} input "
            f"tokens/call, {OUTPUT_TOKENS_PER_CALL[0]}-{OUTPUT_TOKENS_PER_CALL[1]} output "
            "tokens/call incl. thinking; an estimate until a pilot measures usage)"
        )
        if plan.claude5:
            lines.append(
                f"  --run reserves up to ${hi * RESERVE_MARGIN:,.2f} in the shared ledger and "
                "stops the pass if spend reaches the reservation"
            )
    if logdir is not None:
        lines.append(f"  logdir: {logdir / plan.logdir_name()}")
    return "\n".join(lines)


def _git_state() -> tuple[str, bool]:
    try:
        sha = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "status", "--porcelain", "--untracked-files=no"],  # noqa: S607
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown", True
    return sha, bool(dirty)


def _pass_settings(plan: PassPlan, agentdojo_version: str) -> dict[str, Any]:
    """The measurement-defining settings of one pass (``_MANIFEST_KEYS``)."""
    return {
        "model": plan.model_id,
        "effort": plan.effort,
        "max_tokens": plan.max_tokens,
        "thinking": "adaptive" if plan.claude5 else None,
        "attack": ATTACK,
        "benchmark_version": BENCHMARK_VERSION,
        "suites": list(plan.suites),
        "max_user_tasks": plan.max_user_tasks,
        "max_injection_tasks": plan.max_injection_tasks,
        "defense": _DEFENSE,
        "agentdojo_version": agentdojo_version,
    }


def _agentdojo_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("agentdojo")
    except PackageNotFoundError:  # pragma: no cover
        return "?"


def _within_repo(path: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(REPO_ROOT)
    except ValueError:
        return False
    return True


def paid_run_problems(
    plans: list[PassPlan],
    *,
    budget_usd: float | None,
    logdir: Path | None,
    resume: bool,
) -> list[str]:
    """Every reason a ``--run`` must not start; an empty list means it may."""
    problems: list[str] = []
    if budget_usd is None:
        problems.append("--run needs --budget-usd (the most this command may spend)")
    elif budget_usd <= 0:
        problems.append(f"--budget-usd must be positive, got {budget_usd}")
    if logdir is None:
        problems.append(
            "--run needs --logdir: a new or empty directory outside the repository "
            "(agentdojo's trace cache ignores policy and LLM settings, so a reused directory "
            "would silently replay stale trajectories)"
        )
    else:
        target = logdir.expanduser()
        if _within_repo(target):
            problems.append(
                f"--logdir {target} is inside the repository; raw trajectories never enter it "
                "(use e.g. ~/.cache/agent-airlock-bench/runs/agentdojo/<name>)"
            )
        if resume:
            if not target.is_dir():
                problems.append(f"--resume: {target} does not exist")
        elif target.exists() and (not target.is_dir() or any(target.iterdir())):
            problems.append(
                f"--logdir {target} is not empty; use a new directory per pass, or --resume "
                "a pass whose recorded settings match"
            )
    try:
        from benchmarks._claude.client import sdk_version

        sdk = sdk_version()
    except Exception:  # noqa: BLE001
        sdk = "not installed"
    sdk_major = int(sdk.split(".", 1)[0]) if sdk[:1].isdigit() else None
    for plan in plans:
        if plan.model_id.startswith("claude") and not plan.claude5:
            if sdk_major is None or sdk_major >= 1:
                problems.append(
                    f"{plan.model_id}: agentdojo 0.1.35 cannot call it with anthropic {sdk} (it "
                    "passes temperature, which the 1.x SDK removed); only Claude 5.x ids run, "
                    "through claude_patch"
                )
        if plan.claude5 and plan.effort is None:
            problems.append(f"{plan.model_id}: no pinned effort; pass --effort")
        if plan.cost_usd() is None:
            problems.append(
                f"{plan.model_id}: no list price (_MODEL_PRICES / the pricing snapshot); price it "
                "before spending, not after"
            )
    if budget_usd is not None and budget_usd > 0:
        floors = [c[0] for c in (p.cost_usd() for p in plans) if c is not None]
        if sum(floors) > budget_usd:
            problems.append(
                f"--budget-usd ${budget_usd:.2f} is below the low estimate ${sum(floors):.2f} "
                "for these passes; raise it or lower --max-user-tasks"
            )
    return problems


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True, default=str), encoding="utf-8")
    tmp.replace(path)


def prepare_pass_dir(pass_dir: Path, settings: dict[str, Any], *, resume: bool) -> dict[str, Any]:
    """Create one pass's directory and manifest, or re-open it for ``--resume``.

    A missing or empty directory always starts fresh. A non-empty one is reused only
    with ``resume`` and only when its recorded settings match ``settings`` exactly, because
    agentdojo would replay whatever trajectories it holds.

    Raises:
        ValueError: The directory holds something and ``resume`` is off, it holds no
            manifest, or its recorded settings differ.
    """
    manifest_path = pass_dir / MANIFEST_NAME
    sha, dirty = _git_state()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    occupied = pass_dir.is_dir() and any(pass_dir.iterdir())
    if occupied and not resume:
        raise ValueError(
            f"{pass_dir} is not empty; use a new --logdir, or --resume a matching pass"
        )
    if occupied:
        if not manifest_path.exists():
            raise ValueError(f"--resume: {pass_dir} has no {MANIFEST_NAME}; it was not a pass dir")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        recorded = manifest.get("settings", {})
        diff = {
            k: (recorded.get(k), settings.get(k))
            for k in _MANIFEST_KEYS
            if recorded.get(k) != settings.get(k)
        }
        if diff:
            raise ValueError(
                f"--resume: {pass_dir} was recorded with different settings {diff} "
                "(recorded, now); its cached trajectories would not measure this pass"
            )
        manifest.setdefault("resumes", []).append({"at": now, "git_sha": sha, "git_dirty": dirty})
    else:
        manifest = {
            "settings": settings,
            "created": now,
            "git_sha": sha,
            "git_dirty": dirty,
            "status": "planned",
        }
    _write_manifest(manifest_path, manifest)
    return manifest


def _effort_for(model_id: str, override: str | None) -> str | None:
    if not _is_claude5(model_id):
        return None
    if override:
        return override
    from benchmarks._claude.models import DEFAULT_EFFORT

    return DEFAULT_EFFORT.get(model_id)


def run_claude_pass(
    plan: PassPlan,
    pass_dir: Path,
    *,
    guard: Any,
    ledger: Any,
    reservation_usd: float,
) -> ModelRun:
    """Run one Claude 5.x pass through ``claude_patch``, inside a ledger reservation.

    The reservation is the pass's worst case: ``claude_patch`` refuses any call that would
    take the job's spend past it. Settled on success, released (with the reason) on any
    failure; the manifest records the outcome either way.
    """
    from benchmarks.agentdojo.claude_patch import CallRecorder, install_claude_patch

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    job = f"agentdojo-{plan.model_id}-{plan.effort}-{stamp}"
    meter = CostMeter()

    def _on_usage(u: dict[str, Any]) -> None:
        meter.record(
            prompt_tokens=u["prompt_tokens"],
            completion_tokens=u["completion_tokens"],
            cache_read_tokens=u["cache_read_tokens"],
            cache_write_tokens=u["cache_write_tokens"],
            usd=u["usd"],
            model=u["model"],
        )

    recorder = CallRecorder(
        pass_dir / CALLS_LOG_NAME,
        job=job,
        ledger=ledger,
        cap_usd=reservation_usd,
        on_usage=_on_usage,
    )
    manifest_path = pass_dir / MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update({"job": job, "reservation_usd": round(reservation_usd, 4), "status": "running"})
    _write_manifest(manifest_path, manifest)

    if plan.effort is None or plan.max_tokens is None:
        raise ValueError(f"{plan.model_id}: a Claude 5.x pass needs a pinned effort and max_tokens")
    guard.admit(job, reservation_usd)
    try:
        with install_claude_patch(
            {plan.model_id: plan.effort}, recorder=recorder, max_tokens=plan.max_tokens
        ):
            results, ad_ver, stamp_date = execute_model(
                plan.model_id,
                plan.suites,
                plan.max_user_tasks,
                plan.max_injection_tasks,
                logdir_arg=str(pass_dir),
            )
    except BaseException as exc:
        ledger.release(job, reason=f"aborted: {type(exc).__name__}")
        manifest.update(
            {"status": "aborted", "abort_reason": type(exc).__name__, "calls": recorder.summary()}
        )
        _write_manifest(manifest_path, manifest)
        raise
    guard.settle(job)
    manifest.update({"status": "complete", "calls": recorder.summary(), "cost": meter.summary()})
    _write_manifest(manifest_path, manifest)
    return ModelRun(
        plan.model_id,
        results,
        meter,
        ad_ver,
        stamp_date,
        plan.max_user_tasks,
        plan.max_injection_tasks,
        settings={
            "effort": plan.effort,
            "thinking": "adaptive",
            "max_tokens": plan.max_tokens,
        },
        call_outcomes=dict(recorder.outcomes),
        selection=plan.selections,
    )


def run_legacy_pass(plan: PassPlan, pass_dir: Path) -> ModelRun:
    """Run one non-Claude-5 pass (OpenAI, Together, ...) with the SDK cost hooks."""
    meter = CostMeter()
    teardown_litellm = install_litellm_cost_hook(meter)
    teardown_sdk = install_provider_cost_hooks(meter)
    try:
        results, ad_ver, stamp = execute_model(
            plan.model_id,
            plan.suites,
            plan.max_user_tasks,
            plan.max_injection_tasks,
            logdir_arg=str(pass_dir),
        )
    finally:
        teardown_sdk()
        teardown_litellm()
    return ModelRun(
        plan.model_id,
        results,
        meter,
        ad_ver,
        stamp,
        plan.max_user_tasks,
        plan.max_injection_tasks,
        selection=plan.selections,
    )


# --------------------------------------------------------------------------- #
# RESULTS.md rendering + CLI
# --------------------------------------------------------------------------- #


_PENDING_NOTE = """_No model run recorded yet._ The two leaderboard metrics — **utility under attack** and
**ASR** — need a real model-in-the-loop pass (an LLM API key + real API spend). Each run
appends a dated block above; none is claimed until a run produces it."""

_PAID_REPRODUCE = """python -m benchmarks.agentdojo.run \\
  --model claude-haiku-5-5 --model claude-sonnet-5-5 \\
  --run --budget-usd 40 --logdir ~/.cache/agent-airlock-bench/runs/agentdojo/<new-dir> \\
  --out benchmarks/agentdojo/RESULTS.md"""


def _model_log_region(dated_block: str | None) -> str:
    """The append-only Result 2 region: H2 + reproduce command + marker + block."""
    return f"""## Result 2 — model-in-the-loop utility-under-attack + ASR (append-only log)

Each dated block below is one run and is never edited after the fact; newer runs are
prepended under the marker. Reproduce / add a run (without `--run` it prints the plan and
its estimated cost, and sends nothing):

```bash
{_PAID_REPRODUCE}
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
        f"| {s.suite} | {s.all_pairs} | {s.pairs} | {s.blocked_pairs} | **{s.per_task_rate:.1%}** | "
        f"{s.blocked_union}/{s.injections} ({s.union_rate:.0%}) |"
        for s in report.suites
    )
    model_block = _model_log_region(model_section)
    ghost_note = (
        "Every block in this table is an allow-list refusal: the ground-truth calls always "
        "match their tool's schema, so ghost-argument BLOCK never fires here."
        if report.total_ghost_arg_blocks == 0
        else f"{report.total_ghost_arg_blocks} of the blocks are ghost-argument refusals."
    )
    return f"""# AgentDojo — indirect prompt injection, all 4 suites (agent-airlock as a defense)

Reproduce (deterministic block-coverage, no model, no API key):

```bash
pip install "agent-airlock[bench]"
python -m benchmarks.agentdojo.run
```

Reproduce (model-in-the-loop utility-under-attack + ASR, needs a key + API spend):

```bash
{_PAID_REPRODUCE}
```

## What this measures

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024) is a
**model-in-the-loop** indirect prompt-injection benchmark. The attack here is AgentDojo's
fixed-template `{ATTACK}` attack (a `FixedJailbreakAttack`: one template filled with the
injection goal and its target tool sequence), not an adaptive attacker. agent-airlock is
registered as an AgentDojo **defense** — the same `validate -> policy -> execute -> sanitize`
seam `@Airlock` applies, installed at AgentDojo's tool-execution pipeline element
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

| Suite | all pairs | pairs with a tool-call target | blocked | block rate | per-suite-union |
| --- | --- | --- | --- | --- | --- |
{rows}

**Combined: {render_coverage_census(report)}.** Over the pairs it can check, {combined:.1%}
of `{ATTACK}` injection->task pairs have their target tool-call blocked by airlock's
deny-by-default least-privilege policy. {ghost_note}

> This is a deterministic **upper bound on airlock's ASR reduction** over the pairs whose
> injection's ground truth names a tool call — the fraction of those attacks whose target
> action airlock forces to fail *regardless of model*. It is **NOT** AgentDojo's
> model-in-the-loop ASR (that is Result 2), and it says nothing about the pairs whose
> injection's ground truth names no tool call.

{model_block}

## What airlock does NOT neutralize (the honest misses)

The **per-suite-union** column allow-lists *every* tool any benign task in the suite
uses, then asks how many injections are still blocked. {_union_caveat(report)}. The gap
between the per-task and per-suite-union columns is the whole point: **least-privilege
scoping** — authorizing only the tools the *current* task needs — is what blocks these
attacks at the tool seam. A coarse, suite-wide allow-list does not. Injections that
abuse a **legitimately-allowed tool with malicious arguments** are **not** caught by the
tool-level policy alone; catching those needs argument-level policy (airlock's strict
Pydantic validation on the specific arg) or the model-in-the-loop run. An injection whose
goal is text alone (travel `injection_task_6` asks the agent to praise a hotel) is out of
a tool-call policy's reach by construction; workspace `injection_task_6`-`13` do ask for
actions, but their ground truth lists no call, so Result 1 cannot score them. We report
the misses; we do not claim airlock "blocks everything".

## Where this sits vs a native MCP gateway (the wedge)

A gateway / OAuth resource server authenticates *who* connects and routes the call; it
does not open the tool-call payload and check it against the current task's contract. So
the exact injection class airlock's contract layer blocks here — **a call to a tool outside
the task's least-privilege scope** — is precisely the class a gateway forwards, because it
is well-formed transport-wise and carries a valid token. Ghost-argument BLOCK (an argument
key the tool never declared) is wired into the same defense but never fires in Result 1,
where every ground-truth call matches its schema. That is the "contract layer beneath your
gateway" wedge, measured on a third-party prompt-injection benchmark (AgentDojo's
fixed-template attack, not an adaptive attacker) rather than asserted. What a gateway
*does* catch that airlock does not (unauthenticated callers, bad tokens, transport
tampering) is complementary — use both.

## Scope, stated plainly

- Suites: **{", ".join(PINNED_SUITES)}** (all 4 of AgentDojo's suites), attack:
  **{ATTACK}** (fixed template), benchmark version **{BENCHMARK_VERSION}**.
- Result 1 is deterministic, offline, reproducible in CI — no model, no API key, no
  network. Result 2 is the real model-in-the-loop pass and is only shown when run.
- **Not** a re-run of model-in-the-loop incumbents and **no fabricated competitor
  number.**
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmarks.agentdojo.run",
        description="Register agent-airlock as an AgentDojo defense and measure robustness.",
    )
    parser.add_argument(
        "--model",
        action="append",
        default=None,
        help="Model id for the model-in-the-loop pass. Without --run this prints the plan "
        "and its estimated cost and sends nothing. Repeat to run several models "
        "(e.g. --model claude-haiku-5-5 --model claude-sonnet-5-5); each is reported with "
        "its own Wilson CI.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Actually run the paid model pass (needs the provider's API key, --budget-usd "
        "and a new, empty --logdir). Without it nothing is sent and nothing is spent.",
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help="Required with --run: the most this command may spend, in USD. A Claude 5.x "
        "pass reserves its worst case in the shared ledger (benchmarks._claude) before it "
        "starts, refuses any call that would exceed the reservation, and settles after; "
        "other providers are checked against the estimate only.",
    )
    parser.add_argument(
        "--effort",
        choices=("low", "medium", "high", "xhigh", "max"),
        default=None,
        help="Effort pinned for Claude 5.x models (default: each model's API default, "
        "benchmarks._claude.models.DEFAULT_EFFORT); recorded with the run.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="max_tokens per Claude 5.x call (default 16000; agentdojo's own 1024 truncates "
        "thinking turns).",
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
        help="Append another dated run block even when one with the same heading exists; "
        "the existing block is kept, never edited (default: refuse).",
    )
    parser.add_argument(
        "--max-user-tasks",
        type=int,
        default=DEFAULT_MAX_USER_TASKS,
        help="Model path: cap user tasks per suite (default 14: 14 x 3 x 4 = 168 pairs per "
        "arm, over the power calculation's 163; the 2026-07-31 and 2026-08-08 passes used 5).",
    )
    parser.add_argument(
        "--max-injection-tasks",
        type=int,
        default=DEFAULT_MAX_INJECTION_TASKS,
        help="Model path: cap injection tasks per suite.",
    )
    parser.add_argument("--out", type=Path, default=None, help="Write RESULTS.md to this path.")
    parser.add_argument(
        "--logdir",
        type=Path,
        default=None,
        help="Trace/cache dir for the model path, outside the repository. Required with "
        "--run and must be new or empty: agentdojo's cache key ignores the policy and the LLM "
        "settings, so a reused dir would silently replay stale trajectories. One "
        "subdirectory per model and effort is created inside it.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Continue a --run pass in an existing --logdir whose recorded settings match "
        "exactly; agentdojo reuses the trajectories that finished.",
    )
    parser.add_argument(
        "--suites",
        default=None,
        help="Comma-separated subset of suites for the model path (default: all four). "
        "Result 1 (deterministic) always covers all four.",
    )
    return parser


def _execute_paid_passes(
    args: argparse.Namespace, plans: list[PassPlan]
) -> tuple[list[ModelRun], int]:
    """Run every planned pass in order; stop at the first that fails. Returns runs + code."""
    from benchmarks._claude.budget import BudgetExceededError, BudgetGuard
    from benchmarks._claude.ledger import Ledger

    ledger = Ledger()
    guard = BudgetGuard(float(args.budget_usd), ledger)
    logdir: Path = args.logdir.expanduser()
    ad_ver = _agentdojo_version()
    runs: list[ModelRun] = []
    for plan in plans:
        pass_dir = logdir / plan.logdir_name()
        try:
            prepare_pass_dir(pass_dir, _pass_settings(plan, ad_ver), resume=args.resume)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return runs, 2
        print(
            f"running {plan.model_id}: {plan.episodes} episodes, logdir {pass_dir}",
            file=sys.stderr,
        )
        try:
            if plan.claude5:
                cost = plan.cost_usd()
                if cost is None:
                    raise ValueError(f"{plan.model_id} has no exact-id price")
                low, high = cost
                room = guard.headroom()
                if room < low:
                    raise BudgetExceededError(
                        f"{plan.model_id}: ${room:.2f} left under the caps is below this "
                        f"pass's low estimate ${low:.2f}"
                    )
                reservation = min(high * RESERVE_MARGIN, room)
                if reservation < high:
                    print(
                        f"  note: reserving ${reservation:.2f}, below the high estimate "
                        f"${high:.2f}; the pass stops if spend reaches it (resumable)",
                        file=sys.stderr,
                    )
                run = run_claude_pass(
                    plan, pass_dir, guard=guard, ledger=ledger, reservation_usd=reservation
                )
            else:
                run = run_legacy_pass(plan, pass_dir)
        except BudgetExceededError as exc:
            print(f"budget: {exc}", file=sys.stderr)
            return runs, BudgetExceededError.exit_code
        except Exception as exc:  # noqa: BLE001 - reported, then the CLI exits non-zero
            print(
                f"error: the {plan.model_id} pass stopped ({type(exc).__name__}: {exc}). "
                f"Finished trajectories stay in {pass_dir}; rerun with --resume to continue.",
                file=sys.stderr,
            )
            return runs, 1
        print(f"  {plan.model_id} cost: {run.cost.summary()}", file=sys.stderr)
        runs.append(run)
    return runs, 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.run and not args.model:
        parser.error("--run needs at least one --model")
    if args.resume and not args.run:
        parser.error("--resume continues a paid pass; pass --run too")
    if args.max_tokens is not None and args.max_tokens <= 0:
        parser.error(f"--max-tokens must be positive, got {args.max_tokens}")

    if not _HAVE_AGENTDOJO:
        print(
            "agentdojo is not installed. This is a bench-only extra; the airlock core "
            "stays zero-dep.\n  pip install 'agent-airlock[bench]'",
            file=sys.stderr,
        )
        return 0

    report = run_deterministic()
    print(f"Result 1 (deterministic, no model): {render_coverage_census(report)}")

    models: list[str] = args.model or []
    dated_block: str | None = None
    exit_code = 0
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
        from benchmarks.agentdojo.claude_patch import DEFAULT_MAX_TOKENS

        plans = [
            plan_model_pass(
                model_id,
                model_suites,
                args.max_user_tasks,
                args.max_injection_tasks,
                effort=_effort_for(model_id, args.effort),
                max_tokens=(args.max_tokens or DEFAULT_MAX_TOKENS)
                if _is_claude5(model_id)
                else None,
            )
            for model_id in models
        ]
        for plan in plans:
            print(render_pass_plan(plan, logdir=args.logdir), file=sys.stderr)

        if not args.run:
            print(
                "dry run: nothing was sent and nothing was spent. To run it, add --run "
                "--budget-usd N --logdir <new dir outside the repo> (and the provider's key).",
                file=sys.stderr,
            )
            return 0

        problems = paid_run_problems(
            plans, budget_usd=args.budget_usd, logdir=args.logdir, resume=args.resume
        )
        if problems:
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            return 2

        runs, exit_code = _execute_paid_passes(args, plans)
        if runs:
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
                print(f"{out} left unchanged (no completed model pass; nothing to append)")
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
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
