"""Cross-tool block-rate comparison runner.

Runs agent-airlock's deny-by-default defense over the comparison corpus and
records, per item, BLOCK vs ALLOW + a per-decision latency sample. The two
incumbents (Meta LlamaFirewall, Invariant Guardrails) are **not re-run** here —
they are model-in-the-loop systems requiring model weights / a hosted API that
this deterministic harness deliberately avoids — so their coverage is reported
as a **scope claim, cited, not a re-run number**. This is the honest contrast
the benchmark exists to draw: a deterministic in-process block-rate vs.
model-in-the-loop detection.

agent-airlock's decision per corpus category:

- ``over_privileged_selection`` / benign low-priv calls → a least-privilege
  ``SecurityPolicy(default_deny=True, allowed_tools=[<the sufficient tool>])``;
  the call is BLOCKED iff ``check_tool_allowed`` raises ``PolicyViolation``.
- ``argument_injection`` / benign data args → the comprehensive in-process
  guard chain (eval-RCE, subprocess-arg, env-interpolation, codegen); BLOCKED
  iff any guard refuses the args.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from agent_airlock import (
    CodegenDelimiterInjectionGuard,
    EvalRCEGuard,
    MCPServerEnvInterpolationGuard,
    McpSubprocessArgInjectionGuard,
)
from agent_airlock.policy import PolicyViolation, SecurityPolicy

from .corpus import ToolCall, load_corpus

# A realistic in-process argument-guard chain. The subprocess guard is
# deny-by-default; it gets the common static launchers allow-listed.
_ALLOWED_LAUNCHERS = ("uvx", "npx", "node", "python", "python3", "deno")


def _arg_guard_blocks(call: ToolCall) -> bool:
    """True iff any in-process argument guard refuses the call's args.

    Each guard takes the full args mapping. A guard that raises on a shape it
    does not handle is treated as "did not block" (the next guard still runs) —
    never as a crash, never as a silent global skip.
    """
    args = call.args
    guards = (
        EvalRCEGuard(),
        McpSubprocessArgInjectionGuard(allowed_commands=set(_ALLOWED_LAUNCHERS)),
        MCPServerEnvInterpolationGuard(),
        CodegenDelimiterInjectionGuard(),
    )
    for guard in guards:
        try:
            if not guard.evaluate(args).allowed:
                return True
        except Exception:
            continue
    return False


def _policy_blocks(call: ToolCall) -> bool:
    """True iff the least-privilege deny-by-default policy refuses the tool."""
    allow = [call.allowed_tool] if call.allowed_tool else []
    policy = SecurityPolicy(allowed_tools=allow, default_deny=True)
    try:
        policy.check_tool_allowed(call.tool_name)
        return False
    except PolicyViolation:
        return True


def _airlock_blocks(call: ToolCall) -> bool:
    if call.category == "over_privileged_selection":
        return _policy_blocks(call)
    if call.category == "argument_injection":
        return _arg_guard_blocks(call)
    # benign: could be a low-priv selection (policy) or a data arg (guard chain)
    if call.allowed_tool is not None and not call.args:
        return _policy_blocks(call)
    return _arg_guard_blocks(call)


@dataclass
class ToolResult:
    """Counts for one tool / one corpus category."""

    malicious_total: int = 0
    malicious_blocked: int = 0
    benign_total: int = 0
    benign_blocked: int = 0  # false positives

    @property
    def block_rate(self) -> float:
        return self.malicious_blocked / self.malicious_total if self.malicious_total else 0.0

    @property
    def fp_rate(self) -> float:
        return self.benign_blocked / self.benign_total if self.benign_total else 0.0


@dataclass(frozen=True)
class CompetitorScope:
    """A scope-claimed (not re-run) incumbent row.

    ``re_run=False`` always — these are model-in-the-loop systems we do not
    execute in this deterministic harness. ``coverage_note`` cites their
    published detection scope; it is NOT a measured block-rate on this corpus.
    """

    name: str
    approach: str
    coverage_note: str
    source: str
    re_run: bool = False


# Published detection scope of the incumbents (cited, not re-run). Kept terse
# and sourced; the report renders the "scope-claimed, not re-run" caveat.
COMPETITORS: tuple[CompetitorScope, ...] = (
    CompetitorScope(
        name="Meta LlamaFirewall",
        approach="model-in-the-loop (PromptGuard 2 + AlignmentCheck + regex/CodeShield)",
        coverage_note=(
            "Targets prompt-injection / jailbreak inputs, agent-misalignment via "
            "chain-of-thought auditing, and insecure-code outputs (CodeShield). "
            "Tool-argument exploit shapes (subprocess/env/codegen) and least-"
            "privilege tool *selection* are not its stated detection targets; "
            "PromptGuard/AlignmentCheck are LLM scanners requiring model weights."
        ),
        source="https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall",
    ),
    CompetitorScope(
        name="Invariant Guardrails",
        approach="model-in-the-loop + policy DSL over agent traces (Guardrails/Gateway)",
        coverage_note=(
            "Rule/DSL + classifier checks over MCP/agent traces — PII, secrets, "
            "prompt-injection, tool-flow policies. Detection depends on the "
            "operator-authored ruleset and (for some checks) a model classifier; "
            "no single fixed in-process block-rate to re-run on this corpus."
        ),
        source="https://github.com/invariantlabs-ai/invariant",
    ),
)


@dataclass
class BlockRateReport:
    results: list[tuple[ToolCall, bool]]
    by_category: dict[str, ToolResult] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)
    competitors: tuple[CompetitorScope, ...] = COMPETITORS

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def overall_block_rate(self) -> float:
        mal = [(c, b) for c, b in self.results if c.expected_block]
        return sum(1 for _c, b in mal if b) / len(mal) if mal else 0.0

    @property
    def overall_fp_rate(self) -> float:
        ben = [(c, b) for c, b in self.results if not c.expected_block]
        return sum(1 for _c, b in ben if b) / len(ben) if ben else 0.0

    def latency_pct(self, pct: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        idx = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
        return ordered[idx]


def run_blockrate(measure_latency: bool = True) -> BlockRateReport:
    """Run agent-airlock over the corpus and aggregate block-rate (+ latency)."""
    corpus = load_corpus()
    results: list[tuple[ToolCall, bool]] = []
    by_category: dict[str, ToolResult] = defaultdict(ToolResult)
    latencies: list[float] = []

    for call in corpus:
        if measure_latency:
            t0 = time.perf_counter()
            blocked = _airlock_blocks(call)
            latencies.append((time.perf_counter() - t0) * 1000.0)
        else:
            blocked = _airlock_blocks(call)
        results.append((call, blocked))

        stats = by_category[call.category]
        if call.expected_block:
            stats.malicious_total += 1
            stats.malicious_blocked += int(blocked)
        else:
            stats.benign_total += 1
            stats.benign_blocked += int(blocked)

    ordered = {
        k: by_category[k]
        for k in ("over_privileged_selection", "argument_injection", "benign")
        if k in by_category
    }
    return BlockRateReport(results=results, by_category=ordered, latencies_ms=latencies)
