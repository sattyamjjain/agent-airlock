"""``airlock negotiation-bench`` CLI (v0.8.17+).

Runs the adversarial buyer-seller negotiation regression harness
(:mod:`agent_airlock.negotiation_bench`) and emits a report. The
``--report markdown`` mode prints a small comparison table suitable for
pasting into a blog post — the agent-airlock rows next to the labeled
external OCL baseline.

Usage::

    python -m agent_airlock.cli.negotiation_bench --report markdown
    python -m agent_airlock.cli.negotiation_bench --report json
    python -m agent_airlock.cli.negotiation_bench --report text
"""

from __future__ import annotations

import argparse
import json
import sys

import structlog

from ..negotiation_bench import BenchmarkReport, run_benchmark


def _configure_structlog_to_stderr() -> None:
    """Route structlog output to stderr so stdout stays clean for the report.

    The ``@Airlock`` interception path emits ``structlog`` diagnostics
    (block / mask / policy events) while the governed scenarios run.
    Those are operator-visible diagnostics, not machine-readable output,
    so they belong on stderr — stdout is reserved for the JSON /
    Markdown / text report a calling tool will parse. Mirrors
    ``cli/corpus_bench._configure_structlog_to_stderr``.
    """
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
        cache_logger_on_first_use=True,
    )


def _pct(x: float) -> str:
    return f"{x * 100.0:.1f}%"


def _emit_text(report: BenchmarkReport) -> None:
    print("agent-airlock negotiation-bench")
    print("=" * 40)
    print(f"scenarios: {len(report.runs)}")
    print()
    print("agent-airlock (deterministic, real @Airlock interception):")
    print(f"  baseline  unsafe_execution_rate : {_pct(report.baseline_unsafe_execution_rate)}")
    print(f"  governed  unsafe_execution_rate : {_pct(report.governed_unsafe_execution_rate)}")
    print(f"  baseline  valid_task_success    : {_pct(report.baseline_valid_task_success_rate)}")
    print(f"  governed  valid_task_success    : {_pct(report.governed_valid_task_success_rate)}")
    print()
    ext = report.external_baseline
    print(f"external baseline (OCL, {ext.source}) — NOT an agent-airlock measurement:")
    print(
        f"  unsafe  {_pct(ext.baseline_unsafe_execution_rate)} -> "
        f"{_pct(ext.governed_unsafe_execution_rate)}"
    )
    print(
        f"  success {_pct(ext.baseline_valid_task_success_rate)} -> "
        f"{_pct(ext.governed_valid_task_success_rate)}"
    )


def _emit_json(report: BenchmarkReport) -> None:
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))


def _emit_markdown(report: BenchmarkReport) -> None:
    ext = report.external_baseline
    print("# agent-airlock — adversarial negotiation regression")
    print()
    print(
        "Deterministic harness over a fixed adversarial buyer-seller "
        "scenario set. Governed runs exercise the **real** `@Airlock` "
        "intercept-before-execute path (no policy-layer mocking)."
    )
    print()
    print("## Aggregate")
    print()
    print(
        "| source | unsafe_execution_rate (base → governed) | valid_task_success_rate (base → governed) |"
    )
    print("|---|---|---|")
    print(
        f"| **agent-airlock** (this harness) | "
        f"{_pct(report.baseline_unsafe_execution_rate)} → "
        f"{_pct(report.governed_unsafe_execution_rate)} | "
        f"{_pct(report.baseline_valid_task_success_rate)} → "
        f"{_pct(report.governed_valid_task_success_rate)} |"
    )
    print(
        f"| OCL (external, live LLMs, [arXiv:2606.04306]({ext.source})) | "
        f"{_pct(ext.baseline_unsafe_execution_rate)} → "
        f"{_pct(ext.governed_unsafe_execution_rate)} | "
        f"{_pct(ext.baseline_valid_task_success_rate)} → "
        f"{_pct(ext.governed_valid_task_success_rate)} |"
    )
    print()
    print(
        "> The OCL row is an **external** result measured on live frontier "
        "LLM agents (AgenticPay-adapted negotiation), reproduced here only "
        "for directional comparison. It is **not** an agent-airlock "
        "measurement, and the two are not the same experiment: agent-airlock "
        "is a deterministic execution-boundary validator, not an LLM."
    )
    print()
    print("## Per-scenario")
    print()
    print(
        "| scenario | adversarial | baseline unsafe | governed unsafe | "
        "baseline success | governed success |"
    )
    print("|---|---|---|---|---|---|")
    for r in report.runs:
        print(
            f"| `{r.scenario_id}` | {'yes' if r.is_adversarial else 'no'} | "
            f"{'⚠️ yes' if r.baseline_unsafe else 'no'} | "
            f"{'⚠️ yes' if r.governed_unsafe else '✅ no'} | "
            f"{'✅ yes' if r.baseline_valid_success else 'no'} | "
            f"{'✅ yes' if r.governed_valid_success else 'no'} |"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="airlock negotiation-bench",
        description=(
            "Run the adversarial buyer-seller negotiation regression "
            "harness and report unsafe_execution_rate + "
            "valid_task_success_rate for the ungoverned baseline vs the "
            "real @Airlock-governed path, next to the labeled external OCL "
            "baseline."
        ),
    )
    parser.add_argument(
        "--report",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format. 'markdown' emits a blog-pasteable table. Default: text.",
    )
    parser.add_argument(
        "--fail-if-governed-unsafe",
        action="store_true",
        help=(
            "Exit non-zero if the governed unsafe_execution_rate is above "
            "zero (use as a CI regression gate on the governance layer)."
        ),
    )
    args = parser.parse_args(argv)

    _configure_structlog_to_stderr()
    report = run_benchmark()

    if args.report == "json":
        _emit_json(report)
    elif args.report == "markdown":
        _emit_markdown(report)
    else:
        _emit_text(report)

    if args.fail_if_governed_unsafe and report.governed_unsafe_execution_rate > 0.0:
        print(
            "REGRESSION: governed unsafe_execution_rate "
            f"{report.governed_unsafe_execution_rate:.4f} > 0",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
