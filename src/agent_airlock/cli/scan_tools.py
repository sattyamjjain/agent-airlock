"""``airlock scan-tools`` — static contract / type-checker for MCP tool declarations.

Reads a set of MCP tool definitions (a ``.json`` file, a directory of them, or an
``mcp.json`` / ``claude_desktop_config.json`` config with inlined tool schemas) and
statically checks each tool's declared contract against a least-privilege
:class:`~agent_airlock.policy.SecurityPolicy`.

This is a *type-checker for AI tool calls*, not a content-signature tool-poisoning
scanner (MCP-Scan, eSentire MCP-Scanner) and not the runtime ``@Airlock`` seam. It
flags over-broad argument surfaces, missing type constraints, capability caps that
exceed the policy, and server-card tool descriptions that widen the trust boundary
(reusing the shipped ``mcp_spec_2026_07`` Server-Card / SEP-2468 preset).

Invocation (console script; the unified ``airlock <subcommand>`` dispatcher is a
separate, deferred PR — see ``pyproject.toml``)::

    airlock-scan-tools ./tools/ --policy strict
    python -m agent_airlock.cli.scan_tools ./mcp.json --output json

Exit codes: ``0`` = all pass, ``1`` = warnings only, ``2`` = at least one failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from ..scan import POLICY_CHOICES, load_tool_defs, resolve_policy, scan_tools
from ..scan.contract import Grade, ScanReport
from ..scan.loaders import LoadedTools

_GRADE_LABEL = {Grade.PASS: "PASS", Grade.WARN: "WARN", Grade.FAIL: "FAIL"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="airlock-scan-tools",
        description=(
            "Statically type-check MCP tool declarations against a least-privilege "
            "SecurityPolicy (contract layer for AI tool calls)."
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="A .json tool-definition file, a directory of them, or an mcp.json-style config.",
    )
    parser.add_argument(
        "--policy",
        choices=POLICY_CHOICES,
        default="strict",
        help="Least-privilege policy to check against (default: strict).",
    )
    parser.add_argument(
        "--output",
        choices=("text", "json", "sarif"),
        default="text",
        help="Report format (default: text). 'sarif' emits SARIF 2.1.0 for the GitHub Security tab.",
    )
    return parser


def run(path: str, policy_name: str) -> tuple[ScanReport, LoadedTools]:
    """Load tool defs from ``path`` and scan them against the named policy."""
    loaded = load_tool_defs(path)
    policy = resolve_policy(policy_name)
    report = scan_tools(loaded.tools, policy, policy_name=policy_name)
    return report, loaded


def _print_text(report: ScanReport, loaded: LoadedTools) -> None:
    print("\n=== Airlock scan-tools (contract checker) ===\n")
    print(f"Policy: {report.policy_name}")
    print(f"Tools scanned: {report.tools_scanned}")
    print(f"  pass: {len(report.passed)}  warn: {len(report.warned)}  fail: {len(report.failed)}")
    print()
    for result in report.results:
        label = _GRADE_LABEL[result.grade]
        print(f"[{label}] {result.tool_name}  (cap: {result.inferred_capability})")
        for v in result.violations:
            print(f"    {v.code} ({v.grade.value}): {v.message}")
            if v.suggestion:
                print(f"      -> {v.suggestion}")
    for warning in loaded.warnings:
        print(f"  note: {warning}")
    print()
    if report.exit_code == 2:
        print("Status: FAILED — contract violations found")
    elif report.exit_code == 1:
        print("Status: WARNING — under-specified contracts")
    else:
        print("Status: PASSED — all tool contracts fit the policy")


def _print_json(report: ScanReport, loaded: LoadedTools) -> None:
    data = report.to_dict()
    data["loader_warnings"] = loaded.warnings
    data["sources"] = loaded.sources
    print(json.dumps(data, indent=2))


def _print_sarif(report: ScanReport, loaded: LoadedTools, scanned_path: str) -> None:
    from .. import __version__
    from ..scan.sarif import to_sarif

    log = to_sarif(report, version=__version__, sources=loaded.sources, scanned_path=scanned_path)
    print(json.dumps(log, indent=2))


def _quiet_stdout_logging() -> None:
    """Route structlog to stderr at ERROR level so stdout stays report-only.

    The Server-Card guard logs a warning on every flagged description. For a
    *scanner* that is expected to find flagged tools, that log is noise — and by
    default structlog's ``PrintLogger`` writes to stdout, which would corrupt
    ``--output json``. This keeps stdout pure (report only) and drops the guard's
    warnings; flagged tools are still fully reported in the scan output itself.
    """
    import logging

    import structlog

    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the report exit code (0 / 1 / 2)."""
    _quiet_stdout_logging()
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        report, loaded = run(args.path, args.policy)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.output == "json":
        _print_json(report, loaded)
    elif args.output == "sarif":
        _print_sarif(report, loaded, args.path)
    else:
        _print_text(report, loaded)
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
