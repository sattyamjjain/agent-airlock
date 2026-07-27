"""Unified ``airlock`` command-line dispatcher.

A single console script (``airlock``) fronts every ``agent_airlock.cli`` module in
the space-form the docs promise — ``airlock scan-tools``, ``airlock doctor``,
``airlock corpus-bench`` — instead of the ``python -m agent_airlock.cli.<name>``
long-form. Each subcommand delegates to the target module's own ``main(argv)``, so a
subcommand's flags are **identical** whether invoked as ``airlock <cmd> ...`` or
``python -m agent_airlock.cli.<module> ...``; the dispatcher never re-declares them.

Subcommand modules are imported **lazily** — only when their subcommand is invoked —
so optional-extra modules (``console`` needs ``[console]``, etc.) never break the
top-level ``airlock`` listing or an unrelated subcommand.

Run::

    airlock                    # list subcommands, exit 0
    airlock <cmd> --help       # the subcommand's own help
    python -m agent_airlock.cli <cmd> ...   # same dispatcher
"""

from __future__ import annotations

import importlib
import sys

# subcommand (space-form) -> (module basename under agent_airlock.cli, one-line help).
# Insertion order is the display order in `airlock` / `airlock --help`.
_COMMANDS: dict[str, tuple[str, str]] = {
    # Core: inspect + validate + explain.
    "scan-tools": (
        "scan_tools",
        "Static contract/type-check of MCP tool declarations (SARIF-capable).",
    ),
    "doctor": ("doctor", "Scan a codebase for unprotected tools and unsafe patterns."),
    "verify": ("verify", "Verify Airlock protection status and emit a badge."),
    "explain": ("explain", "Privilege right-sizing report (least-privilege suggestions)."),
    "policy": ("policy", "Compile and explain security policies."),
    # Attestation / evidence / packaging.
    "attest": ("attest", "Emit identity + LayerContract attestation receipts."),
    "baseline": ("baseline", "Record or compare a security baseline snapshot."),
    "manifest": ("manifest", "Generate or inspect the signed tool manifest."),
    "conformance": ("conformance", "EU AI Act Art. 12 record-keeping + evidence bundle."),
    "pack": ("pack", "Build a distributable policy pack."),
    # Benchmarks / regression harnesses.
    "corpus-bench": ("corpus_bench", "Block-rate regression bench over the security corpus."),
    "egress-bench": ("egress_bench", "Walk the CVE egress fixtures and report pass/fail."),
    "negotiation-bench": ("negotiation_bench", "Agent-to-agent negotiation guard bench."),
    "replay": ("replay", "Corpus regression replay bench."),
    # Ops / interactive / diagnostics.
    "graph": ("graph", "Render the guard/policy graph."),
    "trace": ("trace", "Watermark detection + trace redaction report."),
    "kill-switch": ("kill_switch", "Arm or disarm the global kill switch."),
    "console": ("console", "Interactive policy-rehearsal TUI (needs the [console] extra)."),
    "studio": ("studio", "Local rehearsal sandbox."),
}

_PROG = "airlock"


def _print_usage(stream: object = None) -> None:
    """Print the subcommand listing with one-line descriptions."""
    out = sys.stdout if stream is None else stream
    width = max(len(name) for name in _COMMANDS)
    lines = [
        f"usage: {_PROG} <command> [options]",
        "",
        "Agent-Airlock — a deny-by-default type-checker and contract layer for AI",
        "agent tool calls. Pick a command:",
        "",
    ]
    for name, (_, desc) in _COMMANDS.items():
        lines.append(f"  {name.ljust(width)}  {desc}")
    lines += [
        "",
        f"Run '{_PROG} <command> --help' for a command's own options.",
    ]
    print("\n".join(lines), file=out)  # type: ignore[arg-type]


def _dispatch(command: str, rest: list[str]) -> int:
    """Import the target module lazily and hand off to its ``main(argv)``."""
    module_name = _COMMANDS[command][0]
    module = importlib.import_module(f"agent_airlock.cli.{module_name}")
    entry = module.main  # every cli module exposes main(argv) -> int
    return int(entry(rest))


def main(argv: list[str] | None = None) -> int:
    """Dispatch ``argv`` to the named subcommand; return its exit code."""
    args = list(sys.argv[1:] if argv is None else argv)

    if not args or args[0] in ("-h", "--help"):
        _print_usage()
        return 0

    command, rest = args[0], args[1:]
    if command not in _COMMANDS:
        print(
            f"{_PROG}: unknown command {command!r}. Run '{_PROG} --help' for the list of commands.",
            file=sys.stderr,
        )
        return 2

    return _dispatch(command, rest)


if __name__ == "__main__":
    raise SystemExit(main())
