"""``airlock policy compile / explain / coverage`` CLI (v0.5.9+; ``coverage`` V0.10.29)."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys

from ..policy import SecurityPolicy
from ..policy_compiler import (
    PolicyCompiler,
    explain_preset,
    register_llm_backend,
)
from ..policy_compiler.compiler import _REGISTRY  # noqa: PLC2701
from ..policy_coverage import CoverageReport, airlock_tools, coverage_report


def _stub_backend(system_prompt: str, user_text: str) -> str:  # noqa: ARG001
    """Deterministic stub backend (used when no real backend is registered).

    Recognises a small set of keywords so tests + smoke usage can land
    a useful YAML without a network round-trip.
    """
    text = user_text.lower()
    rules: list[str] = []
    if "0.0.0.0" in text or "public" in text:  # nosec B104 - keyword match in user text, not a bind target
        rules.append(
            "  - rule_id: refuse_public_bind\n    condition: bind_address_public\n    action: block"
        )
    if "without auth" in text or "no auth" in text or "missing auth" in text:
        rules.append(
            "  - rule_id: require_auth\n    condition: missing_auth_header\n    action: block"
        )
    if "parallel" in text and "above" in text:
        # Pull a fan-out number if one is present, default 8.
        n = "8"
        for tok in text.split():
            if tok.isdigit():
                n = tok
                break
        rules.append(
            f"  - rule_id: cap_parallel_calls\n"
            f"    condition: parallel_tool_calls_above\n"
            f"    threshold: {n}\n"
            f"    action: block"
        )
    if not rules:
        rules.append("  - rule_id: catch_all\n    condition: missing_auth_header\n    action: warn")
    body = (
        "policy_id: compiled_user_policy\n"
        f"description: {user_text.strip().rstrip('.')}\n"
        "rules:\n" + "\n".join(rules) + "\n"
    )
    return body


def _ensure_default_backend() -> None:
    if "stub" not in _REGISTRY:
        register_llm_backend("stub", _stub_backend)


#: Emitted by :func:`_stub_backend` when no keyword matched. Its presence in the
#: output means the English was not translated at all.
_CATCH_ALL_MARKER = "rule_id: catch_all"


def _cmd_compile(args: argparse.Namespace) -> int:
    _ensure_default_backend()
    compiler = PolicyCompiler(backend=args.backend)
    compiled = compiler.compile(args.text)
    print(compiled.yaml, end="")

    # Say what produced this. The default backend is a keyword matcher, not a
    # model: it recognises a handful of phrases and otherwise emits a catch-all
    # rule whose body has nothing to do with the request. Printing valid-looking
    # YAML with no provenance invites a user to trust a policy that does not say
    # what they asked for — `compile "block any tool that deletes records"`
    # returns a rule about `missing_auth_header`.
    #
    # Notices go to stderr so `airlock policy compile ... > policy.yaml` still
    # produces a clean file.
    if args.backend == "stub":
        if _CATCH_ALL_MARKER in compiled.yaml:
            print(
                "warning: no LLM backend is registered, so this was produced by the "
                "built-in keyword matcher — and none of its keywords matched your text. "
                "The rule above is a placeholder, NOT a translation of what you asked "
                "for. Register a real backend with register_llm_backend() before "
                "relying on this output.",
                file=sys.stderr,
            )
        else:
            print(
                "note: produced by the built-in keyword matcher, not a model. It "
                "recognises a small fixed set of phrases; register a real backend with "
                "register_llm_backend() for general English.",
                file=sys.stderr,
            )
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    text = args.preset_yaml.read() if hasattr(args.preset_yaml, "read") else args.preset_yaml
    # Naive parse: split into key: value pairs then pass through.
    preset: dict[str, object] = {}
    rules: list[dict[str, object]] = []
    in_rules = False
    current: dict[str, object] | None = None
    for line in text.splitlines():
        ss = line.strip()
        if not ss or ss.startswith("#"):
            continue
        if line == "rules:":
            in_rules = True
            continue
        if in_rules:
            if line.startswith("  - "):
                if current is not None:
                    rules.append(current)
                current = {}
                inner = line[4:]
                if ":" in inner:
                    k, _, v = inner.partition(":")
                    current[k.strip()] = v.strip()
            elif line.startswith("    "):
                if current is not None and ":" in ss:
                    k, _, v = ss.partition(":")
                    current[k.strip()] = v.strip()
        else:
            if ":" in line:
                k, _, v = line.partition(":")
                preset[k.strip()] = v.strip()
    if current is not None:
        rules.append(current)
    if rules:
        preset["rules"] = rules
    print(explain_preset(preset))
    return 0


class _UsageError(Exception):
    """A coverage run that cannot start: the module or the policy cannot be loaded."""


def _load_policy(spec: str) -> SecurityPolicy:
    """The ``SecurityPolicy`` that ``MODULE:NAME`` names (``NAME`` may be dotted)."""
    module_name, sep, attribute = spec.partition(":")
    if not sep or not module_name or not attribute:
        raise _UsageError(f"--policy takes MODULE:NAME, got {spec!r}")
    target: object = importlib.import_module(module_name)
    for part in attribute.split("."):
        target = getattr(target, part)
    if not isinstance(target, SecurityPolicy):
        raise _UsageError(
            f"{spec} is a {type(target).__name__}, not a SecurityPolicy; a policy resolver "
            "cannot be classified without a call's context"
        )
    return target


def _print_report(report: CoverageReport, module: str, policy: str) -> None:
    print(f"policy coverage of {module} under {policy} ({len(report.tools)} tools)")
    width = max(len(entry.tool) for entry in report.tools)
    for entry in report.tools:
        print(f"  {entry.coverage.value:<20} {entry.tool:<{width}}  {entry.rule}")
    if report.uncovered:
        count = len(report.uncovered)
        noun = "tool is" if count == 1 else "tools are"
        print(
            f"\n{count} {noun} admitted only because allowed_tools is empty: "
            f"{', '.join(report.uncovered)}\nName each in allowed_tools, deny it, or "
            "escalate it."
        )


def _cmd_coverage(args: argparse.Namespace) -> int:
    if os.getcwd() not in sys.path:
        sys.path.insert(0, os.getcwd())  # the console script's sys.path lacks the project
    try:
        policy = _load_policy(args.policy)
        tools = airlock_tools(args.module)
    except (_UsageError, ImportError, AttributeError) as exc:
        print(f"airlock policy coverage: {exc}", file=sys.stderr)
        return 2
    if not tools:
        print(
            f"airlock policy coverage: found no @Airlock tools in {args.module}; point "
            "--module at the package that defines them",
            file=sys.stderr,
        )
        return 2
    report = coverage_report(policy, tools)
    if args.format == "json":
        print(json.dumps({"module": args.module, "policy": args.policy, **report.to_dict()}))
    else:
        _print_report(report, args.module, args.policy)
    return 0 if report.covered else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock policy")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_compile = sub.add_parser("compile")
    p_compile.add_argument("text", help="English policy statement")
    p_compile.add_argument("--backend", default="stub")
    p_compile.set_defaults(func=_cmd_compile)

    p_explain = sub.add_parser("explain")
    p_explain.add_argument(
        "preset_yaml",
        type=argparse.FileType("r"),
        help="Path to a compiled policy YAML (use '-' for stdin)",
    )
    p_explain.set_defaults(func=_cmd_explain)

    p_coverage = sub.add_parser(
        "coverage",
        help="classify every @Airlock tool of a module under a policy; exit 1 when one is "
        "admitted only because allowed_tools is empty",
    )
    p_coverage.add_argument(
        "--module", required=True, help="module or package whose @Airlock tools to check"
    )
    p_coverage.add_argument(
        "--policy", required=True, help="the SecurityPolicy to check them against, MODULE:NAME"
    )
    p_coverage.add_argument("--format", choices=["text", "json"], default="text")
    p_coverage.set_defaults(func=_cmd_coverage)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
