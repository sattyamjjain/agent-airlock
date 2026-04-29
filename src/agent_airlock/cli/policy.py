"""``airlock policy compile / explain`` CLI (v0.5.9+)."""

from __future__ import annotations

import argparse
import sys

from ..policy_compiler import (
    PolicyCompiler,
    explain_preset,
    register_llm_backend,
)
from ..policy_compiler.compiler import _REGISTRY  # noqa: PLC2701


def _stub_backend(system_prompt: str, user_text: str) -> str:  # noqa: ARG001
    """Deterministic stub backend (used when no real backend is registered).

    Recognises a small set of keywords so tests + smoke usage can land
    a useful YAML without a network round-trip.
    """
    text = user_text.lower()
    rules: list[str] = []
    if "0.0.0.0" in text or "public" in text:  # nosec B104 - keyword match in user text, not a bind target
        rules.append(
            "  - rule_id: refuse_public_bind\n"
            "    condition: bind_address_public\n"
            "    action: block"
        )
    if "without auth" in text or "no auth" in text or "missing auth" in text:
        rules.append(
            "  - rule_id: require_auth\n"
            "    condition: missing_auth_header\n"
            "    action: block"
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
        rules.append(
            "  - rule_id: catch_all\n"
            "    condition: missing_auth_header\n"
            "    action: warn"
        )
    body = (
        "policy_id: compiled_user_policy\n"
        f"description: {user_text.strip().rstrip('.')}\n"
        "rules:\n" + "\n".join(rules) + "\n"
    )
    return body


def _ensure_default_backend() -> None:
    if "stub" not in _REGISTRY:
        register_llm_backend("stub", _stub_backend)


def _cmd_compile(args: argparse.Namespace) -> int:
    _ensure_default_backend()
    compiler = PolicyCompiler(backend=args.backend)
    compiled = compiler.compile(args.text)
    print(compiled.yaml, end="")
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

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
