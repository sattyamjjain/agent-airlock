"""Reverse the compile direction: preset / chain -> plain English."""

from __future__ import annotations

from typing import Any

from .compiler import PolicyChain, PolicyRule

_CONDITION_NL: dict[str, str] = {
    "bind_address_public": "the MCP server binds to a public address (0.0.0.0 / ::)",
    "missing_auth_header": "the request carries no authentication header",
    "shell_metachar_in_argv": "any argv element contains a shell metacharacter",
    "parallel_tool_calls_above": "more than {threshold} parallel tool calls are issued in one turn",
    "model_id_prefix": "the model id starts with the configured prefix",
    "egress_per_call_above": "the per-call egress payload exceeds {threshold} bytes",
}


def _explain_rule(rule: PolicyRule) -> str:
    template = _CONDITION_NL.get(rule.condition, rule.condition)
    if template and "{threshold}" in template:
        body = template.format(threshold=rule.threshold)
    else:
        body = template or rule.condition
    return f"  • {rule.action.upper()} when {body}"


def explain_chain(chain: PolicyChain) -> str:
    """Return a multi-line plain-English description of the chain."""
    lines = [f"Policy: {chain.policy_id}", f"Summary: {chain.description}", "Rules:"]
    for r in chain.rules:
        lines.append(_explain_rule(r))
    return "\n".join(lines)


def explain_preset(preset: dict[str, Any]) -> str:
    """Best-effort English rendering for an arbitrary preset dict.

    The compiler ships chains with a known shape, but airlock's
    existing presets are dicts of disparate shape. This explainer
    handles both: chain-shaped inputs route through ``explain_chain``,
    legacy dicts get a generic key-value render.
    """
    if "policy_id" in preset and "rules" in preset and isinstance(preset["rules"], (list, tuple)):
        rules: list[PolicyRule] = []
        for r in preset["rules"]:
            if isinstance(r, PolicyRule):
                rules.append(r)
            elif isinstance(r, dict):
                rules.append(
                    PolicyRule(
                        rule_id=str(r.get("rule_id", "")),
                        condition=str(r.get("condition", "")),  # type: ignore[arg-type]
                        action=str(r.get("action", "block")),  # type: ignore[arg-type]
                        threshold=(
                            float(r["threshold"]) if r.get("threshold") not in (None, "") else None
                        ),
                    )
                )
        chain = PolicyChain(
            policy_id=str(preset["policy_id"]),
            description=str(preset.get("description") or ""),
            rules=tuple(rules),
        )
        return explain_chain(chain)
    # Legacy dict
    lines = [f"Preset: {preset.get('preset_id') or '<unknown>'}"]
    for k, v in preset.items():
        if k == "preset_id":
            continue
        lines.append(f"  {k}: {v}")
    return "\n".join(lines)


__all__ = ["explain_chain", "explain_preset"]
