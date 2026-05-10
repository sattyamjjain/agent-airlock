# Filter-Eval RCE guard (CVE-2026-25592 + CVE-2026-26030, v0.7.5+)

`agent_airlock.mcp_spec.filter_eval_rce_guard.FilterEvalRCEGuard` is
the runtime detector for the Semantic-Kernel-class filter-eval RCE
exploitation primitive disclosed by Microsoft on 2026-05-07.

## Why

Microsoft's MSRC blog ["When prompts become shells: RCE
vulnerabilities in AI agent
frameworks"](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/)
disclosed two CVEs:

| CVE | Class | Trigger |
|---|---|---|
| **CVE-2026-25592** | Python lambda-filter eval RCE | Model-derived `filter` field reaches a runtime `compile()` / `eval()` sink |
| **CVE-2026-26030** | C# template-expression eval RCE | Model-derived template fragment reaches a runtime `Expression.Lambda<>` evaluator |

The exploit class is **not Semantic-Kernel-specific**. Any agent
framework that compiles user-controlled filter expressions is
vulnerable. The guard is a generic detector that fires on the
filter-eval syntax shape regardless of surrounding framework — an
airlock-fronted agent that *might* call into Semantic-Kernel-style
filter expressions, even from a different framework, gets the same
denial.

## Install

The guard is core. No optional extra. The Semantic Kernel package is
**not** imported (the guard is a regex pass over string values).
Operators who don't use Semantic Kernel pay zero install cost.

## Quickstart

```python
from agent_airlock import (
    Airlock,
    FilterEvalRCEGuard,
    FilterEvalRCEVerdict,
)

guard = FilterEvalRCEGuard()  # default suspect_fields, scan_all_fields=False

@Airlock()
def search_users(filter: str) -> list[dict]:
    decision = guard.evaluate({"filter": filter})
    if not decision.allowed:
        raise PermissionError(
            f"filter-eval RCE gate: {decision.detail} "
            f"(verdict={decision.verdict.value}, field={decision.matched_field})"
        )
    return run_search(filter)
```

## Default suspect-field vocabulary

The guard inspects values whose key is in
`FILTER_EVAL_RCE_DEFAULT_SUSPECT_FIELDS`:

```python
frozenset({
    "filter", "condition", "predicate",
    "template", "expression", "where", "lambda",
})
```

A determined attacker who controls the field name can hide the
lambda outside this vocabulary. Use `scan_all_fields=True` to inspect
every value:

```python
defensive = FilterEvalRCEGuard(scan_all_fields=True)
```

Operators on a non-default vocabulary can override:

```python
custom = FilterEvalRCEGuard(suspect_fields=frozenset({"my_filter", "my_template"}))
```

## Decision shape

`evaluate(args)` returns `FilterEvalRCEDecision` with five fields.
The `allowed` field intentionally mirrors `AllowlistVerdict` and
`OutcomesRubricDecision` so an integrator can chain guards on a
single short-circuit predicate.

| Verdict | When |
|---|---|
| `ALLOW` | no pattern matched |
| `DENY_PYTHON_LAMBDA` | `lambda x:` syntax detected (CVE-2026-25592) |
| `DENY_CSHARP_EXPRESSION` | `Expression.Lambda` / `Func<` / `Predicate<` detected (CVE-2026-26030) |
| `DENY_TEMPLATE_EVAL` | `{{ eval(...) }}` or `${ eval(...) }` detected |

## Companion preset

`agent_airlock.policy_presets.semantic_kernel_filter_eval_rce_2026_25592_26030_defaults()`
returns the recommended config dict — parity with the existing
`mcp_config_path_traversal_cve_2026_31402` /
`mcp_elicitation_guard_2026_04` factories:

```python
from agent_airlock.policy_presets import (
    semantic_kernel_filter_eval_rce_2026_25592_26030_defaults,
)

config = semantic_kernel_filter_eval_rce_2026_25592_26030_defaults(scan_all_fields=True)
# config["preset_id"] == "semantic_kernel_filter_eval_rce_2026_25592_26030"
# config["severity"] == "critical"
# config["default_action"] == "deny"
# config["cves"] == ("CVE-2026-25592", "CVE-2026-26030")
```

## Honest scope

- The guard is a **regex heuristic**. It catches the disclosed CVE
  payload class and the obvious obfuscation variants (multi-line
  payloads, leading whitespace). It does **not** AST-evaluate or
  compile the expression — there is no eval-on-untrusted-input
  surface in the guard itself.
- Default mode (`scan_all_fields=False`) only inspects values whose
  key is in the suspect-field vocabulary. Switch to
  `scan_all_fields=True` when the operator does not trust the
  field-name allowlist.
- The full Semantic Kernel adapter trio (lib + tests + docs) is
  scoped as an M-effort future-day row. Today's preset closes the
  exploitation class for any airlock-fronted agent that might call
  into Semantic-Kernel-style filter expressions, even from another
  framework.

## Primary source

- Microsoft MSRC, ["When prompts become shells: RCE vulnerabilities in AI agent frameworks"](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/) (2026-05-07)
