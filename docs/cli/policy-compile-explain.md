# `airlock policy compile / explain` — English in, typed policy out

**Landed in v0.5.9.** Implementation `src/agent_airlock/policy_compiler/`; CLI
`src/agent_airlock/cli/policy.py`.

## Read this before you use `compile`

**The default backend is a keyword matcher, not a model.** No LLM backend ships with
the runtime — `_REGISTRY` is empty on a fresh install — so the CLI falls back to a
built-in stub that recognises a handful of fixed phrases. Anything it does not
recognise produces a catch-all rule with **no relationship to what you asked for**:

```console
$ airlock policy compile "block any tool that deletes records"
policy_id: compiled_user_policy
description: block any tool that deletes records
rules:
  - rule_id: catch_all
    condition: missing_auth_header      # <- nothing to do with deletes
    action: warn
warning: no LLM backend is registered, so this was produced by the built-in keyword
matcher — and none of its keywords matched your text. The rule above is a
placeholder, NOT a translation of what you asked for.
```

That warning is new in v0.10.2. Before it, the same command printed valid-looking
YAML with no provenance at all, which is an invitation to deploy a policy that does
not say what you meant. Notices go to **stderr**, so `airlock policy compile ... >
policy.yaml` still writes a clean file.

The phrases the stub does recognise:

| phrase in your text | rule emitted |
|---|---|
| `0.0.0.0` or `public` | `refuse_public_bind` / `bind_address_public` / block |
| `without auth`, `no auth`, `missing auth` | `require_auth` / `missing_auth_header` / block |
| `parallel` … `above` (+ a number) | `cap_parallel_calls` / `parallel_tool_calls_above` / block |
| anything else | `catch_all` / `missing_auth_header` / **warn** |

For general English, register a real backend first:

```python
from agent_airlock.policy_compiler import register_llm_backend

def my_backend(system_prompt: str, user_text: str) -> str:
    ...  # call OpenAI / Anthropic / a local model; return the YAML
    return yaml_text

register_llm_backend("openai", my_backend)
```

```console
$ airlock policy compile --backend openai "block any tool that deletes records"
```

## Why the backend is a Protocol and ships empty

Three properties the compiler keeps that a bundled backend would cost:

1. **Deterministic.** The prompt template is hash-pinned (`PROMPT_HASH`), so upstream
   LLM drift surfaces as a CI diff rather than as a quiet behaviour change.
2. **Cached.** Outputs are keyed by `(prompt_hash, request_hash)`, so re-running the
   same English never burns tokens twice.
3. **Zero core dependency.** No provider SDK is imported, which is what keeps
   `pip install agent-airlock` Pydantic-only.

## `explain` — the other direction

```console
$ airlock policy explain compiled.yaml
$ cat compiled.yaml | airlock policy explain -
```

Takes a compiled policy YAML (or `-` for stdin) and renders it back as prose, so a
reviewer can check that the typed chain still matches the intent it was written from.
This path involves no backend and no keyword matching; it reads what is in the file.

## Honest scope

- `compile` output is a **draft**, whichever backend produced it. It is a
  `PolicyChain` you should read before loading, not a policy you should trust because
  a machine emitted it. With a real backend that is the usual LLM caveat; with the
  stub it is stronger — see the table above.
- `_REGISTRY` is module-global mutable state. A process that registers a backend named
  `"stub"` replaces the built-in one for everything in that process, including the
  CLI. The regression tests isolate against this explicitly.
- The restricted-grammar YAML loader accepts a fixed rule vocabulary. A backend that
  emits conditions outside it fails to parse rather than loading a rule the engine
  cannot evaluate.

## See also

- [`airlock policy-bundle-lock`](policy-bundle-lock.md) — pinning a compiled bundle
- [Policy guide](../guide/policy.md) — writing `SecurityPolicy` by hand
