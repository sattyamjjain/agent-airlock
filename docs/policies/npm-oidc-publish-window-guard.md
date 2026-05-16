# OIDC publish-window guard (TanStack postmortem 2026-05-11, v0.7.6+)

`agent_airlock.mcp_spec.oidc_publish_window_guard.OIDCPublishWindowGuard`
is the runtime gate for the **TanStack 2026-05-11** npm OIDC trusted-
publisher compromise (42 packages × 84 versions, 12M weekly DL blast
radius).

## Why

Per the [TanStack postmortem][postmortem]: an attacker extracted the
runner's OIDC token from `/proc/<pid>/maps` and `/proc/<pid>/mem` of
the Runner.Worker process and used it to republish packages **outside
the workflow's own publish step**. The npm trusted-publisher binding
has no per-publish review — once configured, any code path in the
workflow can mint a publish-capable token.

Airlock's runtime surface for this class is:

> Agent that fetches / runs just-mutated package versions should
> reject blast-list pairs before tool execution.

The guard fails-closed on a `(package, version)` pair appearing in
the operator-supplied blast list, OR on a registry tarball URL
targeting any pair in the list.

[postmortem]: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem

## Install

Core. No optional extra. The `npm` / `pypi` package metadata clients
are **not** loaded — the guard is a frozenset lookup + a compiled
regex.

## Quickstart

```python
from agent_airlock import (
    OIDCPublishWindowGuard,
    OIDCPublishWindowVerdict,
    load_blast_list_from_2026_05_11,
)

guard = OIDCPublishWindowGuard(blast_list=load_blast_list_from_2026_05_11())

decision = guard.evaluate(
    {"package": "@tanstack/react-router", "version": "1.146.0-compromised-2026-05-11"}
)
# decision.allowed is False
# decision.verdict == OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR
```

## Companion preset

`agent_airlock.policy_presets.npm_oidc_publish_window_guard_defaults()`
returns the recommended config dict (preset_id, severity,
default_action, advisory_url, blast_list pre-loaded from the
2026-05-11 fixture).

## Decision shape

`evaluate(args)` returns `OIDCPublishWindowDecision` mirroring
`AllowlistVerdict` / `OutcomesRubricDecision` / `FilterEvalRCEDecision`
— all expose `allowed: bool` for chain-friendly composition.

| Verdict | When |
|---|---|
| `ALLOW` | no blast-list pattern matched |
| `DENY_BLAST_LIST_PAIR` | `(package, version)` arg pair on the list |
| `DENY_BLAST_LIST_TARBALL_URL` | npm-registry tarball URL targeting a blast pair |

## Honest scope

- The guard is a **known-bad blast-list** denier. It is **not** a
  generic OIDC anomaly detector. The architectural fix is npm's
  per-publish-review feature request (see postmortem section
  "Remediation Guidance"); the runtime side is what Airlock can
  cover today.
- The fixture is a **point-in-time snapshot** (2026-05-11). Operators
  must regenerate the JSON when new blast-list extensions are
  confirmed. Sunday weekly-review surfaces this as a checklist item.

## Primary sources

- [TanStack npm supply-chain compromise postmortem (2026-05-11)][postmortem] — 42 pkgs × 84 versions × 12M weekly DL blast radius
- [Aikido — Mini Shai-Hulud Is Back (2026-05-11)](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised) — cross-ecosystem reinforcement (Mistral SDKs, PyTorch Lightning 2.6.2/2.6.3, intercom-client)
