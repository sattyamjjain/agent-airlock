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

It reads each spelling a package manager resolves to the same release:
`name@1.2.3`, an alias (`alias@npm:name@1.2.3`), a `version` written
`npm:1.2.3` or `npm:@scope/real@1.2.3` (Yarn, pnpm), a tarball URL given
as the `package` or as `name@<url>`, and a URL as Node's `new URL()`
reads it, with a backslash as a path separator and `.` / `..` segments
(`%2e` spellings included) resolved. Until 0.10.28 each of those walked
past it.

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
    {"package": "@tanstack/react-router", "version": "1.169.5"}
)
# decision.allowed is False
# decision.verdict == OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR
```

## Companion preset

`agent_airlock.policy_presets.npm_oidc_publish_window_guard_defaults()`
returns the recommended config dict (preset_id, severity,
default_action, advisory_url, ghsa_url, blast_list pre-loaded from the
current dated snapshot, `data/oidc_publish_blast_2026_10_28.json`).

## Decision shape

`evaluate(args)` returns `OIDCPublishWindowDecision` mirroring
`AllowlistVerdict` / `OutcomesRubricDecision` / `FilterEvalRCEDecision`
— all expose `allowed: bool` for chain-friendly composition.

| Verdict | When |
|---|---|
| `ALLOW` | no blast-list pattern matched |
| `DENY_BLAST_LIST_PAIR` | `(package, version)` arg pair on the list |
| `DENY_BLAST_LIST_TARBALL_URL` | npm-registry tarball URL targeting a blast pair |
| `DENY_UNINSPECTABLE` | an argument shape the guard cannot read |

## Honest scope

- The guard is a **known-bad blast-list** denier. It is **not** a
  generic OIDC anomaly detector. The architectural fix is npm's
  per-publish-review feature request (see postmortem section
  "Remediation Guidance"); the runtime side is what Airlock can
  cover today.
- It matches exact releases only. A range (`^1.169.0`) that could resolve to
  a listed release is not resolved here, and a git spec or a tarball on any host
  but `registry.npmjs.org` and `registry.yarnpkg.com` is not read.
- The list is a **point-in-time copy** of the affected-version table of
  [GHSA-g7cv-rxg3-hmpx][ghsa] (CVE-2026-45321), retrieved 2026-10-28: 42 npm
  packages, two exact versions each. Operators must regenerate the JSON as a
  new dated snapshot when new blast-list extensions are confirmed. Sunday
  weekly-review surfaces this as a checklist item.
- Until 0.10.28 the shipped snapshot (`data/oidc_publish_blast_2026_05_11.json`,
  kept as superseded) could not match a real install: 90 of its 93 versions
  carried a synthetic `-compromised-2026-05-11` suffix no registry publishes, it
  named `@tanstack/react-query`, which the postmortem lists as clean, and its
  three PyPI rows appear in neither source it cited.
- The wider Mini Shai-Hulud wave (Mistral, UiPath and other npm scopes, per
  Aikido) is not in the list. Pass those pairs as a caller-supplied
  `blast_list` from their own advisories.

## Primary sources

- [TanStack npm supply-chain compromise postmortem (2026-05-11)][postmortem] — 42 pkgs × 84 versions × 12M weekly DL blast radius
- [GHSA-g7cv-rxg3-hmpx (CVE-2026-45321)][ghsa] — the affected-version table the shipped list is copied from
- [Aikido — Mini Shai-Hulud Is Back (2026-05-11)](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised) — the wider npm wave (Mistral, UiPath and other scopes); its packages are not in the list

[ghsa]: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
