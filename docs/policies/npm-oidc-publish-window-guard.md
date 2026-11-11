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

Since 0.10.32 it also carries the malware advisory snapshot (below): its exact releases are
added to `blast_list`, and `blocked_packages`, `advisories` and `malware_feed_as_of` come back
beside it. `include_malware_feed=False` leaves it out, and an explicit `blast_list` still
replaces the pairs. Build the guard from all three:

```python
from agent_airlock import OIDCPublishWindowGuard
from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

cfg = npm_oidc_publish_window_guard_defaults(installs_from="npm")
guard = OIDCPublishWindowGuard(
    blast_list=cfg["blast_list"],
    blocked_packages=cfg["blocked_packages"],
    advisories=cfg["advisories"],
    installs_from=cfg["installs_from"],
)
decision = guard.evaluate({"package": "@ethersphere/bee-js@13.3.0"})
# decision.allowed is False; decision.detail names GHSA-hh7j-5m3j-23pf
```

## Refreshing from malware advisories

The incident list covers one incident. GitHub's advisory database and OSV publish malicious
npm and PyPI packages every day, and until 0.10.32 none of them reached the guard until
someone edited a JSON file.

- `scripts/refresh_malware_blast.py` (maintainer-run, the only part that uses the network)
  pages through `GET https://api.github.com/advisories?type=malware` for `npm` and `pip`, can
  also read an osv.dev `all.zip` already on disk (`--osv-zip`), and writes
  `src/agent_airlock/data/malware_blast_<YYYY_MM_DD>.json`. Set `GITHUB_TOKEN` for the
  authenticated rate limit. `--since YYYY-MM-DD` limits it to advisories published since
  then. It filters on the publish date because GitHub re-touches old malware advisories in
  bulk, so an update-date window is most of the feed.
- The shipped snapshot, `malware_blast_2026_11_11.json`, holds advisories published since
  2026-10-11: 1,548 advisories, 2,907 entries (2,190 exact releases, 717 whole packages),
  330 KB. It replaces `malware_blast_2026_11_10.json` (1,485 advisories, 2,772 entries),
  which stays in `data/` until the new one has shipped; the loader reads the newest. When
  counted on 2026-11-10, the whole feed was 121,888 malware advisories, mostly from three
  waves (July, August and September 2026); a snapshot of the last 90 days alone was 87,842
  entries and 9.8 MB, took about 0.7 s and 73 MB to load, and would add that much to the
  repository at every refresh. npm takes most flagged packages down, so old entries mostly guard releases the
  registry no longer serves, though a caching proxy can still serve them. Run the script with
  an earlier `--since` if yours does.
- `load_malware_blast_snapshot()` reads the newest snapshot the install ships, offline;
  `load_blast_list_from_advisories(paths)` reads advisory files you supply.
- An advisory that names exact versions adds pairs. One that calls every version malicious
  (`> 0`, which most GitHub malware advisories use, `>= 0`, an empty range, or OSV
  `introduced: "0"` with no versions list) adds a whole package: any version is refused, and so
  is a request with no version.
- A whole package has no version to narrow it, so it is matched in one ecosystem: the one the
  argument's syntax names (a pip specifier such as `==`, `>=` or `[extra]` is PyPI;
  `@scope/name`, `name@1.2.3`, `npm:` or a tarball URL is npm), else the one `installs_from`
  names. `installs_from` (`"npm"`, `"pypi"` or `"any"`) is required with `blocked_packages`:
  npm malware squats real PyPI names. Across GitHub's whole malware feed on 2026-11-10, 589 npm
  whole-package names were also PyPI projects, 82 of them in PyPI's top 15,000, among them
  `typing-extensions`, `pydantic`, `python-dotenv`, `uvicorn` and `gunicorn`. A pip tool on a
  guard that read bare names in both registries would refuse them all. Pairs still match in
  either ecosystem; among PyPI's top 2,000 projects one npm malware pair equals a real release
  (`asgiref` 1.0).
- Skipped, and counted in the snapshot's `skipped` and `skipped_by_reason`: another ecosystem, a range such as
  `< 2.0.0` (the advisory does not say which releases inside it are malicious), and an OSV
  record that is not malware (a reviewed GHSA vulnerability: reading its affected versions as
  malicious would block safe releases). An OSV record counts as malware when its id is
  `MAL-*` or it carries CWE-506. Withdrawn advisories are left out.
- A malformed document stops the refresh with the file and field named; nothing is written
  from a partial read.

The snapshot is only as current as its date (`malware_feed_as_of`). A package flagged after it
passes until the next refresh.

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
