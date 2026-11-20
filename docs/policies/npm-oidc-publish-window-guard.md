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
replaces the pairs. Since 0.10.36 `rescoped_names` comes back too (see
[Rescoped MCP malware names](#rescoped-mcp-malware-names)). Build the guard from all of them:

```python
from agent_airlock import OIDCPublishWindowGuard
from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

cfg = npm_oidc_publish_window_guard_defaults(installs_from="npm")
guard = OIDCPublishWindowGuard(
    blast_list=cfg["blast_list"],
    blocked_packages=cfg["blocked_packages"],
    advisories=cfg["advisories"],
    installs_from=cfg["installs_from"],
    rescoped_names=cfg["rescoped_names"],
)
decision = guard.evaluate({"package": "@ethersphere/bee-js@13.3.0"})
# decision.allowed is False; decision.detail names GHSA-hh7j-5m3j-23pf
```

## Rescoped MCP malware names

A malicious MCP server is often published again under a fresh npm scope with the same package
name. [GHSA-m5xq-h2p4-962g][m5xq] (2026-11-19, critical) is `@fdcasj_dfew/md-doc-mcp` 1.0.0
and 1.0.1: advertised as a Markdown toolkit, its `index.js` queries Alibaba Cloud's instance
metadata service when the module loads, before any MCP message, and the advisory ties it to the
earlier `@ifasn` family. The 2026-11-14 snapshot already listed `@ifasn/md-doc-mcp`, `-mdd-`,
`-mmd-`, `-mmdd-`, `-ms-doc-mcp` and `@rfewqa-fes/mnm-doc-mcp`, but the guard matched exact
`@scope/name`, so each new scope passed until the next refresh.

Since 0.10.36 the preset also returns `rescoped_names`, built by
`rescoped_name_index(feed)`: every scoped npm name in the snapshot whose basename (the part
after `@scope/`) names MCP, mapped to one listed full name and its advisory ids. A scoped npm
name that the pair and whole-package lookups did not match, whose basename is in that index,
and which is not itself listed, is refused at every version as `DENY_RESCOPED_MALWARE_NAME`:

```python
# With the 2026-11-14 snapshot, before any advisory named the new scope:
decision = guard.evaluate({"package": "@fdcasj_dfew/md-doc-mcp@1.0.0"})
# decision.verdict == OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME
# decision.detail starts "@fdcasj_dfew/md-doc-mcp shares the basename of
#   @ifasn/md-doc-mcp, GHSA-rvw8-22w3-342v"
```

The shipped 2026-11-20 snapshot lists `@fdcasj_dfew/md-doc-mcp` itself, so that call is now a
`DENY_BLAST_LIST_PAIR`, and the next scope (`@newscope/md-doc-mcp`) is the one the rescope
check refuses. Where several scopes list one basename, the index names the first in sorted
order, so the refusal may cite another scope's advisory than the one you expect.

The same test reads a registry tarball URL's package path. Only basenames with `mcp` as a whole
word are indexed (`md-doc-mcp`, `mcp-weather-server`), never a generic one (`mcp`,
`mcp-server`, `server-mcp`, `mcp-client`, `mcp-tools`, `mcp-cli`), so `@company/mcp` and
`@modelcontextprotocol/sdk` pass. From the 2026-11-14 snapshot the index holds 11 basenames;
from the 2026-11-20 one, 13.

If you publish a package that shares a listed basename, put its full name on the guard's
`rescope_allow`:

```python
guard = OIDCPublishWindowGuard(
    blast_list=cfg["blast_list"],
    blocked_packages=cfg["blocked_packages"],
    advisories=cfg["advisories"],
    installs_from=cfg["installs_from"],
    rescoped_names=cfg["rescoped_names"],
    rescope_allow=frozenset({"@yourco/md-doc-mcp"}),
)
```

`npm_oidc_publish_window_guard_defaults(match_rescoped=False)` leaves `rescoped_names` empty,
which is the guard as it was before 0.10.36. An unscoped copy (`md-doc-mcp`) or a copy under a
new basename still passes until an advisory names it.

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
- The shipped snapshot, `malware_blast_2026_11_20.json`, holds advisories published since
  2026-10-11: 2,860 advisories, 4,450 entries (2,619 exact releases, 1,831 whole packages),
  531 KB, among them GHSA-m5xq-h2p4-962g. It replaces `malware_blast_2026_11_14.json`
  (2,376 advisories, 3,857 entries); the older files stay in `data/` and the loader reads
  the newest. One advisory in the 2026-11-14 file, GHSA-q2mc-9hgr-vmx2
  (`screenshot-desktop` 1.16.0), was withdrawn by GitHub on 2026-11-16 and is not in the
  new one; two in the 2026-11-11 file were withdrawn on 2026-11-13. When
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
| `DENY_RESCOPED_MALWARE_NAME` | a scoped npm name sharing a listed MCP malware package's basename under another scope (0.10.36) |
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
- [GHSA-m5xq-h2p4-962g (2026-11-19)][m5xq], `@fdcasj_dfew/md-doc-mcp`: the `@ifasn` MCP malware under a new scope, the reason for the rescoped-name check

[ghsa]: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
[m5xq]: https://github.com/advisories/GHSA-m5xq-h2p4-962g
