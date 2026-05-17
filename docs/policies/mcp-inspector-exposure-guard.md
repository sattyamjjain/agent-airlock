# MCP Inspector exposure guard (CVE-2026-23744 runtime extension, v0.8.0+)

`agent_airlock.mcp_spec.inspector_exposure_guard.InspectorExposureGuard`
is the **runtime listener-scan** complement to the v0.5.x
[`bind_address_guard.py`](../mcp/bind_address.md) config-time check.

## Why

[CVE-2026-23744][poc]: MCPJam Inspector ≤ 1.4.2 binds to `0.0.0.0` by
default with no auth, enabling remote install + execution of malicious
MCP servers via crafted HTTP requests. Patched in 1.4.3.

agent-airlock already covers the **config-time** check
(`bind_address_guard.py` → `UnauthenticatedPublicBindError`) — that
fires when the operator-supplied bind-address string is `0.0.0.0` / `::`.
This module covers the **runtime** path: when the actual LISTEN
socket arrives via a binary path / dynamic argv / library config that
bypassed the config-time hook.

[poc]: https://github.com/boroeurnprach/CVE-2026-23744-PoC

## Install

Core. No optional extra. **Linux-only** — uses stdlib `/proc/net/tcp`.
On macOS / Windows the guard returns
`InspectorExposureVerdict.UNKNOWN_PLATFORM_UNSUPPORTED` and
fails-open. Operators on those platforms who want a runtime check
should layer their own psutil-based scan.

## Quickstart

```python
from agent_airlock import InspectorExposureGuard, InspectorExposureVerdict

guard = InspectorExposureGuard()
decision = guard.scan_listeners()
if not decision.allowed:
    raise PermissionError(decision.detail)
```

## What it scans

- LISTEN sockets in `/proc/net/tcp`
- IPv4 `0.0.0.0` binds on the inspector port range (`6274`–`6277` by
  default). Operators extend the port set via `inspector_ports=`.

## `MCP_INSPECTOR_REQUIRE_AUTH=1` bypass

Set the env var to `1` to declare that an in-process auth handler is
installed. The guard then returns `ALLOW_AUTH_REQUIRED_DECLARED` for
public binds and logs an info-level audit line. The guard does **not**
introspect the actual auth handler.

## Decision shape

`scan_listeners(proc_net_tcp_path=None)` returns
`InspectorExposureDecision` — `allowed: bool` mirrors the v0.6.1–v0.7.x
decision family.

| Verdict | When |
|---|---|
| `ALLOW` | no inspector port bound publicly |
| `ALLOW_AUTH_REQUIRED_DECLARED` | public bind detected, but `MCP_INSPECTOR_REQUIRE_AUTH=1` |
| `DENY_UNAUTH_PUBLIC_BIND` | public bind detected, no auth declared |
| `UNKNOWN_PLATFORM_UNSUPPORTED` | non-Linux platform, fail-open |

## Companion preset

`agent_airlock.policy_presets.mcp_inspector_exposure_guard_defaults()`
returns the recommended config dict.

## Honest scope

- **Detection class:** LISTEN sockets on the inspector port range
  with IPv4 `0.0.0.0`. Does NOT detect a bind to a non-loopback IPv4
  like `192.168.0.5` — the config-time `bind_address_guard.py`
  covers that.
- **Auth-required bypass** is keyed on a single env var. Other
  in-process auth shapes (header check, IP allowlist) are NOT
  introspected.
- **Fail-open on non-Linux.** A CI matrix run on macOS / Windows
  should not red-flag a Linux-only runtime path.

## Primary source

- [CVE-2026-23744 PoC repo][poc]
