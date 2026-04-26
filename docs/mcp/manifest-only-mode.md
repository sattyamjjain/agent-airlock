# Manifest-only STDIO mode (v0.5.7+)

**Module:** `agent_airlock.mcp_spec.manifest_only_mode`

The OX Security 2026-04-15 deep dive established that arbitrary
strings reaching `StdioServerParameters.command` is **the**
agent-supply-chain class of bug. Anthropic confirmed the SDK
validates nothing — that "sanitization is the developer's
responsibility." Manifest-only mode is the design that makes
runtime sanitization unnecessary because **argv never originates
from runtime input**.

## The shape

1. **Pre-register** a `StdioManifest` with a fixed `command` tuple
   under a stable `manifest_id`. Registration requires an
   HMAC-SHA256 signing key.
2. **At runtime**, callers ask `launch_from_manifest` for the
   manifest by ID. The function rejects any attempt to override
   `command`, `cwd`, or `env` outside the manifest's allowlist.

There is no surface a runtime caller can use to inject argv.

## Modes

`SecurityPolicy.stdio_mode` is a `Literal["allowlist", "manifest_only", "disabled"]`:

| Mode | Behaviour |
|---|---|
| `"allowlist"` *(default)* | v0.5.1 behaviour — runtime argv goes through `validate_stdio_command` |
| `"manifest_only"` | Only `launch_from_manifest` may spawn STDIO subprocesses |
| `"disabled"` | No STDIO subprocesses, period |

**Allowlist mode remains the default** so existing v0.5.1 callers
keep working. Manifest-only mode is opt-in for hardening-conscious
deployments.

## HMAC key storage

The signing key is loaded from `AIRLOCK_MANIFEST_SIGNING_KEY`. The
guard refuses to start with a key shorter than 32 bytes:

```bash
export AIRLOCK_MANIFEST_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
```

Rotate the key by re-registering manifests with the new key. A
cross-key resolve raises `ManifestSignatureError` so stale
registries are caught at first call.

## Quick start

```python
from agent_airlock import (
    ManifestRegistry,
    StdioManifest,
    launch_from_manifest,
)

registry = ManifestRegistry()
manifest = StdioManifest(
    manifest_id="local-fs",
    command=("uvx", "mcp-server-everything"),
    env_allowlist=frozenset({"PATH", "HOME"}),
    cwd="/var/repos/local",
    signer="sre-team",
)
registry.register(manifest, signing_key=key)

# Later, anywhere — no argv flows from runtime input:
proc = launch_from_manifest(
    "local-fs",
    registry,
    runtime_env=os.environ,
    allowed_cwd_prefixes=("/var/repos/",),
)
```

A runtime caller passing `command=["evil"]` (or any kwarg outside
`manifest_id` / `runtime_env`) raises
`ManifestRuntimeOverrideAttempted`. That's the load-bearing
guarantee.

## Errors

All four subclass `AirlockError` and are top-level re-exports:

| Error | Raised when |
|---|---|
| `ManifestNotRegisteredError` | `resolve()` called with unknown `manifest_id` |
| `ManifestSignatureError` | Stored signature does not verify against the supplied key |
| `ManifestRuntimeOverrideAttempted` | Runtime caller tried to pass argv / cwd / `command` |
| `ManifestSigningKeyError` | Signing key shorter than 32 bytes |

## Migration from allowlist mode

For a controlled rollout:

1. Keep `stdio_mode="allowlist"` while you enumerate every STDIO
   server your agents currently use.
2. Register each as a `StdioManifest`. The v0.5.7 perf benchmark
   shows resolve+verify latency at **~3 µs median** — invisible to
   any human-driven workflow.
3. Flip to `stdio_mode="manifest_only"` after the manifest list
   stabilises.

Dynamic-argv use cases (e.g. LangGraph agents that compose argv at
runtime) cannot adopt manifest-only — they should stay on
allowlist mode.

## Observability

Every clean launch emits `airlock.stdio.manifest.launch` (OTel)
with attributes:

- `airlock.stdio.manifest.signer`
- `airlock.stdio.manifest.sha256`

Spans are best-effort — a misconfigured OTel provider never
breaks the audit path.

## Primary sources

- [OX Security 2026-04-15 deep dive](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20)
- [The Hacker News (2026-04-16)](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
- [Cloudflare enterprise MCP reference architecture (2026-04-22)](https://blog.cloudflare.com/enterprise-mcp/)
