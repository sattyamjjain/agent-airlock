# DockerBackend (v0.5.1+)

`DockerBackend` runs an agent-airlock-wrapped tool call inside an
ephemeral Docker container. It is one of four pluggable
[`SandboxBackend`](../api/sandbox.md) implementations (E2B, Docker,
Local, Managed-stub).

## What v0.5.1 actually ships

- **Timeout enforced.** `DockerBackend.execute(..., timeout=60)`
  calls `container.wait(timeout=...)` and kills+removes the
  container on timeout. Prior to v0.5.1 the `timeout` kwarg was a
  TODO, so a runaway function would hang forever. See
  [CHANGELOG v0.5.1](../../CHANGELOG.md).
- **`no-new-privileges` always on.** The container runs with
  `security_opt=["no-new-privileges:true"]` so a child process
  cannot regain privileges via `setuid`.
- **All capabilities dropped by default.** `cap_drop=["ALL"]` —
  no `NET_ADMIN`, `SYS_ADMIN`, nothing. Tools that legitimately
  need a capability must be explicitly allow-listed via your own
  wrapping backend.
- **Pass-through `security_opt`.** Supply a seccomp profile via the
  `security_opt=["seccomp=/path/to/profile.json"]` constructor
  parameter. No default profile is shipped — Docker's own default
  seccomp profile applies when you don't override.
- **Network isolation default.** `network_mode="none"` unless you
  explicitly opt out. If your tool needs the network, use agent-
  airlock's `EndpointPolicy` at the app layer rather than opening
  the sandbox.
- **Integration tests.** Four tests behind the `pytest -m docker`
  marker prove availability, success, timeout, and network
  isolation. Default `pytest` runs **exclude** them, so CI does
  not need a Docker daemon.

## Usage

```python
from agent_airlock import Airlock, AirlockConfig
from agent_airlock.sandbox_backend import DockerBackend

backend = DockerBackend(
    image="python:3.11-slim",
    memory_limit="256m",
    cpu_limit=0.5,
    timeout=30,
    security_opt=["seccomp=/etc/docker/airlock-seccomp.json"],
)

config = AirlockConfig(sandbox_backend=backend)

@Airlock(config=config, sandbox=True, sandbox_required=True)
def risky_thing(arg: str) -> str:
    ...
```

## v0.7.0 hardening flags (#37, #38)

Two opt-in fail-closed flags shipped together in v0.7.0:

- **`require_rootless=True`** — on `is_available()`, inspects
  `docker info`'s `SecurityOptions` and refuses to report available
  unless the daemon advertises `rootless` (legacy form) or
  `name=rootless` (current form). Some threat models (multi-tenant
  CI, shared dev hosts) want the call to fail-closed when the daemon
  runs as root rather than silently downgrading.

  ```python
  backend = DockerBackend(image="python@sha256:...", require_rootless=True)
  if not backend.is_available():
      raise RuntimeError("daemon is not rootless — refusing to spawn")
  ```

- **`require_digest_pin=True`** — refuses tag-only image strings at
  construction time. Closes the floating-tag supply-chain risk where
  a tag's identity can change under you. The accepted form is
  `<name>@sha256:<64-hex>` (validated by an explicit regex).

  ```python
  # OK
  DockerBackend(image="python@sha256:" + "0" * 64, require_digest_pin=True)

  # raises ValueError
  DockerBackend(image="python:3.11-slim", require_digest_pin=True)
  ```

  Discover the digest of a tag with `docker pull --quiet <name>:<tag>`
  or `docker inspect <name>:<tag> --format='{{.RepoDigests}}'`.

## Known gaps (still tracked)

- **No user-namespace remap helper.** Users who want
  `--userns=host-uid-remap` style isolation must configure Docker
  themselves; we don't offer a one-liner.

## Relationship to E2B and Managed backends

| Backend | Isolation | Latency | Cloud dependency | Default? |
|---------|-----------|---------|------------------|----------|
| [`E2BBackend`](../api/sandbox.md) | Firecracker MicroVM | <200 ms warm | E2B cloud | ✓ |
| `DockerBackend` (this page) | Container, `cap_drop=ALL` | ~1-2 s cold, <200 ms warm if image cached | local Docker daemon | — |
| `LocalBackend` | **None** | ~0 ms | none | dev only |
| `ManagedSandboxBackend` | Anthropic Managed Agents (session-based) | varies | Anthropic API | preview |

If you're running in air-gapped / on-prem environments where E2B
is not an option, `DockerBackend` is the recommended choice.
