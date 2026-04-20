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

## Known gaps (tracked)

These are intentional scope cuts for v0.5.1 and are tracked as
separate issues:

- **No rootless-by-default.** `DockerBackend` assumes the Docker
  daemon it talks to is either rootless or accepts root-in-
  container workloads. Tracked in
  [#37 — rootless-required mode](https://github.com/sattyamjjain/agent-airlock/issues/37).
- **No user-namespace remap helper.** Users who want
  `--userns=host-uid-remap` style isolation must configure Docker
  themselves; we don't offer a one-liner.
- **No image-digest-pin enforcement.** `DockerBackend(image=...)`
  accepts tags (`python:3.11-slim`) or digests
  (`python@sha256:…`) but does not refuse tag-only form. Tracked in
  [#38 — image-digest-pin enforcement](https://github.com/sattyamjjain/agent-airlock/issues/38).

## Relationship to E2B and Managed backends

| Backend | Isolation | Latency | Cloud dependency | Default? |
|---------|-----------|---------|------------------|----------|
| [`E2BBackend`](../api/sandbox.md) | Firecracker MicroVM | <200 ms warm | E2B cloud | ✓ |
| `DockerBackend` (this page) | Container, `cap_drop=ALL` | ~1-2 s cold, <200 ms warm if image cached | local Docker daemon | — |
| `LocalBackend` | **None** | ~0 ms | none | dev only |
| `ManagedSandboxBackend` | Anthropic Managed Agents (session-based) | varies | Anthropic API | preview |

If you're running in air-gapped / on-prem environments where E2B
is not an option, `DockerBackend` is the recommended choice.
