# DockerBackend (v0.5.1+)

`DockerBackend` runs a Python function inside an ephemeral Docker
container. It is one of the `SandboxBackend` implementations in
`agent_airlock.sandbox_backend` (E2B, Docker, Local, Modal, and a
Managed Agents stub).

## What v0.5.1 actually ships

- **Timeout enforced.** `DockerBackend.execute(..., timeout=60)`
  calls `container.wait(timeout=...)` and kills+removes the
  container on timeout. Prior to v0.5.1 the `timeout` kwarg was a
  TODO, so a runaway function would hang forever. See
  [CHANGELOG v0.5.1](https://github.com/sattyamjjain/agent-airlock/blob/main/CHANGELOG.md).
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
  isolation. Default `pytest` runs **exclude** them; CI's
  `docker-sandbox` job builds the repo `Dockerfile` and requires all
  four to pass.

## Usage

`@Airlock(sandbox=True)` does not take a backend: its sandbox path
always runs through E2B, and `AirlockConfig` has no backend setting.
Call the backend's `execute()` yourself. It returns a `SandboxResult`
instead of raising, and the timeout is a per-call argument, not a
constructor parameter:

```python
from agent_airlock.sandbox_backend import DockerBackend

backend = DockerBackend(
    image="airlock-sandbox:py3.11",  # must have cloudpickle installed; see below
    memory_limit="256m",
    cpu_limit=0.5,
    security_opt=["seccomp=/etc/docker/airlock-seccomp.json"],
)

def risky_thing(arg: str) -> str:
    return arg.upper()

result = backend.execute(risky_thing, args=("hello",), kwargs={}, timeout=30)
if result.success:
    print(result.result)  # HELLO
else:
    print(result.error)
```

The host needs the `docker` Python package, which no extra installs,
and `cloudpickle` (in the `[sandbox]` extra). The image needs
`cloudpickle` too: the script the backend runs starts with
`import cloudpickle`, and with `network_mode="none"` the container
cannot install it, so with the default `python:3.11-slim` image
`execute()` fails with `Container exited with status 1`. Use the
host's Python version in the image, because cloudpickle sends a
function defined in `__main__` as bytecode. A function it can import
by name is sent by reference instead, so its module must be installed
in the image as well. A minimal image:

```dockerfile
FROM python:3.11-slim
RUN pip install --no-cache-dir cloudpickle
```

The repo's `Dockerfile` builds the image the integration tests use.

To pick a backend by availability, `get_default_backend(config=None)`
(exported from `agent_airlock`) returns `E2BBackend` when an E2B API
key is set (on `config` or in `E2B_API_KEY`) and the SDK is installed,
else `DockerBackend()` with the
default image when a Docker daemon answers, else
`LocalBackend(allow_unsafe=True)`, which has no isolation, with a
`no_sandbox_available` warning.

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

  Discover the digest of a tag from the `Digest:` line `docker pull <name>:<tag>` prints,
  or with `docker inspect <name>:<tag> --format='{{.RepoDigests}}'`.

## Known gaps (still tracked)

- **No user-namespace remap helper.** Users who want
  `--userns=host-uid-remap` style isolation must configure Docker
  themselves; we don't offer a one-liner.

## Relationship to E2B and Managed backends

| Backend | Isolation | Per call | Dependency |
|---------|-----------|----------|------------|
| [`E2BBackend`](../api/sandbox.md) | Firecracker MicroVM | Reuses a sandbox from the shared E2B pool | E2B cloud |
| `DockerBackend` (this page) | Container, `cap_drop=ALL` | Starts, then removes, a new container | local Docker daemon |
| `ModalBackend` | Modal sandbox (gVisor) | Creates a new Modal sandbox | Modal (`[modal]` extra) |
| `LocalBackend` | **None** | Calls the function in-process | none (dev only) |
| `ManagedSandboxBackend` | None: `execute()` never runs the function | Returns a failed `SandboxResult` | `anthropic` SDK and API key |

Only the E2B path is used by `@Airlock(sandbox=True)`, and
`get_default_backend()` never returns `ModalBackend` or
`ManagedSandboxBackend`.

If you're running in air-gapped / on-prem environments where E2B
is not an option, `DockerBackend` is the recommended choice, called
directly as in [Usage](#usage).
