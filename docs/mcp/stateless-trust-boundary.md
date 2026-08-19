# The stateless trust boundary (MCP 2026-07-28)

MCP `2026-07-28` made the Streamable HTTP transport stateless and moved two things onto the
tool-argument channel that used to live in trusted transport state. This is the security
read of that change, and what agent-airlock does about it.

## What the spec changed

**SEP-2567 — cross-call state is now a server-minted handle passed as an ordinary tool
argument.** Verbatim from the
[2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog):

> Remove protocol-level sessions and the `Mcp-Session-Id` header from the Streamable HTTP
> transport. List endpoints (`tools/list`, `resources/list`, `prompts/list`) no longer vary
> per-connection. Servers that need cross-call state use explicit, server-minted handles
> passed as ordinary tool arguments (SEP-2567).

**SEP-2243 — custom headers can be sourced from tool parameters.** Verbatim from the same
changelog:

> Require standard MCP request headers (`Mcp-Method`, `Mcp-Name`) on Streamable HTTP POST
> requests, and add support for custom headers from tool parameters via `x-mcp-header`
> (SEP-2243).

## The consequence, in one sentence

**State and headers now share the injection-controlled channel** — a value that grants
cross-call continuity, and values that become HTTP headers, both now arrive in the same
place as attacker-influenced tool arguments.

## What agent-airlock does

The opt-in, deny-by-default preset **`mcp_spec_2026_07_28_handle_trust_defaults`** is the
contract check for that boundary. It complements the SEP-2567 / SEP-2575 stateless preset
`mcp_stateless_conformance_2026_07_defaults`, and is composed from existing airlock
primitives (no new engine, Pydantic-only core):

1. **A handle must be declared, not inferred.** A server-minted handle passed as a tool
   argument must be an *explicit declared parameter* of the tool contract — a distinct trust
   class from caller-supplied data — not absorbed by `**kwargs` or smuggled as a ghost
   argument. Reuses the shipped `validate_state_handle_declared`; raises `GhostArgumentError`.
2. **A tool-parameter header may not set or override a policy-decision header.** An
   `x-mcp-header`-sourced header (rendered `Mcp-Param-{name}`) that resolves to a header
   airlock makes its own decisions on is rejected. The decision set is enumerated
   **explicitly** in `RESERVED_DECISION_HEADERS` (`MCP-Protocol-Version`, `Mcp-Method`,
   `Mcp-Name`, `Authorization`, `Mcp-Session-Id`, `Origin`, `Host`) rather than matched by a
   `Mcp-*` prefix, so the boundary is auditable and cannot silently widen.
3. **An unminted handle is denied by default.** A presented handle that was not minted within
   the current policy scope is refused.

```python
from agent_airlock import mcp_spec_2026_07_28_handle_trust_defaults

preset = mcp_spec_2026_07_28_handle_trust_defaults()
preset["check_tool_call"](tool, kwargs)               # handle must be a declared param
preset["check_headers"](tool_parameter_header_names)  # no reserved-header override
preset["check_handle"](handle, minted=minted_handles) # deny an unminted handle
```

## `HandleField` — the same check as a declared contract (v0.8.77+)

The preset above works, but the operator has to supply `minted` themselves, and nothing
records *who* minted a handle, *what for*, or *for how long*. `HandleField` closes that: the
check becomes part of the tool's declared contract, backed by a per-run issuance ledger.

```python
from agent_airlock import Airlock, HandleField, handle_run, issue_handle

@Airlock()
def open_session(workspace: str) -> str:
    return issue_handle(issuer="mnemo.checkpoint", scope=workspace, ttl_seconds=900)

@Airlock()
def read_checkpoint(session: HandleField(issuer="mnemo.checkpoint", scope="workspace")) -> str:
    ...  # reached only for a handle issued in this run, by that tool, for that scope, unexpired

with handle_run("run-42"):
    read_checkpoint(session=open_session(workspace="workspace"))
```

Four distinct rejections, each with its own `BlockReason` so they stay separable in the audit
log: `handle_not_issued`, `handle_wrong_issuer`, `handle_wrong_scope`, `handle_expired`.
**Deny-by-default extends to the absence of the mechanism** — with no ledger bound to the run,
a declared handle argument is refused rather than waved through, and there is no observe-only
mode.

The two compose rather than compete: `HandleLedger.minted()` returns exactly the set
`check_handle(handle, minted=...)` expects, so a codebase already using the preset can feed it
from the ledger instead of hand-maintaining one.

Two limits, both pinned by tests in `tests/test_handle_field.py`:

- A tool whose signature ends in `**kwargs` declares nothing, so a handle smuggled through it
  is neither ghost-stripped nor `HandleField`-validated. `assert_handles_declared()` is the
  one-line front door to point 1 above, which closes it.
- Under `sandbox=True` with a real backend, `@Airlock` serialises the *undecorated* function
  into the micro-VM, so no `Annotated` validator runs on that path (`SafePath` and `SafeURL`
  included). Validate in the parent process, or keep validated tools out of the sandbox.

## The honest limit

This is a contract layer. It can require a handle to be an explicit, declared parameter, to
have been minted in this run by the declared tool for the declared scope, and to be unexpired
— but it **cannot verify that a handle the server minted is one the server _should_ have
minted**. Whether a given server-issued handle is legitimate for a given caller is a
server-side authorization question, not a request-shape question; airlock narrows the channel,
it does not replace the server's own mint-time checks.

## See also

- [MCP conformance scope](../interop/CONFORMANCE-SCOPE.md) — what airlock's conformance run
  does and does not claim.
- `mcp_stateless_conformance_2026_07_defaults` — the SEP-2567 / SEP-2575 stateless preset.
- `mcp_spec_2026_07_header_integrity_defaults` — the SEP-2243 header/body integrity preset.
