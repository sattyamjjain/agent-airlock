# `airlock kill-switch` — HMAC-signed freeze with quorum reset

**Landed in v0.5.9.** Implementation `src/agent_airlock/kill_switch/`; CLI
`src/agent_airlock/cli/kill_switch.py`.

## Status: operational as of v0.8.86

**Through v0.8.85 this froze nothing.** The HMAC signing, the envelope, the listener state
machine and the M-of-N quorum were all correct and all inert, because
`KillSwitchListener` was never constructed inside the library — the only references
outside `kill_switch/` were the CLI and the CLI dispatcher table. Triggering the switch
halted no tool call anywhere.

Three things changed:

| | before v0.8.85 | now |
|---|---|---|
| `@Airlock` consults the switch | never | yes, ahead of every other gate |
| Cross-process transport | NATS/Redis/S3 were stubs delegating to an in-process queue | `RedisStreamTransport` under the `[redis]` extra |
| CLI `trigger` / `reset` | published into a transport discarded at exit, printed `OK` | require a real transport, or **fail** |

**It is opt-in and it is two steps.** A process must both construct a listener *and*
register it; constructing one alone still changes nothing:

```python
from agent_airlock.kill_switch import HMACBroadcastSigner, KillSwitchListener, registry
from agent_airlock.kill_switch.transports import RedisStreamTransport

registry.install(KillSwitchListener(
    signers=(HMACBroadcastSigner(keyid="ops-a", key=KEY),),
    transport=RedisStreamTransport.from_url("redis://localhost:6379/0"),
))
```

After `install`, a blocked call returns `block_reason: "kill_switch"` — a distinct reason
from `policy_violation`, because "an operator halted the fleet" and "this call is
forbidden" need different responses.

## What it does

An operator signs a `trigger` broadcast with a shared key. Every process running a
`KillSwitchListener` that holds a matching key sees `state == TRIGGERED` on its next
`poll()` and reports `is_frozen()`. Returning to service needs a quorum of *distinct*
keyids — 2-of-3 by default — so one compromised key cannot unilaterally re-enable agents.

The wire envelope is compact JSON with sorted keys, signed over its canonical form:

```json
{"action":"trigger","keyid":"ops-a","reason":"prod incident 412",
 "signature":"<hex hmac-sha256>","ts_epoch":1757000000.0,"version":1}
```

`version` is `BROADCAST_VERSION`, bumped only on incompatible payload changes. Signing keys
must be at least 32 bytes; shorter keys raise `InvalidBroadcastSignature` at construction.

## Runnable example

The whole feature in one script. Output is from an actual run:

```python
from agent_airlock import Airlock
from agent_airlock.kill_switch import (
    HMACBroadcastSigner, InMemoryTransport, KillSwitchBroadcast,
    KillSwitchListener, registry,
)

@Airlock()
def deploy(target: str) -> str:
    return f"deployed to {target}"

bus = InMemoryTransport()          # swap for RedisStreamTransport to cross processes
ops_a = HMACBroadcastSigner(keyid="ops-a", key=b"a" * 32)
ops_b = HMACBroadcastSigner(keyid="ops-b", key=b"b" * 32)

listener = KillSwitchListener(signers=(ops_a, ops_b), transport=bus, poll_interval_seconds=0)
registry.install(listener)         # <- without this, @Airlock never asks
print(listener.state.value, "|", deploy(target="prod"))
# armed | deployed to prod

KillSwitchBroadcast(signer=ops_a, transport=bus).trigger(reason="incident 412")
print(deploy(target="prod")["block_reason"])
# kill_switch     -- the decorated function is now refused

# One key is not enough to come back: the default quorum is 2-of-3.
KillSwitchBroadcast(signer=ops_a, transport=bus).reset(reason="all clear")
print(deploy(target="prod")["block_reason"], listener.quorum_progress())
# kill_switch (1, 2)

KillSwitchBroadcast(signer=ops_b, transport=bus).reset(reason="all clear")
print(deploy(target="prod"))
# deployed to prod

# A broadcast signed by a key the listener does not hold is dropped, not applied.
intruder = HMACBroadcastSigner(keyid="ops-a", key=b"z" * 32)   # right keyid, wrong key
KillSwitchBroadcast(signer=intruder, transport=bus).trigger(reason="forged")
print(deploy(target="prod"))
# deployed to prod
```

Two things worth reading twice. The forged message claims a keyid the listener trusts and
is still rejected, because acceptance is decided by the MAC and not by the claimed
identity. And the same key voting to reset five times is still one vote — the quorum
counts distinct keyids, so a single compromised key cannot re-enable a fleet.

## Commands

```bash
export AIRLOCK_KILL_SWITCH_KEY="<>= 32 bytes, hex or raw>"
export AIRLOCK_KILL_SWITCH_REDIS_URL="redis://localhost:6379/0"   # or --redis-url

airlock kill-switch status  --keyid ops-a
airlock kill-switch trigger "prod incident 412" --keyid ops-a
airlock kill-switch reset   "all clear" --keyid ops-a --quorum 2-of-3
airlock kill-switch arm     ops-a          # validates key material, reads fleet state
```

`--key-env` and `--stream-key` override the key variable and the Redis stream on any
subcommand. `status` exits 1 when the fleet is frozen, so it composes in a shell check.

**Without a transport, the publishing commands fail rather than reporting success:**

```
no broadcast transport configured — this command would reach no process.
  Pass --redis-url redis://host:6379/0, or set AIRLOCK_KILL_SWITCH_REDIS_URL.
  Requires the redis extra: pip install "agent-airlock[redis]"
```

That refusal is the point. Until v0.8.86 these commands printed
`OK: trigger queued (transport=InMemoryTransport)` and reached nothing.

## What this does not cover

- **A freeze takes effect within one poll interval, not instantly.** The listener polls at
  most once per `poll_interval_seconds` (5 s by default) so a transport read does not land
  on every tool call. Set it to `0` to poll on every call. A process that makes no tool
  calls never polls, and is therefore never frozen — the switch stops *calls*, not
  processes.
- **Transport failures fail open by default.** If a poll raises, the previous state is kept
  and the error is logged, because a kill switch that halts every agent when its own
  transport hiccups is an outage generator. This is the opposite of the library's usual
  deny-by-default posture, so it is a deliberate exception: pass `strict=True` to
  `registry.install` to freeze on transport errors instead.
- **`--quorum` does not travel in the broadcast.** The threshold is listener configuration
  (`reset_quorum_threshold` / `reset_quorum_total`). The CLI now parses and validates the
  flag — `--quorum 9-of-3` is rejected rather than echoed — but uses it only to tell you
  how many more votes are needed.
- **NATS and S3 transports are still stubs** that delegate to an in-process queue, as is
  the deprecated `RedisTransportStub`. Only `RedisStreamTransport` crosses a process
  boundary. Anything else needs the two-method `BroadcastTransport` protocol implemented
  against your own bus.
- **There is no replay protection.** `ts_epoch` is signed but never checked for freshness,
  so a captured `reset` envelope stays valid indefinitely. Two captured votes from two
  distinct keyids would disarm a fleet.
- **`docs/kill-switch.md`, cited as the feature spec by the package docstring, does not
  exist.** This page documents the code as it stands.
