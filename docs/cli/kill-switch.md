# `airlock kill-switch` — HMAC-signed freeze with quorum reset

**Landed in v0.5.9.** Implementation `src/agent_airlock/kill_switch/`; CLI
`src/agent_airlock/cli/kill_switch.py`.

## Status: the primitives are wired, the delivery is not

**Verified against v0.8.85 on 2026-09-04.** Three things this page has to say before it
describes anything, because each of them is load-bearing and none is visible from the
command's output:

1. **No airlock-protected process is frozen by this.** `KillSwitchListener` is never
   constructed, polled, or consulted anywhere in the `@Airlock` call path — the only
   references to it outside `kill_switch/` are the CLI and the CLI dispatcher table.
   Triggering the switch halts tool calls **only if you wire the listener into your own
   process** and check `is_frozen()` yourself. (`SecurityPolicy.is_frozen()` is an unrelated
   method meaning "this policy was produced by `freeze()`"; it is not the kill switch.)
2. **No cross-process transport ships.** `NATSTransportStub`, `RedisTransportStub` and
   `S3TransportStub` all subclass `_StubTransport`, which delegates to an in-process
   `InMemoryTransport`. Nothing leaves the process. "Cluster-wide" requires you to implement
   the two-method `BroadcastTransport` protocol against a real bus.
3. **The CLI does not persist anything.** `trigger` and `reset` each construct a fresh
   `InMemoryTransport()`, publish into it, print `OK`, and exit — the broadcast is discarded
   with the process. `arm` validates the key length and prints; no state is written
   anywhere. The commands are smoke tests for key material, not operational controls.

What *is* real and tested: HMAC-SHA256 signing and constant-time verification, the signed
envelope format, the listener state machine, and the M-of-N reset quorum. Those are the
parts the example below exercises end to end.

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

This is the working surface. Output shown is from an actual run:

```python
from agent_airlock.kill_switch import (
    HMACBroadcastSigner, InMemoryTransport, KillSwitchBroadcast,
    KillSwitchListener, KillSwitchState,
)

transport = InMemoryTransport()          # process-local; see limitation 2 above
ops_a = HMACBroadcastSigner(keyid="ops-a", key=b"a" * 32)
ops_b = HMACBroadcastSigner(keyid="ops-b", key=b"b" * 32)

listener = KillSwitchListener(signers=(ops_a, ops_b), transport=transport)
print(listener.state.value, listener.is_frozen())            # disarmed False

KillSwitchBroadcast(signer=ops_a, transport=transport).trigger(reason="prod incident 412")
listener.poll()
print(listener.state.value, listener.is_frozen())            # triggered True

# One key is not enough to come back: the default quorum is 2-of-3.
KillSwitchBroadcast(signer=ops_a, transport=transport).reset(reason="all clear")
listener.poll()
print(listener.state.value, listener.quorum_progress())      # triggered (1, 2)

KillSwitchBroadcast(signer=ops_b, transport=transport).reset(reason="all clear")
listener.poll()
print(listener.state.value, listener.is_frozen())            # disarmed False

# A broadcast signed by a key the listener does not hold is dropped, not applied.
intruder = HMACBroadcastSigner(keyid="ops-a", key=b"z" * 32)  # right keyid, wrong key
KillSwitchBroadcast(signer=intruder, transport=transport).trigger(reason="forged")
print(listener.poll(), listener.state.value)                 # 0 disarmed
```

Note the last block: the forged message claims a keyid the listener trusts, and is still
rejected, because acceptance is decided by the MAC and not by the claimed identity.

## Commands

```bash
export AIRLOCK_KILL_SWITCH_KEY="<>= 32 bytes, hex or raw>"

airlock kill-switch arm ops-a
airlock kill-switch trigger "prod incident 412" --keyid ops-a
airlock kill-switch reset "all clear" --keyid ops-a --quorum 2-of-3
```

`--key-env` overrides the variable name on any subcommand. Real output:

```
OK: kill-switch armed for keyid='ops-a'
OK: trigger queued (reason='prod incident 412', transport=InMemoryTransport)
OK: reset queued (quorum=2-of-3, reason='all clear', transport=InMemoryTransport)
```

Read `transport=InMemoryTransport` in that output literally: the message went into a queue
that is discarded when the command exits.

## What this does not cover

- **`--quorum` is echoed, never enforced.** The flag is printed back and otherwise unused;
  the CLI's `reset` path constructs no `ResetQuorum` at all. `--quorum 9-of-9` is accepted
  and reported as `9-of-9`. Quorum is enforced only by `KillSwitchListener`, via its
  `reset_quorum_threshold` / `reset_quorum_total` fields.
- **`KillSwitchState.ARMED` is never assigned.** The enum member exists; the listener only
  ever moves between `DISARMED` and `TRIGGERED`. There is no armed-but-not-triggered state
  in the implementation, which is also why `arm` writes nothing.
- **There is no 5-second timer.** The listener docstring mentions a 5 s interval "per
  spec"; `poll()` is caller-driven and nothing in the package schedules it. The latency to
  freeze is whatever your own loop provides.
- **A short signing key raises an uncaught traceback** from the CLI rather than a clean
  message.
- **`docs/kill-switch.md`, cited as the feature spec by the package docstring, does not
  exist.** This page is not that spec; it documents the code as it stands.
- **Nothing is authenticated but the broadcast.** There is no replay protection: `ts_epoch`
  is signed but never checked for freshness, so a captured `reset` envelope stays valid.
